import { z } from "zod";
import type { NextRequest } from "next/server";
import { writeAuditLog } from "@/lib/mfa/audit";
import { getMfaEnv } from "@/lib/mfa/env";
import { getRequestIp, jsonError, jsonOk } from "@/lib/mfa/http";
import { rateLimitHit } from "@/lib/mfa/rate-limit";
import { requireSessionUser } from "@/lib/mfa/route-session";
import {
	decryptTotpSecret,
	enableTotp,
	encryptTotpSecret,
	getMfaSettings,
	verifyTotpToken,
} from "@/lib/mfa/totp";

export const runtime = "nodejs";

const bodySchema = z.object({
	code: z.string().min(6).max(12),
});

export async function POST(request: NextRequest) {
	let env;
	try {
		env = getMfaEnv();
	} catch (e) {
		const msg = e instanceof Error ? e.message : "Configuration error";
		return jsonError(msg, 500);
	}

	const auth = await requireSessionUser();
	if (auth.errorResponse) return auth.errorResponse;
	const { supabase, user } = auth;

	const limited = rateLimitHit(`totp-verify:${user.id}`, env.totpVerifyMaxPerMinute, 60_000);
	if (limited) {
		return jsonError("Too many verification attempts. Try again shortly.", 429);
	}

	const raw = await request.json().catch(() => ({}));
	const parsed = bodySchema.safeParse(raw);
	if (!parsed.success) {
		return jsonError("Invalid request body", 400);
	}

	const settings = await getMfaSettings(supabase, user.id);
	if (!settings?.encrypted_totp_secret) {
		return jsonError("TOTP is not set up. Start setup first.", 400);
	}

	const secret = decryptTotpSecret(settings.encrypted_totp_secret);
	const ok = await verifyTotpToken(secret, parsed.data.code);
	if (!ok) {
		await writeAuditLog(supabase, {
			userId: user.id,
			action: "totp_verify_failed",
			metadata: { enabled: settings.totp_enabled },
			ipAddress: getRequestIp(request),
			userAgent: request.headers.get("user-agent"),
		});
		return jsonError("Invalid code.", 401);
	}

	if (!settings.totp_enabled) {
		const reEncrypted = encryptTotpSecret(secret);
		await enableTotp(supabase, user.id, reEncrypted);
		await writeAuditLog(supabase, {
			userId: user.id,
			action: "totp_enabled",
			metadata: {},
			ipAddress: getRequestIp(request),
			userAgent: request.headers.get("user-agent"),
		});
		return jsonOk({ status: "enabled" as const });
	}

	await writeAuditLog(supabase, {
		userId: user.id,
		action: "totp_verify_ok",
		metadata: {},
		ipAddress: getRequestIp(request),
		userAgent: request.headers.get("user-agent"),
	});
	return jsonOk({ status: "verified" as const });
}
