import { z } from "zod";
import type { NextRequest } from "next/server";
import { writeAuditLog } from "@/lib/mfa/audit";
import { getRequestIp, jsonError, jsonOk } from "@/lib/mfa/http";
import { requireSessionUser } from "@/lib/mfa/route-session";
import { verifyUserPassword } from "@/lib/mfa/session-verify";
import { decryptTotpSecret, disableTotp, getMfaSettings, verifyTotpToken } from "@/lib/mfa/totp";

export const runtime = "nodejs";

const bodySchema = z.object({
	password: z.string().min(1),
	totpCode: z.string().min(6).max(12),
});

export async function POST(request: NextRequest) {
	const auth = await requireSessionUser();
	if (auth.errorResponse) return auth.errorResponse;
	const { supabase, user } = auth;

	const raw = await request.json().catch(() => ({}));
	const parsed = bodySchema.safeParse(raw);
	if (!parsed.success) {
		return jsonError("Invalid request body", 400);
	}

	const settings = await getMfaSettings(supabase, user.id);
	if (!settings?.totp_enabled || !settings.encrypted_totp_secret) {
		return jsonError("TOTP is not enabled.", 400);
	}

	if (!user.email) {
		return jsonError("Account email missing", 400);
	}

	const pwOk = await verifyUserPassword(supabase, user.email, parsed.data.password);
	if (!pwOk) {
		await writeAuditLog(supabase, {
			userId: user.id,
			action: "totp_verify_failed",
			metadata: { context: "disable_password" },
			ipAddress: getRequestIp(request),
			userAgent: request.headers.get("user-agent"),
		});
		return jsonError("Invalid password.", 401);
	}

	const secret = decryptTotpSecret(settings.encrypted_totp_secret);
	const totpOk = await verifyTotpToken(secret, parsed.data.totpCode);
	if (!totpOk) {
		await writeAuditLog(supabase, {
			userId: user.id,
			action: "totp_verify_failed",
			metadata: { context: "disable_totp" },
			ipAddress: getRequestIp(request),
			userAgent: request.headers.get("user-agent"),
		});
		return jsonError("Invalid authenticator code.", 401);
	}

	await disableTotp(supabase, user.id);
	await writeAuditLog(supabase, {
		userId: user.id,
		action: "totp_disabled",
		metadata: {},
		ipAddress: getRequestIp(request),
		userAgent: request.headers.get("user-agent"),
	});

	return jsonOk({ status: "disabled" as const });
}
