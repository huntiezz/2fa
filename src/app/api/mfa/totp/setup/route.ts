import QRCode from "qrcode";
import { z } from "zod";
import type { NextRequest } from "next/server";
import { writeAuditLog } from "@/lib/mfa/audit";
import { getMfaEnv } from "@/lib/mfa/env";
import { getRequestIp, jsonError, jsonOk } from "@/lib/mfa/http";
import { requireSessionUser } from "@/lib/mfa/route-session";
import { verifyUserPassword } from "@/lib/mfa/session-verify";
import {
	createTotpSetupPayload,
	encryptTotpSecret,
	getMfaSettings,
	upsertPendingTotpSecret,
	verifyTotpToken,
	decryptTotpSecret,
} from "@/lib/mfa/totp";

export const runtime = "nodejs";

const bodySchema = z.object({
	password: z.string().min(1).optional(),
	totpCode: z.string().min(6).max(12).optional(),
});

export async function POST(request: NextRequest) {
	let mfaEnv;
	try {
		mfaEnv = getMfaEnv();
	} catch (e) {
		const msg = e instanceof Error ? e.message : "Configuration error";
		return jsonError(msg, 500);
	}

	const auth = await requireSessionUser();
	if (auth.errorResponse) return auth.errorResponse;
	const { supabase, user } = auth;

	const raw = await request.json().catch(() => ({}));
	const parsed = bodySchema.safeParse(raw);
	if (!parsed.success) {
		return jsonError("Invalid request body", 400);
	}

	const settings = await getMfaSettings(supabase, user.id);
	if (settings?.totp_enabled && settings.encrypted_totp_secret) {
		const password = parsed.data.password;
		const totpCode = parsed.data.totpCode;
		if (!password || !totpCode) {
			return jsonError(
				"When TOTP is enabled, provide password and current totpCode to rotate the secret.",
				400,
			);
		}
		if (!user.email) {
			return jsonError("Account email missing", 400);
		}
		const pwOk = await verifyUserPassword(supabase, user.email, password);
		if (!pwOk) {
			await writeAuditLog(supabase, {
				userId: user.id,
				action: "totp_verify_failed",
				metadata: { context: "setup_rotate_password" },
				ipAddress: getRequestIp(request),
				userAgent: request.headers.get("user-agent"),
			});
			return jsonError("Invalid password.", 401);
		}
		const currentSecret = decryptTotpSecret(settings.encrypted_totp_secret);
		const totpOk = await verifyTotpToken(currentSecret, totpCode);
		if (!totpOk) {
			await writeAuditLog(supabase, {
				userId: user.id,
				action: "totp_verify_failed",
				metadata: { context: "setup_rotate_totp" },
				ipAddress: getRequestIp(request),
				userAgent: request.headers.get("user-agent"),
			});
			return jsonError("Invalid authenticator code.", 401);
		}
	}

	const username =
		(await supabase.from("profiles").select("username").eq("id", user.id).maybeSingle()).data
			?.username ??
		user.email?.split("@")[0] ??
		"user";

	const { secret, otpauthUrl } = createTotpSetupPayload({
		issuer: "2FA Demo",
		accountLabel: String(username),
	});

	const encrypted = encryptTotpSecret(secret);
	await upsertPendingTotpSecret(supabase, user.id, encrypted);

	const qrDataUrl = await QRCode.toDataURL(otpauthUrl, {
		width: 256,
		margin: 2,
		errorCorrectionLevel: "M",
	});

	await writeAuditLog(supabase, {
		userId: user.id,
		action: "totp_setup_started",
		metadata: { hasExistingTotp: Boolean(settings?.totp_enabled) },
		ipAddress: getRequestIp(request),
		userAgent: request.headers.get("user-agent"),
	});

	return jsonOk({
		otpauthUrl,
		qrDataUrl,
		manualSecret: secret,
		challengeTtlMs: mfaEnv.challengeTtlMs,
	});
}
