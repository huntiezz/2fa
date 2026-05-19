import { timingSafeEqual } from "node:crypto";
import { NextResponse } from "next/server";
import { z } from "zod";
import type { NextRequest } from "next/server";
import { writeAuditLog } from "@/lib/mfa/audit";
import { getMfaEnv } from "@/lib/mfa/env";
import { getRequestIp, jsonError } from "@/lib/mfa/http";
import { setMfaLoginProofCookie } from "@/lib/mfa/mfa-login-proof";
import { getMfaRequirement } from "@/lib/mfa/mfa-requirement";
import { rateLimitHit } from "@/lib/mfa/rate-limit";
import { hashRecoveryCode, normalizeRecoveryCode } from "@/lib/mfa/recovery-codes";
import { requireSessionUser } from "@/lib/mfa/route-session";
import { decryptTotpSecret, getMfaSettings, verifyTotpToken } from "@/lib/mfa/totp";

export const runtime = "nodejs";

const bodySchema = z.discriminatedUnion("method", [
	z.object({
		method: z.literal("totp"),
		code: z.string().min(6).max(12),
	}),
	z.object({
		method: z.literal("recovery"),
		code: z.string().min(8).max(64),
	}),
]);

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

	const raw = await request.json().catch(() => null);
	const parsed = bodySchema.safeParse(raw);
	if (!parsed.success) {
		return jsonError("Invalid request body", 400);
	}

	const requirement = await getMfaRequirement(supabase, user.id);
	if (!requirement.required) {
		return jsonError("MFA is not required for this account.", 400);
	}

	const limited = rateLimitHit(`mfa-login:${user.id}`, env.totpVerifyMaxPerMinute, 60_000);
	if (limited) {
		return jsonError("Too many attempts. Try again shortly.", 429);
	}

	if (parsed.data.method === "totp") {
		if (!requirement.totpEnabled) {
			return jsonError("TOTP is not enabled for this account.", 400);
		}
		const settings = await getMfaSettings(supabase, user.id);
		if (!settings?.totp_enabled || !settings.encrypted_totp_secret) {
			return jsonError("TOTP is not enabled.", 400);
		}
		const secret = decryptTotpSecret(settings.encrypted_totp_secret);
		const ok = await verifyTotpToken(secret, parsed.data.code);
		if (!ok) {
			await writeAuditLog(supabase, {
				userId: user.id,
				action: "totp_verify_failed",
				metadata: { context: "mfa_login" },
				ipAddress: getRequestIp(request),
				userAgent: request.headers.get("user-agent"),
			});
			return jsonError("Invalid code.", 401);
		}

		const res = NextResponse.json({ ok: true, method: "totp" });
		await setMfaLoginProofCookie(res, user.id);
		await writeAuditLog(supabase, {
			userId: user.id,
			action: "mfa_login_satisfied",
			metadata: { method: "totp" },
			ipAddress: getRequestIp(request),
			userAgent: request.headers.get("user-agent"),
		});
		return res;
	}

	if (requirement.recoveryUnused <= 0) {
		return jsonError("No recovery codes available.", 400);
	}

	const normalized = normalizeRecoveryCode(parsed.data.code);
	const candidateHash = hashRecoveryCode(normalized, env.recoveryPepper);

	const { data: rows, error: listErr } = await supabase
		.from("recovery_codes")
		.select("id, code_hash")
		.eq("user_id", user.id)
		.eq("used", false);

	if (listErr || !rows?.length) {
		return jsonError("Recovery verification failed.", 500);
	}

	let matchedId: string | null = null;
	for (const row of rows) {
		const stored = row.code_hash as string;
		try {
			const a = Buffer.from(candidateHash, "utf8");
			const b = Buffer.from(stored, "utf8");
			if (a.length === b.length && timingSafeEqual(a, b)) {
				matchedId = row.id as string;
				break;
			}
		} catch {
			/* continue */
		}
	}

	if (!matchedId) {
		await writeAuditLog(supabase, {
			userId: user.id,
			action: "totp_verify_failed",
			metadata: { context: "mfa_login_recovery" },
			ipAddress: getRequestIp(request),
			userAgent: request.headers.get("user-agent"),
		});
		return jsonError("Invalid recovery code.", 401);
	}

	const { error: delErr } = await supabase
		.from("recovery_codes")
		.delete()
		.eq("id", matchedId)
		.eq("user_id", user.id);

	if (delErr) {
		return jsonError("Could not consume recovery code.", 500);
	}

	const res = NextResponse.json({ ok: true, method: "recovery" });
	await setMfaLoginProofCookie(res, user.id);
	await writeAuditLog(supabase, {
		userId: user.id,
		action: "mfa_login_satisfied",
		metadata: { method: "recovery" },
		ipAddress: getRequestIp(request),
		userAgent: request.headers.get("user-agent"),
	});
	await writeAuditLog(supabase, {
		userId: user.id,
		action: "recovery_code_used",
		metadata: { context: "mfa_login" },
		ipAddress: getRequestIp(request),
		userAgent: request.headers.get("user-agent"),
	});
	return res;
}
