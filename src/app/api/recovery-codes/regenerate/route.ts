import { z } from "zod";
import type { NextRequest } from "next/server";
import type { SupabaseClient } from "@supabase/supabase-js";
import { writeAuditLog } from "@/lib/mfa/audit";
import { getMfaEnv } from "@/lib/mfa/env";
import { getRequestIp, jsonError, jsonOk } from "@/lib/mfa/http";
import { requireSessionUser } from "@/lib/mfa/route-session";
import {
	generateRecoveryCodePlaintextSet,
	hashRecoveryCode,
	RECOVERY_CODE_COUNT,
} from "@/lib/mfa/recovery-codes";
import { verifyUserPassword } from "@/lib/mfa/session-verify";
import { decryptTotpSecret, getMfaSettings, verifyTotpToken } from "@/lib/mfa/totp";

export const runtime = "nodejs";

const bodySchema = z.object({
	password: z.string().min(1),
	totpCode: z.string().min(6).max(12).optional(),
});

async function insertRecoveryRows(
	supabase: SupabaseClient,
	userId: string,
	codes: string[],
	pepper: string,
) {
	const rows = codes.map((code) => ({
		user_id: userId,
		code_hash: hashRecoveryCode(code, pepper),
		used: false,
	}));
	const { error } = await supabase.from("recovery_codes").insert(rows);
	if (error) throw new Error(error.message);
}

export async function POST(request: NextRequest) {
	let pepper: string;
	try {
		pepper = getMfaEnv().recoveryPepper;
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

	if (!user.email) {
		return jsonError("Account email missing", 400);
	}

	const settings = await getMfaSettings(supabase, user.id);
	if (settings?.totp_enabled && settings.encrypted_totp_secret) {
		if (!parsed.data.totpCode) {
			return jsonError("totpCode is required while TOTP is enabled.", 400);
		}
		const secret = decryptTotpSecret(settings.encrypted_totp_secret);
		const totpOk = await verifyTotpToken(secret, parsed.data.totpCode);
		if (!totpOk) {
			await writeAuditLog(supabase, {
				userId: user.id,
				action: "totp_verify_failed",
				metadata: { context: "recovery_regenerate" },
				ipAddress: getRequestIp(request),
				userAgent: request.headers.get("user-agent"),
			});
			return jsonError("Invalid authenticator code.", 401);
		}
	}

	const pwOk = await verifyUserPassword(supabase, user.email, parsed.data.password);
	if (!pwOk) {
		await writeAuditLog(supabase, {
			userId: user.id,
			action: "validation_error",
			metadata: { context: "recovery_regenerate_password" },
			ipAddress: getRequestIp(request),
			userAgent: request.headers.get("user-agent"),
		});
		return jsonError("Invalid password.", 401);
	}

	const { error: delErr } = await supabase.from("recovery_codes").delete().eq("user_id", user.id);
	if (delErr) return jsonError(delErr.message, 500);

	const plaintext = generateRecoveryCodePlaintextSet();
	await insertRecoveryRows(supabase, user.id, plaintext, pepper);

	await writeAuditLog(supabase, {
		userId: user.id,
		action: "recovery_codes_regenerated",
		metadata: { count: RECOVERY_CODE_COUNT },
		ipAddress: getRequestIp(request),
		userAgent: request.headers.get("user-agent"),
	});

	return jsonOk({ codes: plaintext });
}
