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

export const runtime = "nodejs";

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

	const { count, error: countErr } = await supabase
		.from("recovery_codes")
		.select("id", { count: "exact", head: true })
		.eq("user_id", user.id)
		.eq("used", false);

	if (countErr) return jsonError(countErr.message, 500);
	if ((count ?? 0) > 0) {
		return jsonError("Recovery codes already exist. Use regenerate to replace them.", 409);
	}

	const plaintext = generateRecoveryCodePlaintextSet();
	await insertRecoveryRows(supabase, user.id, plaintext, pepper);

	await writeAuditLog(supabase, {
		userId: user.id,
		action: "recovery_codes_generated",
		metadata: { count: RECOVERY_CODE_COUNT },
		ipAddress: getRequestIp(request),
		userAgent: request.headers.get("user-agent"),
	});

	return jsonOk({ codes: plaintext });
}
