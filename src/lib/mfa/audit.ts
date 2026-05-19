import type { SupabaseClient } from "@supabase/supabase-js";

export type AuditAction =
	| "totp_setup_started"
	| "totp_enabled"
	| "totp_disabled"
	| "totp_verify_failed"
	| "totp_verify_ok"
	| "webauthn_register_options"
	| "webauthn_register_verified"
	| "webauthn_register_failed"
	| "webauthn_auth_options"
	| "webauthn_auth_verified"
	| "webauthn_auth_failed"
	| "webauthn_credential_removed"
	| "recovery_codes_generated"
	| "recovery_codes_regenerated"
	| "recovery_code_used"
	| "mfa_login_satisfied"
	| "validation_error";

export async function writeAuditLog(
	supabase: SupabaseClient,
	params: {
		userId: string;
		action: AuditAction;
		metadata?: Record<string, unknown>;
		ipAddress: string | null;
		userAgent: string | null;
	},
): Promise<void> {
	const { error } = await supabase.from("security_audit_logs").insert({
		user_id: params.userId,
		action: params.action,
		metadata: params.metadata ?? {},
		ip_address: params.ipAddress,
		user_agent: params.userAgent,
	});
	if (error) {
		console.error("[audit] insert failed", error.message);
	}
}
