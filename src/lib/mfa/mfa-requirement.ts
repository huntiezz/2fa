import type { SupabaseClient } from "@supabase/supabase-js";

export type MfaRequirement = {
	/** Second factor required before dashboard / gated APIs */
	required: boolean;
	totpEnabled: boolean;
	passkeyCount: number;
	recoveryUnused: number;
};

export async function getMfaRequirement(
	supabase: SupabaseClient,
	userId: string,
): Promise<MfaRequirement> {
	const [{ data: mfa }, { count: pkCount, error: pkErr }, { count: recCount, error: recErr }] =
		await Promise.all([
			supabase.from("mfa_settings").select("totp_enabled").eq("user_id", userId).maybeSingle(),
			supabase
				.from("webauthn_credentials")
				.select("id", { count: "exact", head: true })
				.eq("user_id", userId),
			supabase
				.from("recovery_codes")
				.select("id", { count: "exact", head: true })
				.eq("user_id", userId)
				.eq("used", false),
		]);

	if (pkErr || recErr) {
		return {
			required: false,
			totpEnabled: false,
			passkeyCount: 0,
			recoveryUnused: 0,
		};
	}

	const totpEnabled = Boolean(mfa?.totp_enabled);
	const passkeyCount = pkCount ?? 0;
	const recoveryUnused = recCount ?? 0;

	const required = totpEnabled || passkeyCount > 0 || recoveryUnused > 0;

	return {
		required,
		totpEnabled,
		passkeyCount,
		recoveryUnused,
	};
}
