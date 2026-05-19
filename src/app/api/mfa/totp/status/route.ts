import { jsonOk } from "@/lib/mfa/http";
import { requireSessionUser } from "@/lib/mfa/route-session";
import { getMfaSettings } from "@/lib/mfa/totp";

export const runtime = "nodejs";

export async function GET() {
	const auth = await requireSessionUser();
	if (auth.errorResponse) return auth.errorResponse;
	const { supabase, user } = auth;

	const [mfa, { count, error: recErr }] = await Promise.all([
		getMfaSettings(supabase, user.id),
		supabase
			.from("recovery_codes")
			.select("id", { count: "exact", head: true })
			.eq("user_id", user.id)
			.eq("used", false),
	]);

	if (recErr) {
		return Response.json({ error: recErr.message }, { status: 500 });
	}

	return jsonOk({
		totpEnabled: Boolean(mfa?.totp_enabled),
		totpPending: Boolean(mfa?.encrypted_totp_secret && !mfa?.totp_enabled),
		recoveryUnused: count ?? 0,
	});
}
