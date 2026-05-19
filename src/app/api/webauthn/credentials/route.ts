import { jsonError, jsonOk } from "@/lib/mfa/http";
import { requireSessionUser } from "@/lib/mfa/route-session";

export const runtime = "nodejs";

export async function GET() {
	const auth = await requireSessionUser();
	if (auth.errorResponse) return auth.errorResponse;
	const { supabase, user } = auth;

	const { data, error } = await supabase
		.from("webauthn_credentials")
		.select(
			"id, credential_id, device_name, authenticator_type, transports, sign_count, created_at, last_used_at",
		)
		.eq("user_id", user.id)
		.order("created_at", { ascending: false });

	if (error) return jsonError(error.message, 500);
	return jsonOk({ credentials: data ?? [] });
}
