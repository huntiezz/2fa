import { jsonOk } from "@/lib/mfa/http";
import { getMfaRequirement } from "@/lib/mfa/mfa-requirement";
import { requireSessionUser } from "@/lib/mfa/route-session";

export const runtime = "nodejs";

export async function GET() {
	const auth = await requireSessionUser();
	if (auth.errorResponse) return auth.errorResponse;
	const { supabase, user } = auth;

	const req = await getMfaRequirement(supabase, user.id);

	return jsonOk({
		required: req.required,
		totpEnabled: req.totpEnabled,
		passkeysAvailable: req.passkeyCount > 0,
		recoveryAvailable: req.recoveryUnused > 0,
	});
}
