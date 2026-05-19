import type { NextRequest } from "next/server";
import { writeAuditLog } from "@/lib/mfa/audit";
import { getRequestIp, jsonError, jsonOk } from "@/lib/mfa/http";
import { requireSessionUser } from "@/lib/mfa/route-session";

export const runtime = "nodejs";

export async function DELETE(request: NextRequest, context: { params: Promise<{ id: string }> }) {
	const { id } = await context.params;
	if (!id || !/^[0-9a-f-]{36}$/i.test(id)) {
		return jsonError("Invalid credential id", 400);
	}

	const auth = await requireSessionUser();
	if (auth.errorResponse) return auth.errorResponse;
	const { supabase, user } = auth;

	const { data, error } = await supabase
		.from("webauthn_credentials")
		.delete()
		.eq("id", id)
		.eq("user_id", user.id)
		.select("id")
		.maybeSingle();

	if (error) return jsonError(error.message, 500);
	if (!data) {
		return jsonError("Credential not found.", 404);
	}

	await writeAuditLog(supabase, {
		userId: user.id,
		action: "webauthn_credential_removed",
		metadata: { credentialRowId: id },
		ipAddress: getRequestIp(request),
		userAgent: request.headers.get("user-agent"),
	});

	return jsonOk({ removed: true });
}
