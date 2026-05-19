import type { NextRequest } from "next/server";
import { jsonError, jsonOk } from "@/lib/mfa/http";
import { requireSessionUser } from "@/lib/mfa/route-session";

export const runtime = "nodejs";

export async function GET(request: NextRequest) {
	const auth = await requireSessionUser();
	if (auth.errorResponse) return auth.errorResponse;
	const { supabase, user } = auth;

	const url = new URL(request.url);
	const limitRaw = url.searchParams.get("limit");
	const limit = Math.min(100, Math.max(1, Number.parseInt(limitRaw ?? "50", 10) || 50));

	const { data, error } = await supabase
		.from("security_audit_logs")
		.select("id, action, metadata, ip_address, user_agent, created_at")
		.eq("user_id", user.id)
		.order("created_at", { ascending: false })
		.limit(limit);

	if (error) return jsonError(error.message, 500);

	return jsonOk({ entries: data ?? [] });
}
