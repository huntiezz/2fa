import type { NextRequest } from "next/server";

export function getRequestIp(request: NextRequest): string | null {
	const forwarded = request.headers.get("x-forwarded-for");
	if (forwarded) {
		return forwarded.split(",")[0]?.trim() ?? null;
	}
	return request.headers.get("x-real-ip");
}

export function jsonOk<T>(body: T, init?: { status?: number }) {
	return Response.json(body, { status: init?.status ?? 200 });
}

export function jsonError(message: string, status: number) {
	return Response.json({ error: message }, { status });
}
