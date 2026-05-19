import {
	generateAuthenticationOptions,
	type AuthenticatorTransportFuture,
} from "@simplewebauthn/server";
import { z } from "zod";
import type { NextRequest } from "next/server";
import { writeAuditLog } from "@/lib/mfa/audit";
import { getExpectedOrigins, getMfaEnv } from "@/lib/mfa/env";
import { getRequestIp, jsonError, jsonOk } from "@/lib/mfa/http";
import { requireSessionUser } from "@/lib/mfa/route-session";
import { cleanupChallenges, insertWebAuthnChallenge } from "@/lib/mfa/webauthn-challenges";

export const runtime = "nodejs";

const bodySchema = z.object({
	conditional: z.boolean().optional(),
});

export async function POST(request: NextRequest) {
	let env;
	try {
		env = getMfaEnv();
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

	const conditional = parsed.data.conditional === true;

	await cleanupChallenges(supabase);

	const { data: creds, error } = await supabase
		.from("webauthn_credentials")
		.select("credential_id, transports")
		.eq("user_id", user.id);
	if (error) return jsonError(error.message, 500);

	const allowCredentials =
		!conditional && creds && creds.length > 0
			? creds.map((c) => ({
					id: c.credential_id as string,
					type: "public-key" as const,
					transports: Array.isArray(c.transports)
						? (c.transports as AuthenticatorTransportFuture[])
						: undefined,
				}))
			: undefined;

	const options = await generateAuthenticationOptions({
		rpID: env.rpId,
		allowCredentials,
		userVerification: "required",
		timeout: Math.min(env.challengeTtlMs, 120_000),
	});

	const expiresAt = new Date(Date.now() + env.challengeTtlMs).toISOString();
	await insertWebAuthnChallenge(supabase, {
		userId: user.id,
		challenge: options.challenge,
		challengeType: "authentication",
		expiresAtIso: expiresAt,
	});

	await writeAuditLog(supabase, {
		userId: user.id,
		action: "webauthn_auth_options",
		metadata: { conditional, allowCredentials: allowCredentials?.length ?? 0 },
		ipAddress: getRequestIp(request),
		userAgent: request.headers.get("user-agent"),
	});

	return jsonOk({
		options,
		rpId: env.rpId,
		origins: getExpectedOrigins(),
		expiresAt,
		conditional,
	});
}
