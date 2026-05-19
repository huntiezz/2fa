import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import { decodeClientDataJSON, isoBase64URL } from "@simplewebauthn/server/helpers";
import type {
	AuthenticationResponseJSON,
	AuthenticatorTransportFuture,
} from "@simplewebauthn/server";
import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";
import { writeAuditLog } from "@/lib/mfa/audit";
import { getExpectedOrigins, getMfaEnv } from "@/lib/mfa/env";
import { getRequestIp, jsonError } from "@/lib/mfa/http";
import { setMfaLoginProofCookie } from "@/lib/mfa/mfa-login-proof";
import { requireSessionUser } from "@/lib/mfa/route-session";
import { findValidChallenge, markChallengeUsed } from "@/lib/mfa/webauthn-challenges";

export const runtime = "nodejs";

const authResponseSchema = z
	.object({
		id: z.string(),
		rawId: z.string(),
		type: z.literal("public-key"),
		response: z
			.object({
				clientDataJSON: z.string(),
				authenticatorData: z.string(),
				signature: z.string(),
				userHandle: z.string().optional(),
			})
			.passthrough(),
		clientExtensionResults: z.record(z.unknown()).optional(),
		authenticatorAttachment: z.enum(["platform", "cross-platform"]).optional(),
	})
	.passthrough();

const bodySchema = z.object({
	response: authResponseSchema,
	establishLoginSession: z.boolean().optional(),
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

	const raw = await request.json().catch(() => null);
	const parsed = bodySchema.safeParse(raw);
	if (!parsed.success) {
		return jsonError("Invalid authentication payload", 400);
	}

	const authenticationResponse = parsed.data.response as AuthenticationResponseJSON;

	let clientChallenge: string;
	try {
		const clientData = decodeClientDataJSON(authenticationResponse.response.clientDataJSON);
		if (clientData.type !== "webauthn.get") {
			return jsonError("Unexpected WebAuthn client data type", 400);
		}
		clientChallenge = clientData.challenge;
	} catch {
		return jsonError("Invalid clientDataJSON", 400);
	}

	const challengeRow = await findValidChallenge(supabase, {
		userId: user.id,
		challenge: clientChallenge,
		type: "authentication",
	});
	if (!challengeRow) {
		await writeAuditLog(supabase, {
			userId: user.id,
			action: "webauthn_auth_failed",
			metadata: { reason: "challenge_not_found" },
			ipAddress: getRequestIp(request),
			userAgent: request.headers.get("user-agent"),
		});
		return jsonError("Challenge expired or already used.", 400);
	}

	const credentialId = authenticationResponse.id;
	const { data: row, error: rowErr } = await supabase
		.from("webauthn_credentials")
		.select("id, credential_id, public_key, sign_count, transports")
		.eq("user_id", user.id)
		.eq("credential_id", credentialId)
		.maybeSingle();

	if (rowErr || !row) {
		await writeAuditLog(supabase, {
			userId: user.id,
			action: "webauthn_auth_failed",
			metadata: { reason: "unknown_credential" },
			ipAddress: getRequestIp(request),
			userAgent: request.headers.get("user-agent"),
		});
		return jsonError("Unknown credential.", 400);
	}

	const transports = Array.isArray(row.transports)
		? (row.transports as AuthenticatorTransportFuture[])
		: undefined;

	const credential = {
		id: row.credential_id as string,
		publicKey: isoBase64URL.toBuffer(row.public_key as string),
		counter: Number(row.sign_count),
		transports,
	};

	const verification = await verifyAuthenticationResponse({
		response: authenticationResponse,
		expectedChallenge: clientChallenge,
		expectedOrigin: getExpectedOrigins(),
		expectedRPID: env.rpId,
		credential,
		requireUserVerification: true,
	});

	if (!verification.verified) {
		await writeAuditLog(supabase, {
			userId: user.id,
			action: "webauthn_auth_failed",
			metadata: { reason: "verification_failed" },
			ipAddress: getRequestIp(request),
			userAgent: request.headers.get("user-agent"),
		});
		return jsonError("Authentication could not be verified.", 400);
	}

	const newCounter = verification.authenticationInfo.newCounter;
	const oldCounter = Number(row.sign_count);

	const { data: updated, error: updErr } = await supabase
		.from("webauthn_credentials")
		.update({
			sign_count: newCounter,
			last_used_at: new Date().toISOString(),
		})
		.eq("id", row.id)
		.eq("sign_count", oldCounter)
		.select("id")
		.maybeSingle();

	if (updErr || !updated) {
		await writeAuditLog(supabase, {
			userId: user.id,
			action: "webauthn_auth_failed",
			metadata: { reason: "counter_replay_or_race" },
			ipAddress: getRequestIp(request),
			userAgent: request.headers.get("user-agent"),
		});
		return jsonError("Authenticator counter rejected this attempt.", 409);
	}

	await markChallengeUsed(supabase, challengeRow.id);

	await writeAuditLog(supabase, {
		userId: user.id,
		action: "webauthn_auth_verified",
		metadata: {
			credentialIdSuffix: credentialId.slice(-12),
			newCounter,
			loginSession: Boolean(parsed.data.establishLoginSession),
		},
		ipAddress: getRequestIp(request),
		userAgent: request.headers.get("user-agent"),
	});

	const res = NextResponse.json({
		verified: true,
		newCounter,
	});

	if (parsed.data.establishLoginSession) {
		await setMfaLoginProofCookie(res, user.id);
		await writeAuditLog(supabase, {
			userId: user.id,
			action: "mfa_login_satisfied",
			metadata: { method: "webauthn" },
			ipAddress: getRequestIp(request),
			userAgent: request.headers.get("user-agent"),
		});
	}

	return res;
}
