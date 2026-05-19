import { verifyRegistrationResponse } from "@simplewebauthn/server";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import { decodeClientDataJSON, isoBase64URL } from "@simplewebauthn/server/helpers";
import { z } from "zod";
import type { NextRequest } from "next/server";
import { writeAuditLog } from "@/lib/mfa/audit";
import { getExpectedOrigins, getMfaEnv } from "@/lib/mfa/env";
import { getRequestIp, jsonError, jsonOk } from "@/lib/mfa/http";
import { requireSessionUser } from "@/lib/mfa/route-session";
import { mapAuthenticatorType } from "@/lib/mfa/webauthn-device";
import { findValidChallenge, markChallengeUsed } from "@/lib/mfa/webauthn-challenges";

export const runtime = "nodejs";

const registrationResponseSchema = z
	.object({
		id: z.string(),
		rawId: z.string(),
		type: z.literal("public-key"),
		response: z
			.object({
				clientDataJSON: z.string(),
				attestationObject: z.string(),
				transports: z.array(z.string()).optional(),
				publicKeyAlgorithm: z.number().optional(),
			})
			.passthrough(),
		clientExtensionResults: z.record(z.unknown()).optional(),
		authenticatorAttachment: z.enum(["platform", "cross-platform"]).optional(),
	})
	.passthrough();

const bodySchema = z.object({
	response: registrationResponseSchema,
	deviceName: z.string().min(1).max(80).optional(),
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
		return jsonError("Invalid registration payload", 400);
	}

	const registrationResponse = parsed.data.response as RegistrationResponseJSON;

	let clientChallenge: string;
	try {
		const clientData = decodeClientDataJSON(registrationResponse.response.clientDataJSON);
		if (clientData.type !== "webauthn.create") {
			return jsonError("Unexpected WebAuthn client data type", 400);
		}
		clientChallenge = clientData.challenge;
	} catch {
		return jsonError("Invalid clientDataJSON", 400);
	}

	const challengeRow = await findValidChallenge(supabase, {
		userId: user.id,
		challenge: clientChallenge,
		type: "registration",
	});
	if (!challengeRow) {
		await writeAuditLog(supabase, {
			userId: user.id,
			action: "webauthn_register_failed",
			metadata: { reason: "challenge_not_found" },
			ipAddress: getRequestIp(request),
			userAgent: request.headers.get("user-agent"),
		});
		return jsonError("Challenge expired or already used.", 400);
	}

	const verification = await verifyRegistrationResponse({
		response: registrationResponse,
		expectedChallenge: clientChallenge,
		expectedOrigin: getExpectedOrigins(),
		expectedRPID: env.rpId,
		requireUserPresence: true,
		requireUserVerification: true,
	});

	if (!verification.verified || !verification.registrationInfo) {
		await writeAuditLog(supabase, {
			userId: user.id,
			action: "webauthn_register_failed",
			metadata: { reason: "verification_failed" },
			ipAddress: getRequestIp(request),
			userAgent: request.headers.get("user-agent"),
		});
		return jsonError("Registration could not be verified.", 400);
	}

	const { credential, credentialDeviceType } = verification.registrationInfo;
	const transports = registrationResponse.response.transports ?? credential.transports ?? [];

	const authenticatorType = mapAuthenticatorType(credentialDeviceType, transports);

	const publicKeyStored = isoBase64URL.fromBuffer(credential.publicKey);

	const { error: insertErr } = await supabase.from("webauthn_credentials").insert({
		user_id: user.id,
		credential_id: credential.id,
		public_key: publicKeyStored,
		sign_count: credential.counter,
		device_name: parsed.data.deviceName?.trim() || "Passkey",
		transports,
		authenticator_type: authenticatorType,
		last_used_at: new Date().toISOString(),
	});

	if (insertErr) {
		if (insertErr.code === "23505") {
			return jsonError("This credential is already registered.", 409);
		}
		return jsonError(insertErr.message, 500);
	}

	await markChallengeUsed(supabase, challengeRow.id);

	await writeAuditLog(supabase, {
		userId: user.id,
		action: "webauthn_register_verified",
		metadata: {
			credentialIdSuffix: credential.id.slice(-12),
			authenticatorType,
		},
		ipAddress: getRequestIp(request),
		userAgent: request.headers.get("user-agent"),
	});

	return jsonOk({
		verified: true,
		credentialId: credential.id,
		signCount: credential.counter,
		authenticatorType,
	});
}
