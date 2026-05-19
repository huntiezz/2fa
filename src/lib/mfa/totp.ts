import type { SupabaseClient } from "@supabase/supabase-js";
import { generateSecret, generateURI, verify } from "otplib";
import { decryptUtf8, encryptUtf8 } from "@/lib/mfa/crypto-secret";
import { getMfaEnv } from "@/lib/mfa/env";

export function createTotpSetupPayload(params: { issuer: string; accountLabel: string }): {
	secret: string;
	otpauthUrl: string;
} {
	const secret = generateSecret({ length: 20 });
	const otpauthUrl = generateURI({
		issuer: params.issuer,
		label: params.accountLabel,
		secret,
		algorithm: "sha1",
		digits: 6,
		period: 30,
	});
	return { secret, otpauthUrl };
}

export async function verifyTotpToken(secret: string, token: string): Promise<boolean> {
	const env = getMfaEnv();
	const result = await verify({
		secret,
		token: token.replace(/\s/g, ""),
		digits: 6,
		period: 30,
		epochTolerance: env.totpDriftSeconds,
	});
	return result.valid === true;
}

export function encryptTotpSecret(secret: string): string {
	return encryptUtf8(secret, getMfaEnv().encryptionKey);
}

export function decryptTotpSecret(payload: string): string {
	return decryptUtf8(payload, getMfaEnv().encryptionKey);
}

export type MfaSettingsRow = {
	user_id: string;
	totp_enabled: boolean;
	encrypted_totp_secret: string | null;
};

export async function upsertPendingTotpSecret(
	supabase: SupabaseClient,
	userId: string,
	encryptedSecret: string,
): Promise<void> {
	const { error } = await supabase.from("mfa_settings").upsert(
		{
			user_id: userId,
			encrypted_totp_secret: encryptedSecret,
			totp_enabled: false,
		},
		{ onConflict: "user_id" },
	);
	if (error) throw new Error(error.message);
}

export async function enableTotp(
	supabase: SupabaseClient,
	userId: string,
	encryptedSecret: string,
): Promise<void> {
	const { error } = await supabase.from("mfa_settings").upsert(
		{
			user_id: userId,
			encrypted_totp_secret: encryptedSecret,
			totp_enabled: true,
		},
		{ onConflict: "user_id" },
	);
	if (error) throw new Error(error.message);
}

export async function disableTotp(supabase: SupabaseClient, userId: string): Promise<void> {
	const { error } = await supabase.from("mfa_settings").upsert(
		{
			user_id: userId,
			totp_enabled: false,
			encrypted_totp_secret: null,
		},
		{ onConflict: "user_id" },
	);
	if (error) throw new Error(error.message);
}

export async function getMfaSettings(
	supabase: SupabaseClient,
	userId: string,
): Promise<MfaSettingsRow | null> {
	const { data, error } = await supabase
		.from("mfa_settings")
		.select("user_id, totp_enabled, encrypted_totp_secret")
		.eq("user_id", userId)
		.maybeSingle();
	if (error) throw new Error(error.message);
	return data as MfaSettingsRow | null;
}
