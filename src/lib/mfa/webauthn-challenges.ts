import type { SupabaseClient } from "@supabase/supabase-js";

export type ChallengeType = "registration" | "authentication";

export async function cleanupChallenges(supabase: SupabaseClient): Promise<void> {
	const { error } = await supabase.rpc("cleanup_expired_webauthn_challenges");
	if (error) {
		console.warn("[webauthn] cleanup rpc failed", error.message);
	}
}

export async function insertWebAuthnChallenge(
	supabase: SupabaseClient,
	params: {
		userId: string;
		challenge: string;
		challengeType: ChallengeType;
		expiresAtIso: string;
	},
): Promise<string> {
	const { data, error } = await supabase
		.from("webauthn_challenges")
		.insert({
			user_id: params.userId,
			challenge: params.challenge,
			challenge_type: params.challengeType,
			expires_at: params.expiresAtIso,
			used: false,
		})
		.select("id")
		.single();
	if (error || !data) throw new Error(error?.message ?? "challenge insert failed");
	return data.id as string;
}

export async function findValidChallenge(
	supabase: SupabaseClient,
	params: { userId: string; challenge: string; type: ChallengeType },
): Promise<{ id: string } | null> {
	const now = new Date().toISOString();
	const { data, error } = await supabase
		.from("webauthn_challenges")
		.select("id")
		.eq("user_id", params.userId)
		.eq("challenge", params.challenge)
		.eq("challenge_type", params.type)
		.eq("used", false)
		.gt("expires_at", now)
		.order("created_at", { ascending: false })
		.limit(1)
		.maybeSingle();
	if (error) throw new Error(error.message);
	return data ? { id: data.id as string } : null;
}

export async function markChallengeUsed(supabase: SupabaseClient, id: string): Promise<void> {
	const { error } = await supabase.from("webauthn_challenges").update({ used: true }).eq("id", id);
	if (error) throw new Error(error.message);
}
