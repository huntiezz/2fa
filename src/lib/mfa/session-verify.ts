import type { SupabaseClient } from "@supabase/supabase-js";

export async function verifyUserPassword(
	supabase: SupabaseClient,
	email: string,
	password: string,
): Promise<boolean> {
	const { error } = await supabase.auth.signInWithPassword({
		email,
		password,
	});
	return !error;
}
