import { createClient } from "@/lib/supabase/server";
import { jsonError } from "@/lib/mfa/http";

export async function requireSessionUser(): Promise<
	| {
			supabase: Awaited<ReturnType<typeof createClient>>;
			user: { id: string; email?: string | null };
			errorResponse: null;
	  }
	| {
			supabase: Awaited<ReturnType<typeof createClient>>;
			user: null;
			errorResponse: Response;
	  }
> {
	const supabase = await createClient();
	const {
		data: { user },
		error,
	} = await supabase.auth.getUser();
	if (error || !user) {
		return {
			supabase,
			user: null,
			errorResponse: jsonError("Unauthorized", 401),
		};
	}
	return { supabase, user, errorResponse: null };
}
