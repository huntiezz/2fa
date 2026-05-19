import { createClient } from "@/lib/supabase/server";
import { clearMfaLoginProofCookie } from "@/lib/mfa/mfa-login-proof";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
	const supabase = await createClient();
	await supabase.auth.signOut();

	const { origin } = new URL(request.url);
	const res = NextResponse.redirect(`${origin}/login`, { status: 303 });
	clearMfaLoginProofCookie(res);
	return res;
}
