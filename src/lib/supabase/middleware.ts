import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";
import { MFA_LOGIN_PROOF_COOKIE, verifyMfaLoginProof } from "@/lib/mfa/mfa-login-proof";
import { getMfaRequirement } from "@/lib/mfa/mfa-requirement";

function copyCookies(from: NextResponse, to: NextResponse) {
	from.cookies.getAll().forEach((c) => {
		to.cookies.set(c.name, c.value);
	});
}

export async function updateSession(request: NextRequest) {
	let supabaseResponse = NextResponse.next({ request });

	const supabase = createServerClient(
		process.env.NEXT_PUBLIC_SUPABASE_URL!,
		process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
		{
			cookies: {
				getAll() {
					return request.cookies.getAll();
				},
				setAll(cookiesToSet) {
					cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value));
					supabaseResponse = NextResponse.next({ request });
					cookiesToSet.forEach(({ name, value, options }) =>
						supabaseResponse.cookies.set(name, value, options),
					);
				},
			},
		},
	);

	const {
		data: { user },
	} = await supabase.auth.getUser();

	const pathname = request.nextUrl.pathname;
	const mfaChallengePath = "/login/mfa";

	if (!user && pathname === mfaChallengePath) {
		const url = request.nextUrl.clone();
		url.pathname = "/login";
		return NextResponse.redirect(url);
	}

	const isAuthLanding = pathname === "/login" || pathname === "/signup" || pathname === "/";

	if (!user && pathname.startsWith("/dashboard")) {
		const url = request.nextUrl.clone();
		url.pathname = "/login";
		const redirect = NextResponse.redirect(url);
		copyCookies(supabaseResponse, redirect);
		return redirect;
	}

	if (user) {
		let mfaReq: Awaited<ReturnType<typeof getMfaRequirement>> | null = null;
		try {
			mfaReq = await getMfaRequirement(supabase, user.id);
		} catch {
			mfaReq = {
				required: false,
				totpEnabled: false,
				passkeyCount: 0,
				recoveryUnused: 0,
			};
		}

		const proofCookie = request.cookies.get(MFA_LOGIN_PROOF_COOKIE)?.value;
		let hasProof = false;
		try {
			hasProof = await verifyMfaLoginProof(proofCookie, user.id);
		} catch {
			hasProof = false;
		}
		const mfaBlocking = Boolean(mfaReq?.required && !hasProof);

		if (mfaBlocking && pathname.startsWith("/dashboard")) {
			const url = request.nextUrl.clone();
			url.pathname = mfaChallengePath;
			const redirect = NextResponse.redirect(url);
			copyCookies(supabaseResponse, redirect);
			return redirect;
		}

		if (mfaBlocking && isAuthLanding) {
			const url = request.nextUrl.clone();
			url.pathname = mfaChallengePath;
			const redirect = NextResponse.redirect(url);
			copyCookies(supabaseResponse, redirect);
			return redirect;
		}

		if (!mfaBlocking && pathname === mfaChallengePath) {
			const url = request.nextUrl.clone();
			url.pathname = "/dashboard";
			const redirect = NextResponse.redirect(url);
			copyCookies(supabaseResponse, redirect);
			return redirect;
		}

		if (!mfaBlocking && isAuthLanding) {
			const url = request.nextUrl.clone();
			url.pathname = "/dashboard";
			const redirect = NextResponse.redirect(url);
			copyCookies(supabaseResponse, redirect);
			return redirect;
		}
	}

	return supabaseResponse;
}
