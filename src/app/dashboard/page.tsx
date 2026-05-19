import Link from "next/link";
import { redirect } from "next/navigation";
import { DotmSquare1 } from "@/components/ui/dotm-square-1";
import { createClient } from "@/lib/supabase/server";

function formatDate(iso: string) {
	return new Date(iso).toLocaleDateString(undefined, {
		year: "numeric",
		month: "long",
		day: "numeric",
	});
}

export default async function DashboardPage() {
	const supabase = await createClient();
	const {
		data: { user },
	} = await supabase.auth.getUser();

	if (!user) {
		redirect("/login");
	}

	const { data: profile } = await supabase
		.from("profiles")
		.select("username, created_at")
		.eq("id", user.id)
		.maybeSingle();

	const username =
		profile?.username ??
		(user.user_metadata?.username as string | undefined) ??
		user.email?.split("@")[0] ??
		"user";

	const memberSince = profile?.created_at ?? user.created_at;

	return (
		<div className="app-bg flex min-h-svh w-full flex-col text-foreground">
			<header className="flex items-center border-b border-border/80 px-6 py-4">
				<div className="flex items-center gap-3">
					<DotmSquare1 size={28} dotSize={4} color="var(--dot-on)" animated />
					<h1 className="text-lg font-semibold">Account</h1>
				</div>
			</header>

			<main className="mx-auto flex w-full max-w-lg flex-1 flex-col gap-6 px-6 py-8">
				<section className="glass-surface p-6">
					<h2 className="text-sm font-medium text-muted-foreground">Settings</h2>

					<dl className="mt-5 space-y-4">
						<div>
							<dt className="text-xs text-muted-foreground">Username</dt>
							<dd className="mt-1 font-medium">{username}</dd>
						</div>
						<div>
							<dt className="text-xs text-muted-foreground">Member since</dt>
							<dd className="mt-1 font-medium">{memberSince ? formatDate(memberSince) : "-"}</dd>
						</div>
						<div>
							<dt className="text-xs text-muted-foreground">Security</dt>
							<dd className="mt-1">
								<Link
									href="/dashboard/security"
									className="font-medium text-primary hover:underline"
								>
									MFA &amp; passkeys
								</Link>
							</dd>
						</div>
					</dl>
				</section>

				<form action="/auth/signout" method="post" className="mt-auto space-y-3">
					<div className="relative pb-3">
						<button type="submit" className="glass-blue h-11 w-full text-sm">
							Sign out
						</button>
					</div>
					<p className="text-center text-xs text-muted-foreground">
						<Link href="/login" className="text-primary hover:underline">
							Back to login
						</Link>
					</p>
				</form>
			</main>
		</div>
	);
}
