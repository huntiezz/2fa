import Link from "next/link";
import { redirect } from "next/navigation";
import { DotmSquare1 } from "@/components/ui/dotm-square-1";
import { SecuritySettingsClient } from "@/app/dashboard/security/security-settings-client";
import { createClient } from "@/lib/supabase/server";

export const dynamic = "force-dynamic";

export default async function SecurityPage() {
	const supabase = await createClient();
	const {
		data: { user },
	} = await supabase.auth.getUser();
	if (!user) redirect("/login");

	const [{ data: mfa }, { data: creds }, { count: recoveryCount }, { data: audit }] =
		await Promise.all([
			supabase
				.from("mfa_settings")
				.select("totp_enabled, encrypted_totp_secret")
				.eq("user_id", user.id)
				.maybeSingle(),
			supabase
				.from("webauthn_credentials")
				.select(
					"id, device_name, authenticator_type, transports, sign_count, created_at, last_used_at",
				)
				.eq("user_id", user.id)
				.order("created_at", { ascending: false }),
			supabase
				.from("recovery_codes")
				.select("id", { count: "exact", head: true })
				.eq("user_id", user.id)
				.eq("used", false),
			supabase
				.from("security_audit_logs")
				.select("id, action, metadata, ip_address, user_agent, created_at")
				.eq("user_id", user.id)
				.order("created_at", { ascending: false })
				.limit(25),
		]);

	const totpEnabled = Boolean(mfa?.totp_enabled);
	const totpPending = Boolean(mfa?.encrypted_totp_secret && !mfa?.totp_enabled);

	return (
		<div className="app-bg flex min-h-svh w-full flex-col text-foreground">
			<header className="flex items-center justify-between border-b border-border/80 px-6 py-4">
				<div className="flex items-center gap-3">
					<DotmSquare1 size={28} dotSize={4} color="var(--dot-on)" animated />
					<div>
						<h1 className="text-lg font-semibold">Security</h1>
						<p className="text-xs text-muted-foreground">MFA, passkeys, recovery codes</p>
					</div>
				</div>
				<Link href="/dashboard" className="text-sm text-muted-foreground hover:text-foreground">
					Account
				</Link>
			</header>

			<main className="mx-auto w-full max-w-2xl flex-1 px-6 py-8">
				<SecuritySettingsClient
					initial={{
						totpEnabled,
						totpPending,
						recoveryUnused: recoveryCount ?? 0,
						credentials: creds ?? [],
						audit: audit ?? [],
					}}
				/>
			</main>
		</div>
	);
}
