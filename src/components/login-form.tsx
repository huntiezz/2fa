"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { AuthLoading } from "@/components/auth-loading";
import { PasswordInput } from "@/components/password-input";
import { formatAuthError, usernameToEmail, validateUsername } from "@/lib/auth";
import { createClient } from "@/lib/supabase/client";
import { toast } from "@/lib/toast";
import { cn } from "@/lib/utils";

type Mode = "login" | "signup";

export function LoginForm({ mode = "login" }: { mode?: Mode }) {
	const router = useRouter();
	const [username, setUsername] = useState("");
	const [password, setPassword] = useState("");
	const [loading, setLoading] = useState(false);

	const isSignup = mode === "signup";

	async function handleSubmit(e: React.FormEvent) {
		e.preventDefault();

		const usernameError = validateUsername(username);
		if (usernameError) {
			toast.error(usernameError);
			return;
		}

		if (password.length < 6) {
			toast.error("Password must be at least 6 characters.");
			return;
		}

		setLoading(true);
		const supabase = createClient();
		const email = usernameToEmail(username);

		try {
			if (isSignup) {
				const { data, error: signUpError } = await supabase.auth.signUp({
					email,
					password,
					options: {
						data: { username: username.trim().toLowerCase() },
					},
				});
				if (signUpError) throw signUpError;

				if (!data.session) {
					const { error: signInError } = await supabase.auth.signInWithPassword({
						email,
						password,
					});
					if (signInError) throw signInError;
				}
			} else {
				const { error: signInError } = await supabase.auth.signInWithPassword({
					email,
					password,
				});
				if (signInError) throw signInError;
			}

			toast.success(isSignup ? "Account created" : "Welcome back");

			const mfaRes = await fetch("/api/auth/mfa-requirement");
			if (mfaRes.ok) {
				const mfaJson = (await mfaRes.json()) as { required?: boolean };
				if (mfaJson.required) {
					router.push("/login/mfa");
					router.refresh();
					return;
				}
			}

			router.push("/dashboard");
			router.refresh();
		} catch (err) {
			toast.error(formatAuthError(err instanceof Error ? err.message : "Something went wrong."));
		} finally {
			setLoading(false);
		}
	}

	return (
		<>
			{loading ? <AuthLoading label={isSignup ? "Creating account…" : "Signing in…"} /> : null}

			<div className="flex w-full max-w-sm flex-col gap-8">
				<div className="flex flex-col gap-2 text-center">
					<h1 className="text-2xl font-semibold tracking-tight">
						{isSignup ? "Create account" : "Welcome back"}
					</h1>
					<p className="text-sm text-muted-foreground">
						{isSignup ? "Choose a username and password" : "Sign in to continue"}
					</p>
				</div>

				<form onSubmit={handleSubmit} className="flex flex-col gap-4">
					<div className="flex flex-col gap-2">
						<label htmlFor="username" className="text-sm font-medium">
							Username
						</label>
						<input
							id="username"
							type="text"
							autoComplete="username"
							placeholder="johndoe"
							value={username}
							onChange={(e) => setUsername(e.target.value)}
							required
							className="glass-input"
						/>
					</div>

					<div className="flex flex-col gap-2">
						<label htmlFor="password" className="text-sm font-medium">
							Password
						</label>
						<PasswordInput
							id="password"
							value={password}
							onChange={setPassword}
							autoComplete={isSignup ? "new-password" : "current-password"}
							required
						/>
					</div>

					<div className="relative mt-1 pb-3">
						<button
							type="submit"
							disabled={loading}
							className={cn("glass-blue h-11 w-full text-sm")}
						>
							{isSignup ? "Sign up" : "Login"}
						</button>
					</div>
				</form>

				<p className="text-center text-sm text-muted-foreground">
					{isSignup ? (
						<>
							Already have an account?{" "}
							<Link href="/login" className="font-medium text-primary hover:underline">
								Sign in
							</Link>
						</>
					) : (
						<>
							No account?{" "}
							<Link href="/signup" className="font-medium text-primary hover:underline">
								Sign up
							</Link>
						</>
					)}
				</p>
			</div>
		</>
	);
}
