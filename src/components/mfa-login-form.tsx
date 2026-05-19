"use client";

import { startAuthentication } from "@simplewebauthn/browser";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { AuthLoading } from "@/components/auth-loading";
import { toast } from "@/lib/toast";
import { cn } from "@/lib/utils";

type Requirement = {
	required: boolean;
	totpEnabled: boolean;
	passkeysAvailable: boolean;
	recoveryAvailable: boolean;
};

export function MfaLoginForm() {
	const router = useRouter();
	const [req, setReq] = useState<Requirement | null>(null);
	const [totpCode, setTotpCode] = useState("");
	const [recoveryCode, setRecoveryCode] = useState("");
	const [recoveryOpen, setRecoveryOpen] = useState(false);
	const [busy, setBusy] = useState<string | null>(null);

	useEffect(() => {
		let cancelled = false;
		(async () => {
			const res = await fetch("/api/auth/mfa-requirement");
			if (!res.ok) {
				router.replace("/login");
				return;
			}
			const data = (await res.json()) as Requirement;
			if (cancelled) return;
			if (!data.required) {
				router.replace("/dashboard");
				return;
			}
			setReq(data);
		})();
		return () => {
			cancelled = true;
		};
	}, [router]);

	async function submitTotp() {
		setBusy("totp");
		try {
			const res = await fetch("/api/auth/mfa-complete", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ method: "totp", code: totpCode }),
			});
			const body = (await res.json()) as { error?: string };
			if (!res.ok) throw new Error(body.error ?? "Verification failed");
			toast.success("Signed in");
			router.replace("/dashboard");
			router.refresh();
		} catch (e) {
			toast.error(e instanceof Error ? e.message : "Verification failed");
		} finally {
			setBusy(null);
		}
	}

	async function submitRecovery() {
		setBusy("recovery");
		try {
			const res = await fetch("/api/auth/mfa-complete", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ method: "recovery", code: recoveryCode }),
			});
			const body = (await res.json()) as { error?: string };
			if (!res.ok) throw new Error(body.error ?? "Verification failed");
			toast.success("Signed in with recovery code");
			router.replace("/dashboard");
			router.refresh();
		} catch (e) {
			toast.error(e instanceof Error ? e.message : "Verification failed");
		} finally {
			setBusy(null);
		}
	}

	async function submitPasskey() {
		setBusy("webauthn");
		try {
			const optRes = await fetch("/api/webauthn/authenticate/options", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ conditional: false }),
			});
			const optJson = (await optRes.json()) as {
				error?: string;
				options?: Parameters<typeof startAuthentication>[0]["optionsJSON"];
			};
			if (!optRes.ok) throw new Error(optJson.error ?? "Could not start passkey");
			const assertion = await startAuthentication({
				optionsJSON: optJson.options!,
			});
			const verifyRes = await fetch("/api/webauthn/authenticate/verify", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					response: assertion,
					establishLoginSession: true,
				}),
			});
			const vBody = (await verifyRes.json()) as { error?: string };
			if (!verifyRes.ok) throw new Error(vBody.error ?? "Passkey verification failed");
			toast.success("Signed in with passkey");
			router.replace("/dashboard");
			router.refresh();
		} catch (e) {
			toast.error(e instanceof Error ? e.message : "Passkey failed");
		} finally {
			setBusy(null);
		}
	}

	if (!req) {
		return <AuthLoading label="Checking security settings…" />;
	}

	return (
		<>
			{busy ? <AuthLoading label="Verifying…" /> : null}
			<div className="flex w-full max-w-sm flex-col gap-8">
				<div className="flex flex-col gap-2 text-center">
					<h1 className="text-2xl font-semibold tracking-tight">Second step</h1>
					<p className="text-sm text-muted-foreground">
						Use your authenticator app, a passkey, or a recovery code.
					</p>
				</div>

				{req.totpEnabled ? (
					<div className="glass-surface flex flex-col gap-3 p-4">
						<h2 className="text-sm font-medium">Authenticator code</h2>
						<input
							value={totpCode}
							onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 8))}
							className="glass-input h-11 font-mono text-lg tracking-widest"
							inputMode="numeric"
							autoComplete="one-time-code"
							placeholder="000000"
						/>
						<button
							type="button"
							disabled={busy !== null || totpCode.length < 6}
							onClick={() => void submitTotp()}
							className={cn("glass-blue h-11 text-sm")}
						>
							Continue
						</button>
					</div>
				) : null}

				{req.passkeysAvailable ? (
					<div className="glass-surface flex flex-col gap-3 p-4">
						<h2 className="text-sm font-medium">Passkey or security key</h2>
						<button
							type="button"
							disabled={busy !== null}
							onClick={() => void submitPasskey()}
							className="glass-blue h-11 text-sm"
						>
							Use passkey
						</button>
					</div>
				) : null}

				{req.recoveryAvailable ? (
					<div className="glass-surface flex flex-col gap-3 p-4">
						<button
							type="button"
							className="text-left text-sm font-medium text-primary hover:underline"
							onClick={() => setRecoveryOpen((v) => !v)}
						>
							{recoveryOpen ? "Hide" : "Use a"} recovery code
						</button>
						{recoveryOpen ? (
							<>
								<input
									id="recovery"
									value={recoveryCode}
									onChange={(e) => setRecoveryCode(e.target.value)}
									className="glass-input h-10 text-sm font-mono tracking-wide"
									autoComplete="off"
									spellCheck={false}
									placeholder="XXXX-XXXX-XXXX-XXXX"
								/>
								<button
									type="button"
									disabled={busy !== null || recoveryCode.length < 8}
									onClick={() => void submitRecovery()}
									className="glass-blue h-11 text-sm"
								>
									Verify recovery code
								</button>
							</>
						) : null}
					</div>
				) : null}

				<p className="text-center text-xs text-muted-foreground">
					Wrong account?{" "}
					<form action="/auth/signout" method="post" className="inline">
						<button type="submit" className="text-primary hover:underline">
							Sign out
						</button>
					</form>
				</p>
			</div>
		</>
	);
}
