"use client";

import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { useRouter } from "next/navigation";
import { useCallback, useMemo, useState, type ReactNode } from "react";
import { useDevDiagnostics } from "@/context/dev-diagnostics-context";
import { toast } from "@/lib/toast";
import { cn } from "@/lib/utils";

type CredRow = {
	id: string;
	device_name: string;
	authenticator_type: string;
	transports: unknown;
	sign_count: number;
	created_at: string;
	last_used_at: string | null;
};

type AuditRow = {
	id: string;
	action: string;
	metadata: Record<string, unknown> | null;
	ip_address: string | null;
	user_agent: string | null;
	created_at: string;
};

type Initial = {
	totpEnabled: boolean;
	totpPending: boolean;
	recoveryUnused: number;
	credentials: CredRow[];
	audit: AuditRow[];
};

function formatWhen(iso: string) {
	return new Date(iso).toLocaleString(undefined, {
		dateStyle: "medium",
		timeStyle: "short",
	});
}

function Modal({
	title,
	children,
	onClose,
}: {
	title: string;
	children: ReactNode;
	onClose: () => void;
}) {
	return (
		<div className="fixed inset-0 z-50 flex items-center justify-center p-4">
			<button
				type="button"
				aria-label="Close"
				className="absolute inset-0 bg-black/55 backdrop-blur-sm"
				onClick={onClose}
			/>
			<div className="glass-surface relative z-10 max-h-[90vh] w-full max-w-md overflow-y-auto p-5 shadow-2xl">
				<div className="mb-4 flex items-center justify-between gap-2">
					<h3 className="text-base font-semibold">{title}</h3>
					<button
						type="button"
						className="text-sm text-muted-foreground hover:text-foreground"
						onClick={onClose}
					>
						Close
					</button>
				</div>
				{children}
			</div>
		</div>
	);
}

export function SecuritySettingsClient({ initial }: { initial: Initial }) {
	const router = useRouter();
	const dev = useDevDiagnostics();
	const [totpEnabled, setTotpEnabled] = useState(initial.totpEnabled);
	const [totpPending, setTotpPending] = useState(initial.totpPending);
	const [recoveryUnused, setRecoveryUnused] = useState(initial.recoveryUnused);
	const [credentials, setCredentials] = useState(initial.credentials);
	const [audit, setAudit] = useState(initial.audit);

	const [busy, setBusy] = useState<string | null>(null);

	const [totpQrModal, setTotpQrModal] = useState<{
		qrDataUrl: string;
		manualSecret: string;
	} | null>(null);
	const [totpVerifyOpen, setTotpVerifyOpen] = useState(false);
	const [totpCode, setTotpCode] = useState("");
	const [disableOpen, setDisableOpen] = useState(false);
	const [disablePassword, setDisablePassword] = useState("");
	const [disableTotp, setDisableTotp] = useState("");

	const [recoveryModalCodes, setRecoveryModalCodes] = useState<string[] | null>(null);
	const [regenPassword, setRegenPassword] = useState("");
	const [regenTotp, setRegenTotp] = useState("");
	const [regenOpen, setRegenOpen] = useState(false);

	const [passkeyName, setPasskeyName] = useState("");

	const refreshAll = useCallback(async () => {
		const [cRes, aRes, sRes] = await Promise.all([
			fetch("/api/webauthn/credentials"),
			fetch("/api/security/audit-log?limit=25"),
			fetch("/api/mfa/totp/status"),
		]);
		if (cRes.ok) {
			const j = (await cRes.json()) as { credentials: CredRow[] };
			setCredentials(j.credentials);
		}
		if (aRes.ok) {
			const j = (await aRes.json()) as { entries: AuditRow[] };
			setAudit(j.entries);
		}
		if (sRes.ok) {
			const j = (await sRes.json()) as {
				totpEnabled: boolean;
				totpPending: boolean;
				recoveryUnused: number;
			};
			setTotpEnabled(j.totpEnabled);
			setTotpPending(j.totpPending);
			setRecoveryUnused(j.recoveryUnused);
		} else {
			router.refresh();
		}
	}, [router]);

	const log = useCallback(
		(title: string, detail?: unknown) => {
			dev?.pushLog({ category: "security-ui", title, detail });
		},
		[dev],
	);

	const startTotpSetup = async () => {
		setBusy("totp-setup");
		try {
			const res = await fetch("/api/mfa/totp/setup", { method: "POST" });
			const body = (await res.json()) as {
				error?: string;
				qrDataUrl?: string;
				manualSecret?: string;
			};
			if (!res.ok) throw new Error(body.error ?? "Setup failed");
			setTotpQrModal({
				qrDataUrl: body.qrDataUrl!,
				manualSecret: body.manualSecret!,
			});
			setTotpPending(true);
			log("TOTP setup started");
			toast.success("Scan the QR code with your authenticator app.");
		} catch (e) {
			toast.error(e instanceof Error ? e.message : "Setup failed");
		} finally {
			setBusy(null);
		}
	};

	const verifyTotp = async () => {
		setBusy("totp-verify");
		try {
			const res = await fetch("/api/mfa/totp/verify", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ code: totpCode }),
			});
			const body = (await res.json()) as { error?: string; status?: string };
			if (!res.ok) throw new Error(body.error ?? "Verification failed");
			setTotpVerifyOpen(false);
			setTotpCode("");
			setTotpQrModal(null);
			if (body.status === "enabled") {
				setTotpEnabled(true);
				setTotpPending(false);
			}
			toast.success(body.status === "enabled" ? "Authenticator app enabled" : "Code accepted");
			log("TOTP verified", { status: body.status });
			await refreshAll();
		} catch (e) {
			toast.error(e instanceof Error ? e.message : "Verification failed");
		} finally {
			setBusy(null);
		}
	};

	const disableTotpFn = async () => {
		setBusy("totp-disable");
		try {
			const res = await fetch("/api/mfa/totp/disable", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					password: disablePassword,
					totpCode: disableTotp,
				}),
			});
			const body = (await res.json()) as { error?: string };
			if (!res.ok) throw new Error(body.error ?? "Disable failed");
			setDisableOpen(false);
			setDisablePassword("");
			setDisableTotp("");
			setTotpEnabled(false);
			setTotpPending(false);
			toast.success("Authenticator app disabled");
			log("TOTP disabled");
			await refreshAll();
		} catch (e) {
			toast.error(e instanceof Error ? e.message : "Disable failed");
		} finally {
			setBusy(null);
		}
	};

	const registerPasskey = async () => {
		setBusy("webauthn-reg");
		try {
			log("WebAuthn registration requested");
			const optRes = await fetch("/api/webauthn/register/options", {
				method: "POST",
			});
			const optJson = (await optRes.json()) as {
				error?: string;
				options?: Parameters<typeof startRegistration>[0]["optionsJSON"];
			};
			if (!optRes.ok) throw new Error(optJson.error ?? "Could not start registration");
			const att = await startRegistration({
				optionsJSON: optJson.options!,
			});
			const verifyRes = await fetch("/api/webauthn/register/verify", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					response: att,
					deviceName: passkeyName.trim() || undefined,
				}),
			});
			const vBody = (await verifyRes.json()) as {
				error?: string;
				verified?: boolean;
			};
			if (!verifyRes.ok) throw new Error(vBody.error ?? "Registration failed");
			toast.success("Passkey registered");
			log("WebAuthn registration completed", { verified: vBody.verified });
			setPasskeyName("");
			await refreshAll();
		} catch (e) {
			toast.error(e instanceof Error ? e.message : "Registration failed");
			log("WebAuthn registration error", {
				message: e instanceof Error ? e.message : String(e),
			});
		} finally {
			setBusy(null);
		}
	};

	const testPasskeyAuth = async (conditional: boolean) => {
		setBusy("webauthn-auth");
		try {
			log("WebAuthn authentication requested", { conditional });
			const optRes = await fetch("/api/webauthn/authenticate/options", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ conditional }),
			});
			const optJson = (await optRes.json()) as {
				error?: string;
				options?: Parameters<typeof startAuthentication>[0]["optionsJSON"];
			};
			if (!optRes.ok) throw new Error(optJson.error ?? "Could not start sign-in");
			const assertion = await startAuthentication({
				optionsJSON: optJson.options!,
				useBrowserAutofill: conditional,
			});
			const verifyRes = await fetch("/api/webauthn/authenticate/verify", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ response: assertion }),
			});
			const vBody = (await verifyRes.json()) as { error?: string };
			if (!verifyRes.ok) throw new Error(vBody.error ?? "Verification failed");
			toast.success("Passkey verified");
			log("WebAuthn authentication verified");
			await refreshAll();
		} catch (e) {
			toast.error(e instanceof Error ? e.message : "Passkey sign-in failed");
		} finally {
			setBusy(null);
		}
	};

	const removeCredential = async (id: string) => {
		if (!window.confirm("Remove this passkey from your account?")) return;
		setBusy(`del-${id}`);
		try {
			const res = await fetch(`/api/webauthn/credentials/${id}`, {
				method: "DELETE",
			});
			const body = (await res.json()) as { error?: string };
			if (!res.ok) throw new Error(body.error ?? "Remove failed");
			toast.success("Passkey removed");
			await refreshAll();
		} catch (e) {
			toast.error(e instanceof Error ? e.message : "Remove failed");
		} finally {
			setBusy(null);
		}
	};

	const generateRecovery = async () => {
		setBusy("rec-gen");
		try {
			const res = await fetch("/api/recovery-codes/generate", {
				method: "POST",
			});
			const body = (await res.json()) as { error?: string; codes?: string[] };
			if (!res.ok) throw new Error(body.error ?? "Generate failed");
			setRecoveryModalCodes(body.codes ?? []);
			setRecoveryUnused(body.codes?.length ?? 0);
			toast.success("Recovery codes created");
			log("Recovery codes generated", { count: body.codes?.length });
			await refreshAll();
		} catch (e) {
			toast.error(e instanceof Error ? e.message : "Generate failed");
		} finally {
			setBusy(null);
		}
	};

	const openRegen = () => {
		if (
			!window.confirm("Regenerating invalidates all existing recovery codes immediately. Continue?")
		) {
			return;
		}
		setRegenOpen(true);
	};

	const regenerateRecovery = async () => {
		setBusy("rec-regen");
		try {
			const res = await fetch("/api/recovery-codes/regenerate", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					password: regenPassword,
					totpCode: totpEnabled ? regenTotp : undefined,
				}),
			});
			const body = (await res.json()) as { error?: string; codes?: string[] };
			if (!res.ok) throw new Error(body.error ?? "Regenerate failed");
			setRegenOpen(false);
			setRegenPassword("");
			setRegenTotp("");
			setRecoveryModalCodes(body.codes ?? []);
			setRecoveryUnused(body.codes?.length ?? 0);
			toast.success("New recovery codes generated");
			log("Recovery codes regenerated");
			await refreshAll();
		} catch (e) {
			toast.error(e instanceof Error ? e.message : "Regenerate failed");
		} finally {
			setBusy(null);
		}
	};

	const copyCodes = async (codes: string[]) => {
		await navigator.clipboard.writeText(codes.join("\n"));
		toast.success("Copied to clipboard");
	};

	const totpBadge = useMemo(() => {
		if (totpEnabled) return { label: "Enabled", className: "text-emerald-300" };
		if (totpPending) return { label: "Setup pending", className: "text-amber-300" };
		return { label: "Off", className: "text-muted-foreground" };
	}, [totpEnabled, totpPending]);

	return (
		<div className="flex flex-col gap-8">
			<input
				id="webauthn-autofill"
				name="webauthn"
				type="text"
				autoComplete="webauthn"
				className="sr-only"
				tabIndex={-1}
				readOnly
				aria-hidden
			/>

			<section className="glass-surface p-6">
				<div className="flex flex-wrap items-start justify-between gap-4">
					<div>
						<h2 className="text-sm font-medium text-muted-foreground">Authenticator app (TOTP)</h2>
						<p className="mt-2 text-xs text-muted-foreground">
							RFC 6238 compatible apps: Google Authenticator, Authy, 1Password, Bitwarden, Aegis,
							and others.
						</p>
					</div>
					<span
						className={cn(
							"rounded-full border border-border/80 px-3 py-1 text-xs font-medium",
							totpBadge.className,
						)}
					>
						{totpBadge.label}
					</span>
				</div>
				<div className="mt-5 flex flex-wrap gap-3">
					{!totpEnabled ? (
						<button
							type="button"
							disabled={busy !== null}
							onClick={startTotpSetup}
							className="glass-blue h-10 px-4 text-sm"
						>
							{totpPending ? "Restart setup" : "Enable authenticator"}
						</button>
					) : null}
					{totpPending || totpEnabled ? (
						<button
							type="button"
							disabled={busy !== null}
							onClick={() => setTotpVerifyOpen(true)}
							className="h-10 rounded-sm border border-border px-4 text-sm hover:bg-white/5"
						>
							Enter verification code
						</button>
					) : null}
					{totpEnabled ? (
						<button
							type="button"
							disabled={busy !== null}
							onClick={() => setDisableOpen(true)}
							className="h-10 rounded-sm border border-destructive/40 px-4 text-sm text-destructive hover:bg-destructive/10"
						>
							Disable authenticator
						</button>
					) : null}
				</div>
			</section>

			<section className="glass-surface p-6">
				<h2 className="text-sm font-medium text-muted-foreground">Security keys &amp; passkeys</h2>
				<p className="mt-2 text-xs text-muted-foreground">
					Platform passkeys (Touch ID, Face ID, Windows Hello, Android) and cross-platform FIDO2
					security keys (YubiKey, Titan, etc.).
				</p>
				<div className="mt-4 flex flex-wrap gap-3">
					<input
						value={passkeyName}
						onChange={(e) => setPasskeyName(e.target.value)}
						placeholder="Device name (optional)"
						className="glass-input h-10 max-w-xs flex-1 text-sm"
					/>
					<button
						type="button"
						disabled={busy !== null}
						onClick={registerPasskey}
						className="glass-blue h-10 px-4 text-sm"
					>
						Add passkey
					</button>
					<button
						type="button"
						disabled={busy !== null || credentials.length === 0}
						onClick={() => void testPasskeyAuth(false)}
						className="h-10 rounded-sm border border-border px-4 text-sm hover:bg-white/5"
					>
						Test passkey
					</button>
					<button
						type="button"
						disabled={busy !== null || credentials.length === 0}
						onClick={() => void testPasskeyAuth(true)}
						className="h-10 rounded-sm border border-border px-4 text-sm hover:bg-white/5"
					>
						Test passkey autofill
					</button>
				</div>
				<ul className="mt-6 space-y-3">
					{credentials.length === 0 ? (
						<li className="text-sm text-muted-foreground">No passkeys yet.</li>
					) : (
						credentials.map((c) => (
							<li
								key={c.id}
								className="flex flex-wrap items-center justify-between gap-3 rounded-sm border border-border/60 bg-card/40 px-4 py-3"
							>
								<div>
									<p className="font-medium">{c.device_name}</p>
									<p className="text-xs text-muted-foreground">
										{c.authenticator_type} · added {formatWhen(c.created_at)}
										{c.last_used_at ? ` · last used ${formatWhen(c.last_used_at)}` : ""}
									</p>
								</div>
								<button
									type="button"
									disabled={busy !== null}
									onClick={() => void removeCredential(c.id)}
									className="text-sm text-destructive hover:underline"
								>
									Remove
								</button>
							</li>
						))
					)}
				</ul>
			</section>

			<section className="glass-surface p-6">
				<h2 className="text-sm font-medium text-muted-foreground">Recovery codes</h2>
				<p className="mt-2 text-xs text-muted-foreground">
					One-time emergency codes (10). Stored hashed on the server. Save them offline after
					generation.
				</p>
				<div className="mt-4 flex flex-wrap gap-3">
					<button
						type="button"
						disabled={busy !== null || recoveryUnused > 0}
						onClick={() => void generateRecovery()}
						className="glass-blue h-10 px-4 text-sm disabled:opacity-50"
					>
						Generate codes
					</button>
					<button
						type="button"
						disabled={busy !== null || recoveryUnused === 0}
						onClick={openRegen}
						className="h-10 rounded-sm border border-border px-4 text-sm hover:bg-white/5 disabled:opacity-50"
					>
						Regenerate
					</button>
					{recoveryUnused > 0 ? (
						<span className="self-center text-xs text-muted-foreground">
							{recoveryUnused} unused on file
						</span>
					) : null}
				</div>
			</section>

			<section className="glass-surface p-6">
				<h2 className="text-sm font-medium text-muted-foreground">Audit log</h2>
				<ul className="mt-4 max-h-80 space-y-3 overflow-y-auto pr-1">
					{audit.length === 0 ? (
						<li className="text-sm text-muted-foreground">No events yet.</li>
					) : (
						audit.map((row) => (
							<li
								key={row.id}
								className="rounded-sm border border-border/50 bg-card/30 px-3 py-2 text-xs"
							>
								<div className="flex flex-wrap justify-between gap-2">
									<span className="font-mono text-[11px] text-primary">{row.action}</span>
									<span className="text-muted-foreground">{formatWhen(row.created_at)}</span>
								</div>
								<p className="mt-1 text-[11px] text-muted-foreground">
									{row.ip_address ?? "-"} ·{" "}
									<span className="line-clamp-2 break-all">{row.user_agent ?? "-"}</span>
								</p>
							</li>
						))
					)}
				</ul>
			</section>

			{totpQrModal ? (
				<Modal title="Scan QR code" onClose={() => setTotpQrModal(null)}>
					<div className="flex flex-col items-center gap-4">
						{/* eslint-disable-next-line @next/next/no-img-element */}
						<img
							src={totpQrModal.qrDataUrl}
							alt="TOTP QR code"
							className="h-48 w-48 rounded-sm border border-border/60 bg-white p-2"
						/>
						<p className="text-center text-xs text-muted-foreground">
							Or enter the key manually in your app (treat it like a password).
						</p>
						<code className="w-full break-all rounded-sm bg-black/40 p-3 font-mono text-xs">
							{totpQrModal.manualSecret}
						</code>
						<button
							type="button"
							className="glass-blue mt-2 h-10 w-full text-sm"
							onClick={() => {
								setTotpQrModal(null);
								setTotpVerifyOpen(true);
							}}
						>
							I&apos;ve added it - verify code
						</button>
					</div>
				</Modal>
			) : null}

			{totpVerifyOpen ? (
				<Modal title="Verify authenticator code" onClose={() => setTotpVerifyOpen(false)}>
					<label className="block text-sm font-medium">6-digit code</label>
					<input
						value={totpCode}
						onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 8))}
						className="glass-input mt-2 h-11 font-mono text-lg tracking-widest"
						inputMode="numeric"
						autoComplete="one-time-code"
					/>
					<button
						type="button"
						disabled={busy !== null || totpCode.length < 6}
						className="glass-blue mt-4 h-10 w-full text-sm"
						onClick={() => void verifyTotp()}
					>
						Verify
					</button>
				</Modal>
			) : null}

			{disableOpen ? (
				<Modal title="Disable authenticator" onClose={() => setDisableOpen(false)}>
					<p className="text-xs text-muted-foreground">
						Re-enter your password and a current TOTP code to disable.
					</p>
					<label className="mt-4 block text-sm font-medium">Password</label>
					<input
						type="password"
						value={disablePassword}
						onChange={(e) => setDisablePassword(e.target.value)}
						className="glass-input mt-1 h-10 text-sm"
						autoComplete="current-password"
					/>
					<label className="mt-3 block text-sm font-medium">TOTP code</label>
					<input
						value={disableTotp}
						onChange={(e) => setDisableTotp(e.target.value.replace(/\D/g, "").slice(0, 8))}
						className="glass-input mt-1 h-10 font-mono text-sm tracking-widest"
						inputMode="numeric"
					/>
					<button
						type="button"
						disabled={busy !== null}
						className="glass-blue mt-4 h-10 w-full text-sm"
						onClick={() => void disableTotpFn()}
					>
						Disable TOTP
					</button>
				</Modal>
			) : null}

			{recoveryModalCodes ? (
				<Modal title="Save your recovery codes" onClose={() => setRecoveryModalCodes(null)}>
					<p className="text-xs text-destructive">
						This is the only time we show these codes. Copy them to a safe place.
					</p>
					<ul className="mt-4 max-h-56 space-y-1 overflow-y-auto font-mono text-sm">
						{recoveryModalCodes.map((c) => (
							<li key={c}>{c}</li>
						))}
					</ul>
					<button
						type="button"
						className="glass-blue mt-4 h-10 w-full text-sm"
						onClick={() => void copyCodes(recoveryModalCodes)}
					>
						Copy all
					</button>
				</Modal>
			) : null}

			{regenOpen ? (
				<Modal title="Regenerate recovery codes" onClose={() => setRegenOpen(false)}>
					<label className="block text-sm font-medium">Password</label>
					<input
						type="password"
						value={regenPassword}
						onChange={(e) => setRegenPassword(e.target.value)}
						className="glass-input mt-1 h-10 text-sm"
						autoComplete="current-password"
					/>
					{totpEnabled ? (
						<>
							<label className="mt-3 block text-sm font-medium">TOTP code</label>
							<input
								value={regenTotp}
								onChange={(e) => setRegenTotp(e.target.value.replace(/\D/g, "").slice(0, 8))}
								className="glass-input mt-1 h-10 font-mono text-sm"
								inputMode="numeric"
							/>
						</>
					) : null}
					<button
						type="button"
						disabled={busy !== null}
						className="glass-blue mt-4 h-10 w-full text-sm"
						onClick={() => void regenerateRecovery()}
					>
						Regenerate
					</button>
				</Modal>
			) : null}
		</div>
	);
}
