import { z } from "zod";

const envSchema = z.object({
	NEXT_PUBLIC_APP_URL: z.string().url().optional(),
	WEBAUTHN_RP_ID: z.string().min(1).optional(),
	MFA_ENCRYPTION_KEY: z
		.string()
		.regex(/^[0-9a-fA-F]{64}$/, "MFA_ENCRYPTION_KEY must be 64 hex chars (32 bytes)")
		.optional(),
	MFA_RECOVERY_CODE_PEPPER: z.string().min(16).optional(),
	MFA_TOTP_DRIFT_STEPS: z.coerce.number().int().min(0).max(10).default(1),
	MFA_CHALLENGE_TTL_SECONDS: z.coerce.number().int().min(60).max(900).default(300),
	MFA_TOTP_VERIFY_MAX_PER_MINUTE: z.coerce.number().int().min(3).max(60).default(12),
	MFA_DEV_CONSOLE_ADMIN_EMAILS: z.string().optional(),
	NEXT_PUBLIC_MFA_DEV_CONSOLE: z.enum(["0", "1"]).optional(),
});

export type MfaEnv = z.infer<typeof envSchema> & {
	appUrl: string;
	rpId: string;
	encryptionKey: Buffer;
	recoveryPepper: string;
	totpDriftSeconds: number;
	challengeTtlMs: number;
	totpVerifyMaxPerMinute: number;
};

function parseEnv(): MfaEnv {
	const raw = {
		NEXT_PUBLIC_APP_URL: process.env.NEXT_PUBLIC_APP_URL,
		WEBAUTHN_RP_ID: process.env.WEBAUTHN_RP_ID,
		MFA_ENCRYPTION_KEY: process.env.MFA_ENCRYPTION_KEY,
		MFA_RECOVERY_CODE_PEPPER: process.env.MFA_RECOVERY_CODE_PEPPER,
		MFA_TOTP_DRIFT_STEPS: process.env.MFA_TOTP_DRIFT_STEPS,
		MFA_CHALLENGE_TTL_SECONDS: process.env.MFA_CHALLENGE_TTL_SECONDS,
		MFA_TOTP_VERIFY_MAX_PER_MINUTE: process.env.MFA_TOTP_VERIFY_MAX_PER_MINUTE,
		MFA_DEV_CONSOLE_ADMIN_EMAILS: process.env.MFA_DEV_CONSOLE_ADMIN_EMAILS,
		NEXT_PUBLIC_MFA_DEV_CONSOLE: process.env.NEXT_PUBLIC_MFA_DEV_CONSOLE as "0" | "1" | undefined,
	};

	const parsed = envSchema.safeParse(raw);
	if (!parsed.success) {
		throw new Error(`Invalid MFA environment: ${parsed.error.message}`);
	}

	const appUrl = parsed.data.NEXT_PUBLIC_APP_URL?.replace(/\/$/, "") ?? "http://localhost:3000";

	const rpId = parsed.data.WEBAUTHN_RP_ID ?? new URL(appUrl).hostname;

	const encryptionHex = parsed.data.MFA_ENCRYPTION_KEY;
	if (!encryptionHex) {
		throw new Error("MFA_ENCRYPTION_KEY is required (64 hex characters = 32-byte AES key)");
	}

	const recoveryPepper = parsed.data.MFA_RECOVERY_CODE_PEPPER ?? encryptionHex;

	const driftSteps = parsed.data.MFA_TOTP_DRIFT_STEPS ?? 1;
	const totpDriftSeconds = driftSteps * 30;

	return {
		...parsed.data,
		appUrl,
		rpId,
		encryptionKey: Buffer.from(encryptionHex, "hex"),
		recoveryPepper,
		totpDriftSeconds,
		challengeTtlMs: (parsed.data.MFA_CHALLENGE_TTL_SECONDS ?? 300) * 1000,
		totpVerifyMaxPerMinute: parsed.data.MFA_TOTP_VERIFY_MAX_PER_MINUTE ?? 12,
	};
}

let cached: MfaEnv | null = null;

export function getMfaEnv(): MfaEnv {
	if (!cached) {
		cached = parseEnv();
	}
	return cached;
}

export function getExpectedOrigins(): string[] {
	const env = getMfaEnv();
	const origins = new Set<string>([env.appUrl]);
	if (env.appUrl.startsWith("http://")) {
		origins.add(env.appUrl.replace("http://", "https://"));
	}
	return [...origins];
}

export function parseAdminEmails(): string[] {
	const raw = process.env.MFA_DEV_CONSOLE_ADMIN_EMAILS;
	if (!raw?.trim()) return [];
	return raw
		.split(",")
		.map((s) => s.trim().toLowerCase())
		.filter(Boolean);
}

export function isDevConsoleAllowedForUser(email: string | undefined): boolean {
	if (process.env.NODE_ENV === "development") return true;
	if (process.env.NEXT_PUBLIC_MFA_DEV_CONSOLE === "1") {
		const admins = parseAdminEmails();
		if (admins.length === 0) return true;
		if (!email) return false;
		return admins.includes(email.toLowerCase());
	}
	return false;
}
