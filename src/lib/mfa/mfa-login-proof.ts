import type { NextResponse } from "next/server";
import { getMfaEnv } from "@/lib/mfa/env";

export const MFA_LOGIN_PROOF_COOKIE = "mfa_login_proof";

const COOKIE_VERSION = "v1";

function loginProofTtlSeconds(): number {
	const raw = process.env.MFA_LOGIN_SESSION_SECONDS;
	const n = raw ? Number.parseInt(raw, 10) : NaN;
	if (Number.isFinite(n) && n >= 300 && n <= 86400 * 7) {
		return n;
	}
	return 12 * 60 * 60;
}

function toBase64Url(bytes: Uint8Array): string {
	let binary = "";
	for (let i = 0; i < bytes.length; i += 1) {
		binary += String.fromCharCode(bytes[i]!);
	}
	const b64 = btoa(binary);
	return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function utf8ToBase64Url(s: string): string {
	return toBase64Url(new TextEncoder().encode(s));
}

function base64UrlToUtf8(payload: string): string {
	const pad = payload.length % 4 === 0 ? "" : "=".repeat(4 - (payload.length % 4));
	const b64 = payload.replace(/-/g, "+").replace(/_/g, "/") + pad;
	const bin = atob(b64);
	const bytes = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
	return new TextDecoder().decode(bytes);
}

function timingSafeEqualStr(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i += 1) {
		diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	}
	return diff === 0;
}

async function hmacSha256B64Url(secret: Uint8Array, message: string): Promise<string> {
	const rawKey = new Uint8Array(secret);
	const key = await crypto.subtle.importKey(
		"raw",
		rawKey,
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
	return toBase64Url(new Uint8Array(sig));
}

async function deriveSigningMaterial(): Promise<Uint8Array> {
	const raw = new Uint8Array(getMfaEnv().encryptionKey);
	const key = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, [
		"sign",
	]);
	const out = await crypto.subtle.sign(
		"HMAC",
		key,
		new TextEncoder().encode(`mfa-login-proof:${COOKIE_VERSION}`),
	);
	return new Uint8Array(out);
}

export async function signMfaLoginProof(userId: string): Promise<string> {
	const exp = Math.floor(Date.now() / 1000) + loginProofTtlSeconds();
	const payload = utf8ToBase64Url(JSON.stringify({ v: COOKIE_VERSION, sub: userId, exp }));
	const material = await deriveSigningMaterial();
	const sig = await hmacSha256B64Url(material, payload);
	return `${payload}.${sig}`;
}

export async function verifyMfaLoginProof(
	cookieValue: string | undefined,
	userId: string,
): Promise<boolean> {
	if (!cookieValue?.includes(".")) return false;
	const lastDot = cookieValue.lastIndexOf(".");
	const payload = cookieValue.slice(0, lastDot);
	const sig = cookieValue.slice(lastDot + 1);
	const material = await deriveSigningMaterial();
	const expected = await hmacSha256B64Url(material, payload);
	if (!timingSafeEqualStr(sig, expected)) return false;
	try {
		const json = JSON.parse(base64UrlToUtf8(payload)) as {
			v?: string;
			sub?: string;
			exp?: number;
		};
		if (json.v !== COOKIE_VERSION || json.sub !== userId) return false;
		if (typeof json.exp !== "number") return false;
		if (json.exp < Math.floor(Date.now() / 1000)) return false;
		return true;
	} catch {
		return false;
	}
}

export async function setMfaLoginProofCookie(res: NextResponse, userId: string): Promise<void> {
	const token = await signMfaLoginProof(userId);
	res.cookies.set(MFA_LOGIN_PROOF_COOKIE, token, {
		httpOnly: true,
		secure: process.env.NODE_ENV === "production",
		sameSite: "lax",
		path: "/",
		maxAge: loginProofTtlSeconds(),
	});
}

export function clearMfaLoginProofCookie(res: NextResponse): void {
	res.cookies.set(MFA_LOGIN_PROOF_COOKIE, "", {
		httpOnly: true,
		secure: process.env.NODE_ENV === "production",
		sameSite: "lax",
		path: "/",
		maxAge: 0,
	});
}
