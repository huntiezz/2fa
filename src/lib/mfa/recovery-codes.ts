import { createHash, randomBytes } from "node:crypto";

const CODE_COUNT = 10;
const GROUP = 4;
const GROUPS = 4;
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function randomChar(): string {
	const i = randomBytes(1)[0]! % ALPHABET.length;
	return ALPHABET[i]!;
}

function generateOneCode(): string {
	const len = GROUP * GROUPS;
	let s = "";
	for (let i = 0; i < len; i += 1) {
		if (i > 0 && i % GROUP === 0) s += "-";
		s += randomChar();
	}
	return s;
}

export function generateRecoveryCodePlaintextSet(): string[] {
	const codes = new Set<string>();
	while (codes.size < CODE_COUNT) {
		codes.add(generateOneCode());
	}
	return [...codes];
}

export function normalizeRecoveryCode(input: string): string {
	return input.replace(/\s+/g, "").toUpperCase();
}

export function hashRecoveryCode(code: string, pepper: string): string {
	const normalized = normalizeRecoveryCode(code);
	return createHash("sha256")
		.update(pepper, "utf8")
		.update("\0", "utf8")
		.update(normalized, "utf8")
		.digest("base64url");
}

export const RECOVERY_CODE_COUNT = CODE_COUNT;
