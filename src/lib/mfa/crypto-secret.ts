import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const ALG = "aes-256-gcm";
const IV_LEN = 12;
const TAG_LEN = 16;

export function encryptUtf8(plain: string, key: Buffer): string {
	if (key.length !== 32) {
		throw new Error("Encryption key must be 32 bytes");
	}
	const iv = randomBytes(IV_LEN);
	const cipher = createCipheriv(ALG, key, iv, { authTagLength: TAG_LEN });
	const ciphertext = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
	const tag = cipher.getAuthTag();
	return Buffer.concat([iv, tag, ciphertext]).toString("base64url");
}

export function decryptUtf8(payload: string, key: Buffer): string {
	if (key.length !== 32) {
		throw new Error("Encryption key must be 32 bytes");
	}
	const buf = Buffer.from(payload, "base64url");
	if (buf.length < IV_LEN + TAG_LEN + 1) {
		throw new Error("Invalid ciphertext");
	}
	const iv = buf.subarray(0, IV_LEN);
	const tag = buf.subarray(IV_LEN, IV_LEN + TAG_LEN);
	const ciphertext = buf.subarray(IV_LEN + TAG_LEN);
	const decipher = createDecipheriv(ALG, key, iv, { authTagLength: TAG_LEN });
	decipher.setAuthTag(tag);
	return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}
