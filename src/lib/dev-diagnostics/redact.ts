const SENSITIVE_KEY =
	/^(?:.*secret.*|.*password.*|.*token.*|.*cookie.*|authorization|manualsecret|otpauthurl|qrdataurl|codes|clientdatajson|attestationobject|authenticatordata|signature|privatekey|encrypted|refreshtoken|accesstoken)$/i;

function isSensitiveKey(key: string): boolean {
	return SENSITIVE_KEY.test(key);
}

export function redactForDevLog(value: unknown): unknown {
	if (value === null || value === undefined) return value;
	if (typeof value !== "object") {
		return value;
	}
	if (Array.isArray(value)) {
		return value.map((item) => redactForDevLog(item));
	}
	const out: Record<string, unknown> = {};
	for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
		if (isSensitiveKey(k)) {
			out[k] = "[REDACTED]";
		} else {
			out[k] = redactForDevLog(v);
		}
	}
	return out;
}
