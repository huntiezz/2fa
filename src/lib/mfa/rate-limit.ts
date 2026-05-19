type Bucket = { count: number; windowStart: number };

const store = new Map<string, Bucket>();

export function rateLimitHit(key: string, max: number, windowMs: number): boolean {
	const now = Date.now();
	const bucket = store.get(key);
	if (!bucket || now - bucket.windowStart > windowMs) {
		store.set(key, { count: 1, windowStart: now });
		return false;
	}
	bucket.count += 1;
	if (bucket.count > max) {
		return true;
	}
	store.set(key, bucket);
	return false;
}
