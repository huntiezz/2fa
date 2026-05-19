/** Internal auth identifier - never shown to users. */
const AUTH_DOMAIN = "users.2fa.app";

export function usernameToEmail(username: string): string {
	return `${username.trim().toLowerCase()}@${AUTH_DOMAIN}`;
}

export function validateUsername(username: string): string | null {
	const value = username.trim();
	if (value.length < 3) {
		return "Username must be at least 3 characters.";
	}
	if (value.length > 24) {
		return "Username must be at most 24 characters.";
	}
	if (!/^[a-zA-Z0-9_]+$/.test(value)) {
		return "Username can only use letters, numbers, and underscores.";
	}
	return null;
}

export function formatAuthError(message: string): string {
	const lower = message.toLowerCase();

	if (lower.includes("invalid") && lower.includes("email")) {
		return "Invalid username or password.";
	}
	if (lower.includes("already registered") || lower.includes("already been registered")) {
		return "That username is already taken.";
	}
	if (lower.includes("invalid login credentials")) {
		return "Invalid username or password.";
	}
	if (lower.includes("not confirmed") || lower.includes("email not confirmed")) {
		return "Could not sign in. Please try again.";
	}
	if (lower.includes("rate limit") || lower.includes("too many requests")) {
		return "Too many attempts. Wait a minute, then try again.";
	}
	if (
		lower.includes("database error") ||
		lower.includes("username_taken") ||
		lower.includes("profile_create_failed")
	) {
		return "That username may already be taken, or signup is temporarily unavailable. Try again shortly.";
	}

	return message
		.replace(/email address\s*["']?[^"']*["']?\s*is invalid/gi, "Invalid username or password")
		.replace(/["']?[\w.+-]+@[\w.-]+\.[\w.-]+["']?/g, "")
		.replace(/\bemail\b/gi, "account")
		.replace(/\s{2,}/g, " ")
		.trim();
}
