import type { CredentialDeviceType } from "@simplewebauthn/server";

export function mapAuthenticatorType(
	deviceType: CredentialDeviceType,
	transports: string[] | undefined,
): "platform" | "cross-platform" | "hybrid" | "unknown" {
	if (transports?.includes("hybrid")) return "hybrid";
	if (deviceType === "multiDevice") return "cross-platform";
	if (deviceType === "singleDevice") {
		if (transports?.includes("internal")) return "platform";
		return "cross-platform";
	}
	return "unknown";
}
