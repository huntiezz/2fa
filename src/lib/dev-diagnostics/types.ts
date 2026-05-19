export type DevLogLevel = "info" | "warn" | "error";

export type DevLogEntry = {
	id: string;
	ts: number;
	category: string;
	level: DevLogLevel;
	title: string;
	detail?: unknown;
	durationMs?: number;
};
