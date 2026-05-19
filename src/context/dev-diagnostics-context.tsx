"use client";

import {
	createContext,
	useCallback,
	useContext,
	useEffect,
	useMemo,
	useState,
	type ReactNode,
} from "react";
import { redactForDevLog } from "@/lib/dev-diagnostics/redact";
import type { DevLogEntry, DevLogLevel } from "@/lib/dev-diagnostics/types";

const MAX_LOGS = 400;

function newId(): string {
	return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 9)}`;
}

type DevDiagnosticsContextValue = {
	enabled: boolean;
	logs: DevLogEntry[];
	pushLog: (entry: {
		category: string;
		level?: DevLogLevel;
		title: string;
		detail?: unknown;
		durationMs?: number;
	}) => void;
	clearLogs: () => void;
	exportLogs: () => string;
	open: boolean;
	setOpen: (v: boolean) => void;
	autoScroll: boolean;
	setAutoScroll: (v: boolean) => void;
};

const DevDiagnosticsContext = createContext<DevDiagnosticsContextValue | null>(null);

export function useDevDiagnostics(): DevDiagnosticsContextValue | null {
	return useContext(DevDiagnosticsContext);
}

export function DevDiagnosticsProvider({
	enabled,
	children,
}: {
	enabled: boolean;
	children: ReactNode;
}) {
	const [logs, setLogs] = useState<DevLogEntry[]>([]);
	const [open, setOpen] = useState(false);
	const [autoScroll, setAutoScroll] = useState(true);

	const pushLog = useCallback(
		(entry: {
			category: string;
			level?: DevLogLevel;
			title: string;
			detail?: unknown;
			durationMs?: number;
		}) => {
			if (!enabled) return;
			const row: DevLogEntry = {
				id: newId(),
				ts: Date.now(),
				category: entry.category,
				level: entry.level ?? "info",
				title: entry.title,
				detail: entry.detail === undefined ? undefined : redactForDevLog(entry.detail),
				durationMs: entry.durationMs,
			};
			setLogs((prev) => {
				const next = [row, ...prev];
				return next.slice(0, MAX_LOGS);
			});
		},
		[enabled],
	);

	const clearLogs = useCallback(() => setLogs([]), []);

	const exportLogs = useCallback(() => {
		return JSON.stringify(logs, null, 2);
	}, [logs]);

	useEffect(() => {
		if (!enabled) return;

		function isDiagnosticsShortcut(e: KeyboardEvent): boolean {
			const mod = e.metaKey || e.ctrlKey;
			if (!mod || !e.shiftKey) return false;
			// ⌘⇧C / Ctrl⇧C - Chrome often steals this for “Inspect”; ⌘⇧D is a reliable fallback.
			return e.code === "KeyC" || e.code === "KeyD";
		}

		function onKey(e: KeyboardEvent) {
			if (!isDiagnosticsShortcut(e)) return;
			e.preventDefault();
			e.stopPropagation();
			setOpen((v) => !v);
		}
		window.addEventListener("keydown", onKey, true);
		return () => window.removeEventListener("keydown", onKey, true);
	}, [enabled]);

	useEffect(() => {
		if (!enabled) return;

		function onErr(ev: ErrorEvent) {
			pushLog({
				category: "exception",
				level: "error",
				title: ev.message || "window.error",
				detail: { filename: ev.filename, lineno: ev.lineno, colno: ev.colno },
			});
		}
		function onRej(ev: PromiseRejectionEvent) {
			const reason =
				ev.reason instanceof Error ? ev.reason.message : String(ev.reason ?? "rejection");
			pushLog({
				category: "exception",
				level: "error",
				title: `Unhandled rejection: ${reason}`,
			});
		}
		window.addEventListener("error", onErr);
		window.addEventListener("unhandledrejection", onRej);
		return () => {
			window.removeEventListener("error", onErr);
			window.removeEventListener("unhandledrejection", onRej);
		};
	}, [enabled, pushLog]);

	useEffect(() => {
		if (!enabled) return;
		const orig = window.fetch.bind(window);
		window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
			const url =
				typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
			const start = performance.now();
			try {
				const res = await orig(input, init);
				const ms = Math.round(performance.now() - start);
				let detail: unknown;
				const ct = res.headers.get("content-type") ?? "";
				if (ct.includes("application/json")) {
					try {
						const clone = res.clone();
						detail = redactForDevLog(await clone.json());
					} catch {
						detail = { parseError: true };
					}
				}
				pushLog({
					category: "fetch",
					title: `${res.status} ${res.statusText} ${url}`,
					detail: { body: detail, status: res.status },
					durationMs: ms,
					level: res.ok ? "info" : "warn",
				});
				return res;
			} catch (err) {
				const ms = Math.round(performance.now() - start);
				pushLog({
					category: "fetch",
					level: "error",
					title: `Fetch failed ${url}`,
					detail: { error: err instanceof Error ? err.message : String(err) },
					durationMs: ms,
				});
				throw err;
			}
		};
		return () => {
			window.fetch = orig;
		};
	}, [enabled, pushLog]);

	const value = useMemo(
		() => ({
			enabled,
			logs,
			pushLog,
			clearLogs,
			exportLogs,
			open,
			setOpen,
			autoScroll,
			setAutoScroll,
		}),
		[enabled, logs, pushLog, clearLogs, exportLogs, open, autoScroll],
	);

	return <DevDiagnosticsContext.Provider value={value}>{children}</DevDiagnosticsContext.Provider>;
}
