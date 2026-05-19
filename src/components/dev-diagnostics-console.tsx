"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useDevDiagnostics } from "@/context/dev-diagnostics-context";
import type { DevLogEntry } from "@/lib/dev-diagnostics/types";
import { cn } from "@/lib/utils";

function formatTime(ts: number) {
	return new Date(ts).toLocaleTimeString(undefined, {
		hour: "2-digit",
		minute: "2-digit",
		second: "2-digit",
	});
}

function JsonBlock({ value }: { value: unknown }) {
	const text = useMemo(() => {
		try {
			return JSON.stringify(value, null, 2);
		} catch {
			return String(value);
		}
	}, [value]);
	return (
		<pre className="max-h-48 overflow-auto rounded-sm bg-black/40 p-2 font-mono text-[11px] leading-relaxed text-muted-foreground">
			{text}
		</pre>
	);
}

function LogRow({
	entry,
	expanded,
	onToggle,
}: {
	entry: DevLogEntry;
	expanded: boolean;
	onToggle: () => void;
}) {
	return (
		<div className="border-b border-border/60 py-2">
			<button
				type="button"
				onClick={onToggle}
				className="flex w-full items-start gap-2 text-left text-xs"
			>
				<span
					className={cn(
						"mt-0.5 shrink-0 rounded px-1 py-0.5 font-mono text-[10px] uppercase",
						entry.level === "error" && "bg-destructive/20 text-destructive",
						entry.level === "warn" && "bg-amber-500/15 text-amber-200",
						entry.level === "info" && "bg-primary/15 text-primary",
					)}
				>
					{entry.level}
				</span>
				<span className="shrink-0 font-mono text-[10px] text-muted-foreground">
					{formatTime(entry.ts)}
				</span>
				<span className="min-w-0 flex-1">
					<span className="text-[10px] uppercase text-muted-foreground">{entry.category}</span>
					<span className="mt-0.5 block font-medium text-foreground">
						{entry.title}
						{entry.durationMs != null ? (
							<span className="ml-2 font-mono text-[10px] text-muted-foreground">
								{entry.durationMs}ms
							</span>
						) : null}
					</span>
				</span>
				<span className="shrink-0 text-muted-foreground">{expanded ? "▾" : "▸"}</span>
			</button>
			{expanded && entry.detail !== undefined ? (
				<div className="mt-2 pl-6">
					<JsonBlock value={entry.detail} />
				</div>
			) : null}
		</div>
	);
}

export function DevDiagnosticsConsole() {
	const ctx = useDevDiagnostics();
	const [query, setQuery] = useState("");
	const [expanded, setExpanded] = useState<Record<string, boolean>>({});
	const scrollRef = useRef<HTMLDivElement | null>(null);

	const filtered = useMemo(() => {
		const q = query.trim().toLowerCase();
		if (!q) return ctx?.logs ?? [];
		return (ctx?.logs ?? []).filter((e) => {
			const blob = `${e.category} ${e.title} ${JSON.stringify(e.detail ?? {})}`.toLowerCase();
			return blob.includes(q);
		});
	}, [ctx?.logs, query]);

	useEffect(() => {
		if (!ctx?.enabled || !ctx.open || !ctx.autoScroll) return;
		const el = scrollRef.current;
		if (!el) return;
		el.scrollTop = 0;
	}, [ctx?.logs, ctx?.open, ctx?.autoScroll, ctx?.enabled]);

	if (!ctx?.enabled) return null;

	return (
		<>
			{!ctx.open ? (
				<button
					type="button"
					className="fixed bottom-4 left-4 z-[90] rounded-full border border-border/80 bg-card/90 px-3 py-1.5 text-[11px] font-medium text-muted-foreground shadow-lg backdrop-blur-md hover:bg-card hover:text-foreground"
					onClick={() => ctx.setOpen(true)}
					aria-label="Open developer diagnostics"
					title="Keyboard: ⌘⇧C / ⌘⇧D (Mac) or Ctrl⇧C / Ctrl⇧D (Windows)"
				>
					Diagnostics
				</button>
			) : null}
			{ctx.open ? (
				<div className="fixed inset-0 z-[100] flex items-end justify-center p-4 sm:items-center">
					<button
						type="button"
						aria-label="Close diagnostics"
						className="absolute inset-0 bg-black/60 backdrop-blur-sm"
						onClick={() => ctx.setOpen(false)}
					/>
					<div
						className="glass-surface relative z-[101] flex max-h-[min(640px,85vh)] w-full max-w-3xl flex-col overflow-hidden shadow-2xl"
						role="dialog"
						aria-modal="true"
						aria-label="Developer diagnostics"
					>
						<header className="flex flex-wrap items-center gap-3 border-b border-border/60 px-4 py-3">
							<h2 className="text-sm font-semibold">Developer diagnostics</h2>
							<span className="max-w-[min(100%,14rem)] rounded-full bg-muted-foreground/15 px-2 py-0.5 text-[10px] leading-snug text-muted-foreground">
								⌘⇧C · ⌘⇧D · Ctrl⇧C/D
							</span>
							<div className="ml-auto flex flex-wrap items-center gap-2">
								<label className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
									<input
										type="checkbox"
										checked={ctx.autoScroll}
										onChange={(e) => ctx.setAutoScroll(e.target.checked)}
									/>
									Auto-scroll
								</label>
								<button
									type="button"
									className="rounded-sm border border-border px-2 py-1 text-[11px] hover:bg-white/5"
									onClick={() => {
										void navigator.clipboard.writeText(ctx.exportLogs());
									}}
								>
									Export
								</button>
								<button
									type="button"
									className="rounded-sm border border-border px-2 py-1 text-[11px] hover:bg-white/5"
									onClick={ctx.clearLogs}
								>
									Clear
								</button>
								<button
									type="button"
									className="rounded-sm border border-border px-2 py-1 text-[11px] hover:bg-white/5"
									onClick={() => ctx.setOpen(false)}
								>
									Close
								</button>
							</div>
						</header>
						<div className="border-b border-border/60 px-4 py-2">
							<input
								value={query}
								onChange={(e) => setQuery(e.target.value)}
								placeholder="Search logs…"
								className="glass-input h-9 text-xs"
							/>
						</div>
						<div ref={scrollRef} className="flex-1 overflow-y-auto px-2 pb-4 pt-1">
							{filtered.length === 0 ? (
								<p className="px-3 py-8 text-center text-xs text-muted-foreground">
									No log entries yet.
								</p>
							) : (
								filtered.map((entry) => (
									<div key={entry.id} className="group px-2">
										<LogRow
											entry={entry}
											expanded={Boolean(expanded[entry.id])}
											onToggle={() =>
												setExpanded((m) => ({
													...m,
													[entry.id]: !m[entry.id],
												}))
											}
										/>
										<div className="-mt-1 mb-2 flex justify-end px-2 opacity-0 transition-opacity group-hover:opacity-100">
											<button
												type="button"
												className="text-[11px] text-primary hover:underline"
												onClick={() => {
													const payload = JSON.stringify(entry, null, 2);
													void navigator.clipboard.writeText(payload);
												}}
											>
												Copy entry
											</button>
										</div>
									</div>
								))
							)}
						</div>
					</div>
				</div>
			) : null}
		</>
	);
}
