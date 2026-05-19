import type { ReactNode } from "react";

export function AppShell({ children }: { children: ReactNode }) {
	return (
		<div className="app-bg relative flex min-h-svh w-full flex-col items-center justify-center px-6 py-10 text-foreground">
			{children}
		</div>
	);
}
