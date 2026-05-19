"use client";

import { DotmSquare1 } from "@/components/ui/dotm-square-1";

export function AuthLoading({ label = "Signing in…" }: { label?: string }) {
	return (
		<div className="fixed inset-0 z-50 flex flex-col items-center justify-center gap-5 bg-background/80 backdrop-blur-md">
			<DotmSquare1 size={52} dotSize={6} color="var(--dot-on)" animated ariaLabel={label} />
			<p className="text-sm text-muted-foreground">{label}</p>
		</div>
	);
}
