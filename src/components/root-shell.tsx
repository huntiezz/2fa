import type { ReactNode } from "react";
import { createClient } from "@/lib/supabase/server";
import { DevDiagnosticsConsole } from "@/components/dev-diagnostics-console";
import { GooeyToasterProvider } from "@/components/gooey-toaster";
import { DevDiagnosticsProvider } from "@/context/dev-diagnostics-context";
import { isDevConsoleAllowedForUser } from "@/lib/mfa/env";

export const dynamic = "force-dynamic";

export async function RootShell({ children }: { children: ReactNode }) {
	const supabase = await createClient();
	const {
		data: { user },
	} = await supabase.auth.getUser();
	const devDiagnosticsEnabled = isDevConsoleAllowedForUser(user?.email ?? undefined);

	return (
		<DevDiagnosticsProvider enabled={devDiagnosticsEnabled}>
			{children}
			<GooeyToasterProvider />
			<DevDiagnosticsConsole />
		</DevDiagnosticsProvider>
	);
}
