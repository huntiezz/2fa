import { AppShell } from "@/components/app-shell";
import { LoginForm } from "@/components/login-form";

export default function SignupPage() {
	return (
		<AppShell>
			<LoginForm mode="signup" />
		</AppShell>
	);
}
