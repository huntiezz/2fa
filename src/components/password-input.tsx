"use client";

import { Eye, EyeOff } from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";

type PasswordInputProps = {
	id?: string;
	value: string;
	onChange: (value: string) => void;
	autoComplete?: string;
	placeholder?: string;
	required?: boolean;
	className?: string;
};

export function PasswordInput({
	id = "password",
	value,
	onChange,
	autoComplete = "current-password",
	placeholder = "Password",
	required,
	className,
}: PasswordInputProps) {
	const [visible, setVisible] = useState(false);

	return (
		<div className={cn("relative", className)}>
			<input
				id={id}
				type={visible ? "text" : "password"}
				autoComplete={autoComplete}
				placeholder={placeholder}
				value={value}
				onChange={(e) => onChange(e.target.value)}
				required={required}
				className="glass-input pr-11"
			/>
			<button
				type="button"
				onClick={() => setVisible((prev) => !prev)}
				className="absolute top-1/2 right-3 -translate-y-1/2 text-muted-foreground transition-colors hover:text-foreground"
				aria-label={visible ? "Hide password" : "Show password"}
			>
				{visible ? <Eye size={20} /> : <EyeOff size={20} />}
			</button>
		</div>
	);
}
