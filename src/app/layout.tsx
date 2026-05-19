import type { ReactNode } from "react";
import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { RootShell } from "@/components/root-shell";
import "goey-toast/styles.css";
import "./globals.css";

const geistSans = Geist({
	variable: "--font-geist-sans",
	subsets: ["latin"],
});

const geistMono = Geist_Mono({
	variable: "--font-geist-mono",
	subsets: ["latin"],
});

export const metadata: Metadata = {
	title: "2FA",
	description: "Sign in to your account",
};

export default function RootLayout({
	children,
}: Readonly<{
	children: ReactNode;
}>) {
	return (
		<html lang="en" className={`${geistSans.variable} ${geistMono.variable} h-full`}>
			<body className={`${geistSans.className} min-h-full font-sans antialiased`}>
				<RootShell>{children}</RootShell>
			</body>
		</html>
	);
}
