"use client";

import { GooeyToaster } from "goey-toast";

export function GooeyToasterProvider() {
	return (
		<GooeyToaster
			position="top-right"
			theme="light"
			preset="bouncy"
			closeButton="top-right"
			visibleToasts={4}
			offset={16}
		/>
	);
}
