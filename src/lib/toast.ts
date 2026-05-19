import { gooeyToast } from "goey-toast";

const defaults = { preset: "bouncy" as const };

export const toast = {
	success(message: string) {
		return gooeyToast.success(message, defaults);
	},
	error(message: string) {
		return gooeyToast.error(message, defaults);
	},
	info(message: string) {
		return gooeyToast.info(message, defaults);
	},
};
