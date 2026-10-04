import type process from "process";


declare global {
	interface SSLMeta {
		expiredDate?: string;
		auth: {
			type:string;
			zone_id:string;
			token:string;
		};
		domains:string[];
	}
}