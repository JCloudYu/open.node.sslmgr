import type process from "process";


declare global {
	interface AuthSession {
		jti:uniqid;
		did:uniqid;
		exp:epoch; 
		iat:epoch;
		nbf:epoch;
	};

	interface SSLMeta {
		auth: {
			type:string;
			zone_id:string;
			token:string;
		};
		domains:string[];
	}
}