#!/usr/bin/env tsx

import dotenv from "dotenv";
import BWT from "@/lib/bwt.js";


dotenv.config({path:['.env', '.env.local', '.env.prod'], override:true});

(async()=>{
	const ARGV = process.argv.slice(2);
	const [did, exp_ts] = ARGV;
	if ( !did ) {
		console.error("Usage: tool.issue-token.ts {did} [exp_ts]");
		process.exit(1);
		return;
	}


	let exp_date = new Date(Date.now() + 365 * 86400_000);
	if ( exp_ts ) {
		exp_date = new Date(exp_ts);
		if ( isNaN(exp_date.getTime()) ) {
			console.error("Invalid expiration time! Accepted format is YYYY-MM-DDTHH:MM:SS+ZZZZ");
			process.exit(1);
			return;
		}
	}

	const now = Math.floor(Date.now() / 1000);
	const token = BWT.encode({
		did,
		iat: now,
		nbf: now,
		exp: Math.floor(exp_date.getTime() / 1000),
	}, Buffer.from(process.env.BWT_SECRET!, 'base64'));
	
	console.log(token);
})();