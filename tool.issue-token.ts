#!/usr/bin/env tsx

import dotenv from "dotenv";
import BWT from "@/lib/bwt.js";
import Database from "better-sqlite3";
import fs from "fs";
import path from "path";
import TrimId from "trimid";


dotenv.config({path:['.env', '.env.local', '.env.prod'], override:true});

(async()=>{
	const SESSION_DB_PATH = path.resolve(__dirname, process.env.SQLITE_PATH||'./db.sqlite3');
	const SessionDB = new Database(SESSION_DB_PATH);


	const ARGV = process.argv.slice(2);
	const [pool_id, description, exp_ts] = ARGV;
	if ( !description ) {
		console.error("Usage: tool.issue-token.ts pool_id [description] [exp_ts]");
		process.exit(1);
		return;
	}

	
	const certMetaPath = path.resolve(__dirname, process.env.SSL_POOL_DIR||'./pool', pool_id, 'meta.json');
	if ( !fs.existsSync(certMetaPath) ) {
		console.error("Certificate meta file not found! Path: ", certMetaPath);
		process.exit(1);
		return;
	}


	let expired_time = -1;
	if ( exp_ts ) {
		const exp_date = new Date(exp_ts);
		if ( isNaN(exp_date.getTime()) ) {
			console.error("Invalid expiration time! Accepted format is YYYY-MM-DDTHH:MM:SS+ZZZZ");
			process.exit(1);
			return;
		}

		expired_time = Math.floor(exp_date.getTime()/1000);
	}

	const now = Math.floor(Date.now() / 1000);
	const sessionId = TrimId.shortid();
	

	const token = BWT.encode({
		jti: sessionId,
		did: pool_id,
		iat: now,
		nbf: now,
		exp: expired_time,
	}, Buffer.from(process.env.BWT_SECRET!, 'base64'));

	const stmt = SessionDB.prepare<[string, string, string, epoch, epoch], void>(
		"INSERT INTO sessions (key, host, note, expired, created) VALUES (?, ?, ?, ?, ?);"
	);
	stmt.run(sessionId, pool_id, description, expired_time, now);
	
	console.log('TKN:', token);
	console.log('HST:', pool_id);
	console.log('SID:', sessionId);
	console.log('DES:', description);
	console.log('EXP:', expired_time < 0 ? 'Never' : new Date(expired_time * 1000).toLocaleISOString());
})();