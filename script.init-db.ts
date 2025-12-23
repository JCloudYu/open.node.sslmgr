import "extes";
import fs from "fs/promises";
import path from "path";
import Database from "better-sqlite3";
import {LogTool} from "@/env.runtime.js";
import dotenv from "dotenv";


dotenv.config({path:['.env', '.env.local', '.env.prod'], override:true});

(async()=>{
	const DB_PATH = path.resolve(__dirname, process.env.SQLITE_PATH||'./db.sqlite3');
	const db_dir = path.dirname(DB_PATH);

	try {
		await fs.access(DB_PATH);
		LogTool.info(`Session database already exists at ${DB_PATH}`);
		return;
	}
	catch {
		// File does not exist; continue to create
	}


	try {
		await fs.mkdir(db_dir, {recursive:true});
	}
	catch {
		// Ignore if directory already exists or cannot be created
	}


	const db = new Database(DB_PATH);
	db.exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			host TEXT NOT NULL,
			valid INTEGER NOT NULL DEFAULT 1,
			key TEXT NOT NULL UNIQUE,
			note TEXT NOT NULL,
			expired INTEGER NOT NULL,
			created INTEGER NOT NULL
		);
		
		CREATE INDEX IF NOT EXISTS idx_sessions_key ON sessions(key);
	`);
	db.close();

	LogTool.info(`Session database initialized at ${DB_PATH}`);
})(); 


