#!/usr/bin/env tsx

import path from "node:path";
import child from "node:child_process";
import fs from "node:fs/promises";
import dotenv from "dotenv";
import * as acme from 'acme-client';
import dayjs from "dayjs";

dotenv.config({path:['.env', '.env.local', '.env.prod'], override:true});

(async()=>{
	const SSL_POOL_DIR = path.resolve(__dirname, process.env.SSL_POOL_DIR||'./pool');
	const entries = await fs.readdir(SSL_POOL_DIR, { withFileTypes: true });
	const projDirs:{path:string, meta:string, name:string}[] = [];
	
	for (const entry of entries) {
		const itemName = entry.name;
		if ( itemName === '.' || itemName === '..' || !entry.isDirectory() ) continue;
		const candidateDir = path.join(SSL_POOL_DIR, itemName);
		const metaPath = path.join(candidateDir, 'meta.json');
		const metaContent = await fs.readFile(metaPath).catch((e:Error&{code?:string})=>e);
		if ( metaContent instanceof Error ) {
			console.error('Error reading meta file:', metaPath);
			continue;
		}
		
		const metaInfo = JSONDecode<SSLMeta>(metaContent.toString('utf8'));
		if ( !metaInfo ) {
			console.error('Error parsing meta file:', metaPath);
			continue;
		}

		if ( metaInfo.expiredDate ) {
			const projExpiredDate = new Date(metaInfo.expiredDate);
			const projExpiredTime = projExpiredDate.getTime();
			if ( projExpiredTime <= Date.now() ) {
				console.log(`Project \`${itemName}\` has been expired at ${dayjs(projExpiredDate).format('YYYY-MM-DD HH:mm')}! Skipping... ❌`);
				continue;
			}
		}

		projDirs.push({path:candidateDir, meta:metaPath, name:itemName});
	}
	
	
	const padding = projDirs.reduce((max, projDir) => Math.max(max, projDir.name.length), 0);
	for(const projDir of projDirs) {
		const certPath = path.join(projDir.path, 'ssl.crt');
		const accState = await fs.access(certPath).catch((e)=>e);
		const paddedDirName = projDir.name.padEnd(padding, ' ');
		if ( accState instanceof Error ) {
			const error = accState as Error & {code?:string};
			if ( error.code !== 'ENOENT' ) {
				console.error('Error reading certificate file:', certPath);
				console.error('Error:', error);
				continue;
			}

			console.log(`${paddedDirName}: no initialized! Initializing... ❌`);
		}
		else {
			const cert = await fs.readFile(certPath);
			const certInfo = acme.crypto.readCertificateInfo(cert);
			const expiredTime = certInfo.notAfter.getTime();
			const updateBoundary = Date.now() + 7 * 86400_000;
			const isExpired = expiredTime <= updateBoundary;
			
			if (!isExpired) {
				console.log(`${paddedDirName}: ${dayjs(expiredTime).format('YYYY-MM-DD HH:mm')}. Passed! ✅`);
				continue;
			}
			else {
				console.log(`${paddedDirName}: ${dayjs(expiredTime).format('YYYY-MM-DD HH:mm:ss')}. Refreshing... ❌`);
			}
		}


		console.log(`Processing certificate for ${projDir.name}...`);
		const refScript = path.join(__dirname, 'tool.refresh.ts');
			
		// 執行 ref.ts 腳本
		const childProc = child.spawn('tsx', [
			refScript,
			projDir.meta,
		], { stdio:'inherit', cwd:projDir.path });
		
		const execResult = await new Promise<void>((resolve, reject) => {
			childProc.on('close', (code, signal) => {
				if (code === 0) {
					resolve();
				} 
				else
				if ( code !== null ) {
					reject(new Error(`Process exited with code ${code}`));
				}
				else {
					reject(new Error(`Process exited with signal ${signal}`));
				}
			});
			
			childProc.on('error', e=>reject(e));
		}).catch(e=>e);

		if ( execResult instanceof Error ) {
			console.error('Error executing ref.ts:', execResult);
			continue;
		}

		console.log(`${projDir} refreshed!`);
	}


	function JSONDecode<Type=any>(str:string):Type|undefined {
		try {
			return JSON.parse(str);
		}
		catch(e) {
			return undefined;
		}
	}
})();