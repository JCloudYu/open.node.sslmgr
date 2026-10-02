#!/usr/bin/env tsx

import path from "node:path";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import dotenv from "dotenv";
import dayjs from "dayjs";

dotenv.config({path:['.env', '.env.prod', '.env.local'], override:true});



const CERT_DIR = path.resolve(__dirname, process.env.CERT_DIR||'./cert');
const CERT_FETCH_HOST = (process.env.CERT_FETCH_HOST||'').replace(/\/+$/, '');
const CERT_HOST_KEY = (process.env.CERT_HOST_KEY||'').trim();
const CHECK_INTERVAL = 3600_000;
const UPDATE_BOUNDARY = 7 * 86400_000;

if ( !CERT_FETCH_HOST ) {
	console.error('CERT_FETCH_HOST is not set!');
	process.exit(1);
}

if ( !CERT_HOST_KEY ) {
	console.error('CERT_HOST_KEY is not set!');
	process.exit(1);
}

let running = false;
RefreshCertificate();
setInterval(RefreshCertificate, CHECK_INTERVAL);



async function RefreshCertificate() {
	if ( running ) return;
	running = true;

	const logTime = dayjs().format('YYYY-MM-DD HH:mm:ss');
	const keyPath = path.join(CERT_DIR, 'ssl.key');
	const crtPath = path.join(CERT_DIR, 'ssl.crt');
	const bundlePath = path.join(CERT_DIR, 'bundle.pem');

	const result = await (async()=>{
		const keyPem = await fs.readFile(keyPath).catch(()=>null);
		if ( !keyPem ) {
			throw new Error(`Unable to read private key: ${keyPath}`);
		}
		const privateKey = crypto.createPrivateKey(keyPem);

		let localCert:crypto.X509Certificate|null = null;
		const localCrt = await fs.readFile(crtPath).catch(()=>null);
		if ( localCrt ) {
			try { localCert = new crypto.X509Certificate(localCrt); }
			catch { localCert = null; }
		}

		const hasBundle = await fs.access(bundlePath).then(()=>true, ()=>false);
		const localNotAfter = localCert ? new Date(localCert.validTo).getTime() : 0;

		if ( localCert && hasBundle && localNotAfter - Date.now() > UPDATE_BOUNDARY ) {
			console.log(`[${logTime}] ${CERT_HOST_KEY}: ${dayjs(localNotAfter).format('YYYY-MM-DD HH:mm:ss')}. Passed! ✅`);
			return;
		}

		const localState = localCert ? dayjs(localNotAfter).format('YYYY-MM-DD HH:mm:ss') : 'no certificate';
		console.log(`[${logTime}] ${CERT_HOST_KEY}: ${localState}${hasBundle ? '' : ' (no bundle)'}. Refreshing... ❌`);



		const signature = crypto.createSign('RSA-SHA256')
			.update(JSON.stringify({key:CERT_HOST_KEY, ts:Math.floor(Date.now() / 10000)}))
			.sign({key:privateKey, padding:crypto.constants.RSA_PKCS1_PADDING})
			.toString('base64url');

		const [crtPem, bundlePem] = await Promise.all(['crt', 'bundle'].map(async(type)=>{
			const res = await fetch(`${CERT_FETCH_HOST}/ssl/${encodeURIComponent(CERT_HOST_KEY)}/${type}`, {
				headers:{Authorization:signature},
				signal:AbortSignal.timeout(30_000)
			});
			if ( !res.ok ) {
				throw new Error(`Unable to fetch ${type}! (status:${res.status})`);
			}
			return res.text();
		}));

		const remoteCert = new crypto.X509Certificate(crtPem);
		const remoteNotAfter = new Date(remoteCert.validTo).getTime();
		if ( !remoteCert.checkPrivateKey(privateKey) ) {
			throw new Error('Fetched certificate does not match local private key!');
		}
		if ( !bundlePem.includes(crtPem.trim()) ) {
			throw new Error('Fetched bundle does not contain fetched certificate!');
		}
		if ( localCert && hasBundle && remoteNotAfter <= localNotAfter ) {
			console.log(`[${logTime}] ${CERT_HOST_KEY}: remote certificate has not been renewed yet! (${dayjs(remoteNotAfter).format('YYYY-MM-DD HH:mm:ss')})`);
			return;
		}

		await fs.writeFile(`${crtPath}.tmp`, crtPem);
		await fs.writeFile(`${bundlePath}.tmp`, bundlePem, {mode:0o600});
		await fs.rename(`${crtPath}.tmp`, crtPath);
		await fs.rename(`${bundlePath}.tmp`, bundlePath);
		console.log(`[${logTime}] ${CERT_HOST_KEY}: ${dayjs(remoteNotAfter).format('YYYY-MM-DD HH:mm:ss')}. Updated! ✅`);

		// 對 PID=1 發 SIGNAL
	})().catch((e:Error)=>e);

	if ( result instanceof Error ) {
		console.error(`[${logTime}] Error refreshing certificate:`, result.message);
	}

	running = false;
}
