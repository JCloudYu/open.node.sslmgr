#!/usr/bin/env tsx
import * as acme from 'acme-client';
import * as fs from 'fs';
import path from 'path';
import { inspect } from 'util';

(async()=>{
	process
	.on('unhandledRejection', (e: unknown)=>{
		console.error("UnhandledRejection:", e);
	})
	.on('uncaughtException', (e: unknown)=>{
		console.error("UncaughtException:", e);
	});


	const META_DIR = path.resolve(__dirname, 'meta.json');
	const meta_str = fs.readFileSync(META_DIR, 'utf-8');
	const meta:SSLMeta = JSON.parse(meta_str);

	

	// Environmental context
	const challanges: string[] = [ 'dns-01' ];
	const CF_EFFECTIVE_TIME = 90_000;
	const IS_PRODUCTION = true;





	
	/* Init client */
	let client_key: Buffer, crt_key: Buffer;
	try {
		client_key = fs.readFileSync('./client.key');
	}
	catch(e: unknown) {
		if ( e instanceof Error ) {
			const err = e as Error&{code?:string};
			if ( err.code !== 'ENOENT' ) {
				throw e;
			}
		}
		
		console.log("No client.key found! Generating...");
		client_key = await acme.crypto.createPrivateKey(4096);
		fs.writeFileSync('./client.key', client_key);
	}
	
	try {
		crt_key = fs.readFileSync('./ssl.key');
	}
	catch(e: unknown) {
		if ( e instanceof Error ) {
			const err = e as Error&{code?:string};
			if ( err.code !== 'ENOENT' ) {
				throw e;
			}
		}
		
		console.log("No ssl.key found! Generating...");
		crt_key = await acme.crypto.createPrivateKey(4096);
		fs.writeFileSync('./ssl.key', crt_key);
	}

	interface AuthzType {
		identifier: {
			value: string;
		}
	}

	interface ChallengeType {
		type: string;
		token: string;
	}

	const created_records: string[] = [];
    const client = new acme.Client({
        directoryUrl: IS_PRODUCTION ? acme.directory.letsencrypt.production : acme.directory.letsencrypt.staging,
        accountKey: client_key
    });

    /* Create CSR */
    const [,csr] = await acme.crypto.createCsr({
		commonName: meta.domains[0], 
		altNames: meta.domains.slice(1)
    }, crt_key);

    /* Certificate */
    const cert = await client.auto({
        csr,
        email: 'j.cloud.yu@purimize.com',
        termsOfServiceAgreed: true,
		challengePriority: challanges,
        challengeCreateFn: async(authz: AuthzType, challenge: ChallengeType, keyAuthorization: string) => {
			const SEQ = Date.now()%100_000;

			/* http-01 */
			if (challenge.type === 'http-01') {
				const RECORD_PATH = `/.well-known/acme-challenge/${challenge.token}`;
				const RECORD_VALUE = keyAuthorization;
		
				console.log(`[${SEQ}] PATH: ${RECORD_PATH} VAL: ${RECORD_VALUE}`);
				// await fs.writeFile(filePath, fileContents);
			}
			else if (challenge.type === 'dns-01') {
				const RECORD_NAME = `_acme-challenge.${authz.identifier.value}`;
				const RECORD_VALUE = keyAuthorization;
		
				console.log(`[${SEQ}] TXT: ${RECORD_NAME} VAL: ${RECORD_VALUE}`);
				await CF_CreateTXTRecordForTag(meta.auth, RECORD_NAME, RECORD_VALUE);

				console.log(`[${SEQ}] Waiting for CF to take affect...`);
				await Idle(CF_EFFECTIVE_TIME);
				created_records.push(RECORD_NAME);
			}
		},
        challengeRemoveFn: async(authz: AuthzType, challenge: ChallengeType, keyAuthorization: string) => {
			/* http-01 */
			if (challenge.type === 'http-01') {
				const RECORD_PATH = `/.well-known/acme-challenge/${challenge.token}`;
				const RECORD_VALUE = keyAuthorization;
		
				//console.log(`[DEL] PATH: ${RECORD_PATH} VAL:${RECORD_VALUE}`);
				// await fs.unlink(filePath);
			}
		
			/* dns-01 */
			else if (challenge.type === 'dns-01') {
				const RECORD_NAME = `_acme-challenge.${authz.identifier.value}`;
				const RECORD_VALUE = keyAuthorization;
		
				//console.log(`[DEL] TXT: ${RECORD_NAME} VAL:${RECORD_VALUE}`);
			}
		}
    });

	console.log("Purging CFRecords...");
	const records = new Set(created_records);
	for(const record_name of records) {
		console.log(`Purging ${record_name}...`);
		await CF_PurgeAllTXTRecordsForTag(meta.auth, record_name);
	}
	const cert_info = await acme.crypto.readCertificateInfo(cert);
	console.log("Done!\n");

    /* Done */
	fs.writeFileSync('./ssl.csr', csr.toString());
	fs.writeFileSync('./ssl.crt', cert.toString());
	fs.writeFileSync('./bundle.pem', cert.toString() + '\n' + crt_key.toString());

	console.log('Cert Info:', Object.assign({}, cert_info, {
		notAfterLocal: ToLocalISOString(cert_info.notAfter),
		notBeforeLocal: ToLocalISOString(cert_info.notBefore)
	}));
})();






function ToLocalISOString(ref_date: Date | string | number | undefined = undefined, show_milli = false): string {
	let date: Date;
	
	if (typeof ref_date === "string" || typeof ref_date === "number") {
		date = new Date(ref_date);
	}
	else if (ref_date instanceof Date) {
		date = ref_date;
	}
	else {
		date = new Date();
	}

	if (Number.isNaN(date.getTime())) {
		throw new RangeError("Invalid time value");
	}
	
	let offset = 'Z';

	const zone = date.getTimezoneOffset();
	if (zone !== 0) {
		const abs_zone	= Math.abs(zone);
		const zone_hour = Math.floor(abs_zone / 60);
		const zone_min	= abs_zone % 60;
		offset = (zone > 0 ? '-' : '+') + (zone_hour.toString().padStart(2, '0')) + (zone_min.toString().padStart(2, '0'));
	}
	
	const milli = show_milli ? ('.' + (date.getMilliseconds() % 1000).toString().padStart(3, '0')) : '';
	return date.getFullYear() +
		'-' + (date.getMonth() + 1).toString().padStart(2, '0') +
		'-' + (date.getDate()).toString().padStart(2, '0') +
		'T' + (date.getHours()).toString().padStart(2, '0') +
		':' + (date.getMinutes()).toString().padStart(2, '0') +
		':' + (date.getSeconds()).toString().padStart(2, '0') +
		milli + offset;
}

function Idle(milli_seconds: number): Promise<void> {
	return new Promise((res)=>setTimeout(res, milli_seconds||0));
}

async function CF_PurgeAllTXTRecordsForTag(auth_info: CFAuthInfo, tag_name: string): Promise<void> {
	const list = await fetch(`https://api.cloudflare.com/client/v4/zones/${auth_info.zone_id}/dns_records`,{
		method: 'GET',
		headers: { Authorization: `bearer ${auth_info.token}` }
	})
	.then(async(res)=>{
		const body = await res.json() as CFResponse;
		if (res.status !== 200) {
			console.log(res.status, inspect(body, false, null, true));
			return Promise.reject(Object.assign(new Error("Unable to fetch dns records!"), {code:res.status, remote:true, detail:body}));
		}
		return body;
	});
	
	const txt_records = list.result.filter((i)=>i.type === 'TXT' && i.name === tag_name);
	for(const record of txt_records) {
		console.log(`PURGE: ${record.name} ID: ${record.id} ZONE: ${auth_info.zone_id}`);
		await fetch(`https://api.cloudflare.com/client/v4/zones/${auth_info.zone_id}/dns_records/${record.id}`, {
			method:'DELETE',
			headers: { Authorization: `bearer ${auth_info.token}` }
		}).then(async(res)=>{
			const body = await res.json();
			if (res.status !== 200) {
				console.log(res.status, inspect(body, false, null, true));
				return Promise.reject(Object.assign(new Error("Unable to delete txt record!"), {code:res.status, remote:true, detail:body}));
			}
			
			return body;
		});
	}
}

async function CF_CreateTXTRecordForTag(auth_info: CFAuthInfo, tag_name: string, tag_value: string): Promise<unknown> {
	return fetch(`https://api.cloudflare.com/client/v4/zones/${auth_info.zone_id}/dns_records`, {
		method:'POST',
		headers: { Authorization: `bearer ${auth_info.token}` },
		body: Buffer.from(JSON.stringify({
			name: tag_name,
			content: tag_value,
			proxied: false,
			type: 'TXT',
			comment: "ACME Challange for session " + Date.now(),
			ttl: 60
		}))
	}).then(async(res)=>{
		const body = await res.json();
		if (res.status !== 200) {
			console.log(res.status, inspect(body, false, null, true));
			return Promise.reject(Object.assign(new Error("Unable to create txt record!"), {code:res.status, remote:true, detail:body}));
		}
		
		return body;
	});
}




interface CFResponse {
	result: CFRecord[];
};

interface CFRecord {
	type: string;
	name: string;
	id: string;
	zone_id: string;
};

interface CFAuthInfo {
	zone_id: string;
	token: string;
};