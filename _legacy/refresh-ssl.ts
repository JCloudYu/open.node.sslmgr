#!/usr/bin/env node
// @ts-nocheck
import fs from "fs";
import acme from "acme-client";

(async()=>{
	process
	.on('unhandledRejection', (e)=>{
		console.error("UnhandledRejection:", e);
	})
	.on('uncaughtException', (e)=>{
		console.error("UncaughtException:", e);
	});



	/* Init client */
	const cf_info = {
		zone_id: '', // cf zone id
		token: '' // cf token
	};
	const client_key = await acme.crypto.createPrivateKey();
	const crt_key = await acme.crypto.createPrivateKey();
	// root domain, ... additional domains
	const domains = [ 'prebeta.aihunter.net', '*.prebeta.aihunter.net', 'beta.aihunter.net', '*.beta.aihunter.net' ];
	const challanges = [ 'dns-01' ];
	const CF_EFFECTIVE_TIME = 90_000;
	const IS_PRODUCTION = true;


	





	const created_records = [];
    const client = new acme.Client({
        directoryUrl: IS_PRODUCTION ? acme.directory.letsencrypt.production : acme.directory.letsencrypt.staging,
        accountKey: client_key
    });

    /* Create CSR */
    const [,csr] = await acme.crypto.createCsr({
		commonName: domains[0], altNames: domains.slice(1)
    }, crt_key);

    /* Certificate */
    const cert = await client.auto({
        csr,
        email: 'j.cloud.yu@purimize.com',
        termsOfServiceAgreed: true,
		challengePriority: challanges,
        challengeCreateFn:async(authz, challenge, keyAuthorization)=>{
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
				await CF_CreateTXTRecordForTag(cf_info, RECORD_NAME, RECORD_VALUE);

				console.log(`[${SEQ}] Waiting for CF to take affect...`);
				await Idle(CF_EFFECTIVE_TIME);
				created_records.push(RECORD_NAME);
			}
		},
        challengeRemoveFn:async(authz, challenge, keyAuthorization)=>{
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
		await CF_PurgeAllTXTRecordsForTag(cf_info, record_name);
	}
	const cert_info = await acme.crypto.readCertificateInfo(cert);
	console.log("Done!\n");


    /* Done */
	fs.writeFileSync('./client.ket', client_key.toString());
	fs.writeFileSync('./ssl.csr', csr.toString());
	fs.writeFileSync('./ssl.key', crt_key.toString());
	fs.writeFileSync('./ssl.crt', cert.toString());

	cert_info.notAfterLocal = ToLocalISOString(cert_info.notAfter);
	cert_info.notBeforeLocal = ToLocalISOString(cert_info.notBefore);
	console.log('Cert Info:', cert_info);
})();



function ToLocalISOString(ref_date=undefined, show_milli=false) {
	if ( this instanceof Date ) ref_date = this;
	if ( typeof ref_date === "string" || typeof ref_date === "number" ) {
		ref_date = new Date(ref_date);
	}
	else 
	if ( !(ref_date instanceof Date) ) {
		ref_date = new Date();
	}

	if ( Number.isNaN(ref_date.getTime()) ) {
		throw new RangeError("Invalid time value");
	}
	
	
	
	let offset = 'Z';

	const zone = ref_date.getTimezoneOffset();
	if (zone !== 0) {
		const abs_zone	= Math.abs(zone);
		const zone_hour = Math.floor(abs_zone / 60);
		const zone_min	= abs_zone % 60;
		offset = (zone > 0 ? '-' : '+') + (zone_hour.toString().padStart(2, '0')) + (zone_min.toString().padStart(2, '0'));
	}
	
	const milli = show_milli ? ('.' + (ref_date.getMilliseconds() % 1000).toString().padStart(3, '0')) : '';
	return ref_date.getFullYear() +
		'-' + (ref_date.getMonth() + 1).toString().padStart(2, '0') +
		'-' + (ref_date.getDate()).toString().padStart(2, '0') +
		'T' + (ref_date.getHours()).toString().padStart(2, '0') +
		':' + (ref_date.getMinutes()).toString().padStart(2, '0') +
		':' + (ref_date.getSeconds()).toString().padStart(2, '0') +
		milli + offset;
}


function Idle(milli_seconds) {
	return new Promise((res)=>setTimeout(res, milli_seconds||0));
}
async function CF_PurgeAllTXTRecordsForTag(auth_info, tag_name) {
	const list = await fetch(`https://api.cloudflare.com/client/v4/zones/${auth_info.zone_id}/dns_records`,{
		method: 'GET',
		headers: { Authorization: `bearer ${auth_info.token}` }
	})
	.then(async(res)=>{
		const body = await res.json();
		if (res.status !== 200) {
			console.log(res.status, require('util').inspect(body, false, null, true));
			return Promise.reject(Object.assign(new Error("Unable to fetch dns records!"), {code:res.status, remote:true, detail:body}));
		}
		return body;
	});
	
	const txt_records = list.result.filter((i)=>i.type === 'TXT' && i.name === tag_name);
	for(const record of txt_records) {
		console.log(`PURGE: ${record.name} ID: ${record.id} ZONE: ${record.zone_id}`);
		await fetch(`https://api.cloudflare.com/client/v4/zones/${record.zone_id}/dns_records/${record.id}`, {
			method:'DELETE',
			headers: { Authorization: `bearer ${auth_info.token}` }
		}).then(async(res)=>{
			const body = await res.json();
			if (res.status !== 200) {
				console.log(res.status, require('util').inspect(body, false, null, true));
				return Promise.reject(Object.assign(new Error("Unable to delete txt record!"), {code:res.status, remote:true, detail:body}));
			}
			
			return body;
		});
	}
}

async function CF_CreateTXTRecordForTag(auth_info, tag_name, tag_value) {
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
			console.log(res.status, require('util').inspect(body, false, null, true));
			return Promise.reject(Object.assign(new Error("Unable to create txt record!"), {code:res.status, remote:true, detail:body}));
		}
		
		return body;
	});
}