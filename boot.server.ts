import "extes";
import Fastify from "fastify";
import dotenv from "dotenv";
import path from "path";
import crypto from "node:crypto";
import * as acme from 'acme-client';
import fs from "fs/promises";
import {createWriteStream} from "node:fs";
import child from "node:child_process";
import dayjs from "dayjs";

import Helper from "@/lib/helper.js";
import {LogTool, ContextCtrl} from "@/env.runtime.js";
import {ErrorCode} from "@/lib/error-code.js";




dotenv.config({path:['.env', '.env.prod', '.env.local'], override:true});
const STORAGE_DIR = path.resolve(__dirname, process.env.STORAGE_DIR!);

Promise.chain(async()=>{
	// Bind core events
	{
		process
		.on('unhandledRejection', (e)=>{
			LogTool.fatal("Received unhandled rejection:", e);
			process.emit('terminate', e as Error);
		})
		.on('uncaughtException', (e)=>{
			LogTool.fatal("Received unhandled rejection:", e);
			process.emit('terminate', e);
		})
		.on('SIGQUIT', SIGNAL_CLOSE)
		.on('SIGINT', SIGNAL_CLOSE);


		function SIGNAL_CLOSE(signal:NodeJS.Signals) {
			LogTool.fatal(`Received ${signal} signal...`);
			process.emit('terminate');
		}
	}


	const fastify = Fastify()
	.register(async(fastify)=>{
		fastify.addHook('onRequest', async(req, reply)=>{
			const {poolKey} = req.params as {poolKey?:string;};
			const given = (req.headers.authorization||'').trim();
			const entries = await fs.readdir(STORAGE_DIR, {withFileTypes:true}).catch(()=>[]);
			if (
				!poolKey || !entries.some((entry)=>entry.isDirectory() && entry.name === poolKey)
			) {
				return reply.code(401).send();
			}



			const cert_dir = path.resolve(STORAGE_DIR, poolKey);
			const given_sig = Buffer.from(given, 'base64url');
			const key_pem = await fs.readFile(path.resolve(cert_dir, 'ssl.key')).catch(()=>null);
			if ( !key_pem ) {
				return reply.code(401).send();
			}

			const now_otp = Math.floor(Date.now() / 10000);
			let matched = false;
			try {
				for (const ts of [now_otp, now_otp - 1]) {
					const expected = crypto.createSign('RSA-SHA256')
						.update(JSON.stringify({key:poolKey, ts}))
						.sign({key:key_pem, padding:crypto.constants.RSA_PKCS1_PADDING});
					if ( expected.length === given_sig.length && crypto.timingSafeEqual(expected, given_sig) ) {
						matched = true;
						break;
					}
				}
			}
			catch {
				matched = false;
			}

			if ( !matched ) {
				return reply.code(401).send();
			}
		});

		fastify.get('/ssl/:poolKey/info', async(req, res)=>{
			const {poolKey} = req.params as {poolKey:string;};
			const meta_raw = await fs.readFile(path.resolve(STORAGE_DIR, poolKey, 'meta.json'), 'utf-8');
			const meta = Helper.JSONDecode<SSLMeta>(meta_raw);
			if ( !meta ) return res.code(404).send({
				code: ErrorCode.RESOURCE_NOT_FOUND,
				message: "Invalid SSL meta!"
			});

			const cert = await fs.readFile(path.resolve(STORAGE_DIR, poolKey, 'ssl.crt'), 'utf-8');
			const cert_info = acme.crypto.readCertificateInfo(cert);

			return res.send({
				reqTime: Math.floor(Date.now() / 1000),
				domains: cert_info.domains,
				notAfter: Math.floor(cert_info.notAfter.getTime() / 1000),
				notAfterTS: Helper.ToLocalISOString(cert_info.notAfter),
				notBefore: Math.floor(cert_info.notBefore.getTime() / 1000),
				notBeforeTS: Helper.ToLocalISOString(cert_info.notBefore)
			});
		});

		fastify.get('/ssl/:poolKey/crt', async(req, res)=>{
			const {poolKey} = req.params as {poolKey:string;};

			if ( req.headers['x-proxy-from'] === 'nginx' ) {
				return res.header('X-Accel-Redirect', `/storage/${poolKey}/ssl.crt`).send();
			}

			const crt = await fs.readFile(path.resolve(STORAGE_DIR, poolKey, 'ssl.crt'), 'utf-8');
			return res.header('Content-Type', 'application/x-pem-file').send(crt);
		});

		fastify.get('/ssl/:poolKey/bundle', async(req, res)=>{
			const {poolKey} = req.params as {poolKey:string;};

			if ( req.headers['x-proxy-from'] === 'nginx' ) {
				return res.header('X-Accel-Redirect', `/storage/${poolKey}/bundle.pem`).send();
			}

			const crt = await fs.readFile(path.resolve(STORAGE_DIR, poolKey, 'bundle.pem'), 'utf-8');
			return res.header('Content-Type', 'application/x-pem-file').send(crt);
		});
	});



	const info = await fastify.listen({
		host:process.env.BIND_HOST!,
		port:parseInt(process.env.BIND_PORT!)
	});
	
	LogTool.info(`Server is now listening on ${info}!`);



	const CRON_LOG_DIR = '/var/log/sslmgr';
	let cronTimer:NodeJS.Timeout|undefined;
	let cronProc:child.ChildProcess|undefined;
	ScheduleRefresh();

	ContextCtrl.final(()=>{
		clearTimeout(cronTimer);
		cronProc?.kill();
		fastify.close();
	});



	function ScheduleRefresh() {
		const delay = dayjs().add(1, 'day').startOf('day').diff(dayjs());
		cronTimer = setTimeout(async()=>{
			ScheduleRefresh();

			if ( cronProc ) {
				LogTool.warn('Previous certificate refresh cron is still running! Skipping...');
				return;
			}

			const mkdirResult = await fs.mkdir(CRON_LOG_DIR, {recursive:true}).catch((e:Error)=>e);
			if ( mkdirResult instanceof Error ) {
				LogTool.error('Unable to create cron log directory:', mkdirResult);
				return;
			}

			const logPath = path.join(CRON_LOG_DIR, `refresh-${dayjs().format('YYYY-MM-DD')}.log`);
			const logStream = createWriteStream(logPath, {flags:'a'});
			logStream.write(`===== ${dayjs().format('YYYY-MM-DD HH:mm:ss')} =====\n`);
			LogTool.info(`Running certificate refresh cron, output to ${logPath}...`);

			cronProc = child.spawn('tsx', [path.join(__dirname, 'cron.refresh-certificate.ts')], {
				cwd:__dirname, stdio:['ignore', 'pipe', 'pipe']
			});
			cronProc.stdout!.pipe(logStream, {end:false});
			cronProc.stderr!.pipe(logStream, {end:false});
			cronProc
			.on('error', (e)=>{
				logStream.write(`Error executing cron: ${e.message}\n`);
				LogTool.error('Error executing certificate refresh cron:', e);
			})
			.on('close', (code, signal)=>{
				cronProc = undefined;
				logStream.end(`===== exited with ${code !== null ? `code ${code}` : `signal ${signal}`} =====\n\n`);
				LogTool.info(`Certificate refresh cron finished! (code:${code}, signal:${signal})`);
			});
		}, delay);
	}
});
