import "extes";
import Fastify from "fastify";
import dotenv from "dotenv";
import path from "path";
import * as acme from 'acme-client';
import fs from "fs/promises";
import Database from "better-sqlite3";

import Helper from "@/lib/helper.js";
import {LogTool, ContextCtrl} from "@/env.runtime.js";
import BWT from "@/lib/bwt.js";
import {ErrorCode} from "@/lib/error-code.js";




dotenv.config({path:['.env', '.env.local', '.env.prod'], override:true});
const SSL_POOL_DIR = path.resolve(__dirname, process.env.SSL_POOL_DIR||'./pool');

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


	await import('@/script.init-db.js').then(({initDb})=>initDb());


	// Connect to database
	const SESSION_DB_PATH = path.resolve(__dirname, process.env.SQLITE_PATH||'./db.sqlite3');
	const SessionDB = new Database(SESSION_DB_PATH);

	
	const fastify = Fastify()
	.addHook('onRequest', async(req)=>{
		req.time = Math.floor((req.time_milli = Date.now())/1000);
		req.session = {
			valid:false
		};
	})
	.addHook('onRequest', async(req)=>{
		const [type, token] = (req.headers['authorization']||'').split(' ').map((i)=>i.trim()).filter((i)=>i!=='');
		if ( (type||'').lowerCase !== "bearer" ) return;
		const content = BWT.decode<AuthSession>(token||'');
		if ( !content ) return;
		if ( req.time < content.nbf ) return;
		if ( content.exp > 0 && req.time > content.exp ) return;



		const stmt = SessionDB.prepare<[string], {valid:number; expired:epoch;}>(
			"SELECT valid, expired FROM sessions WHERE key = ? LIMIT 1;"
		);
		const session = stmt.get(content.jti);
		if ( !session || !session.valid ) return;



		Object.assign(req.session, {
			valid:true, info:content, expired:session.expired
		});
	})
	.register(async(fastify)=>{
		fastify.addHook('onRequest', async(req, reply)=>{
			if ( !req.session.valid ) {
				return reply.code(401).send({
					code: ErrorCode.UNAUTHORIZED_ACCESS,
					message: "Your not authorized to access this api!"
				});
			}
		});

		fastify.get('/ssl', async(req, res)=>{
			const {did} = req.session.info!;

			const meta = await ReadMeta(did);
			if ( !meta ) return res.code(404).send({
				code: ErrorCode.RESOURCE_NOT_FOUND,
				message: "Invalid SSL meta!"
			});

			const cert = await fs.readFile(path.resolve(SSL_POOL_DIR, did, 'ssl.crt'), 'utf-8');
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

		fastify.get('/ssl/key', async(req, res)=>{
			const {did} = req.session.info!;

			if ( req.headers['x-proxy-from'] === 'nginx' ) {
				return res.header('X-Accel-Redirect', `/pool/${did}/ssl.key`).send();
			}

			const key = await fs.readFile(path.resolve(SSL_POOL_DIR, did, 'ssl.key'), 'utf-8');
			return res.header('Content-Type', 'application/x-pem-file').send(key);
		});

		fastify.get('/ssl/crt', async(req, res)=>{
			const {did} = req.session.info!;

			if ( req.headers['x-proxy-from'] === 'nginx' ) {
				return res.header('X-Accel-Redirect', `/pool/${did}/ssl.crt`).send();
			}

			const crt = await fs.readFile(path.resolve(SSL_POOL_DIR, did, 'ssl.crt'), 'utf-8');
			return res.header('Content-Type', 'application/x-pem-file').send(crt);
		});

		fastify.get('/ssl/bundle', async(req, res)=>{
			const {did} = req.session.info!;

			if ( req.headers['x-proxy-from'] === 'nginx' ) {
				return res.header('X-Accel-Redirect', `/pool/${did}/bundle.pem`).send();
			}

			const crt = await fs.readFile(path.resolve(SSL_POOL_DIR, did, 'bundle.pem'), 'utf-8');
			return res.header('Content-Type', 'application/x-pem-file').send(crt);
		});
	});

	async function ReadMeta(did:string):Promise<SSLMeta|null> {
		const META_DIR = path.resolve(SSL_POOL_DIR, did);

		const meta = await fs.readFile(`${META_DIR}/meta.json`, 'utf-8');
		const ssl_meta = Helper.JSONDecode<SSLMeta>(meta);
		if ( !ssl_meta ) return null;

		return ssl_meta;
	}



	const info = await fastify.listen({
		host:process.env.BIND_HOST!,
		port:parseInt(process.env.BIND_PORT!)
	});
	LogTool.info(`Server is now listening on ${info}!`);
	ContextCtrl.final(()=>{
		SessionDB.close();
		fastify.close();
	});
});