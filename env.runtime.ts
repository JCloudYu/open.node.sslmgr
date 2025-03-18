import crypto from "node:crypto";
const SESSION_ID = crypto.randomBytes(10);
let SEQ:number = 0;


type CodedError = Error & {code?:string;}
interface LogStreamMetaInfo {
	time_milli:boolean; tags:string[]
};
interface LogInfoType {
	t: string;
	l:'debg'|'info'|'warn'|'eror'|'fatl';
	b: number;
	p: {
		tags:string[], ctnt:any|CodedError
	}
}
interface LogWriter {(msg:LogInfoType):void};


const LoggerRuntime:{writer:LogWriter} = { writer:(m)=>console.log(JSON.stringify(m)) };
const LogStreamMeta:WeakMap<LogStream, LogStreamMetaInfo> = new WeakMap();
class LogStream {
	constructor() {
		LogStreamMeta.set(this, {
			time_milli:false,
			tags: []
		});
	}

	get time_milli() { return LogStreamMeta.get(this)!.time_milli; }
	set time_milli(show_milli) { LogStreamMeta.get(this)!.time_milli = !!show_milli; }
	get tags() { return LogStreamMeta.get(this)!.tags; }

	clone() {
		const new_stream = new LogStream();
		Object.assign(LogStreamMeta.get(new_stream)!, CloneMeta(LogStreamMeta.get(this)!));
		return new_stream;
	}
	debug(...contents:any[]) {
		const curr_meta = LogStreamMeta.get(this)!;
		const log_time = ToLocalISOString(curr_meta.time_milli);
		const batch = fnv1a32(Buffer.concat([SESSION_ID, Buffer.from(log_time), Buffer.from((new Uint32Array([SEQ = (SEQ+1)%0xFFFFFFFF])).buffer)]));
		for(const content of contents) {
			Log({t:log_time, l:'debg', b:batch, p:{tags:curr_meta.tags, ctnt:content}});
		}
	}
	info(...contents:any[]) {
		const curr_meta = LogStreamMeta.get(this)!;
		const log_time = ToLocalISOString(curr_meta.time_milli);
		const batch = fnv1a32(Buffer.concat([SESSION_ID, Buffer.from(log_time), Buffer.from((new Uint32Array([SEQ = (SEQ+1)%0xFFFFFFFF])).buffer)]));
		for(const content of contents) {
			Log({t:log_time, l:'info', b:batch, p:{tags:curr_meta.tags, ctnt:content}});
		}
	}
	warn(...contents:any[]) {
		const curr_meta = LogStreamMeta.get(this)!;
		const log_time = ToLocalISOString(curr_meta.time_milli);
		const batch = fnv1a32(Buffer.concat([SESSION_ID, Buffer.from(log_time), Buffer.from((new Uint32Array([SEQ = (SEQ+1)%0xFFFFFFFF])).buffer)]));
		for(const content of contents) {
			Log({t:log_time, l:'warn', b:batch, p:{tags:curr_meta.tags, ctnt:content}});
		}
	}
	error(...contents:any[]) {
		const curr_meta = LogStreamMeta.get(this)!;
		const log_time = ToLocalISOString(curr_meta.time_milli);
		const batch = fnv1a32(Buffer.concat([SESSION_ID, Buffer.from(log_time), Buffer.from((new Uint32Array([SEQ = (SEQ+1)%0xFFFFFFFF])).buffer)]));
		for(const content of contents) {
			Log({t:log_time, l:'eror', b:batch, p:{tags:curr_meta.tags, ctnt:content}});
		}
	}
	fatal(...contents:any[]) {
		const curr_meta = LogStreamMeta.get(this)!;
		const log_time = ToLocalISOString(curr_meta.time_milli);
		const batch = fnv1a32(Buffer.concat([SESSION_ID, Buffer.from(log_time), Buffer.from((new Uint32Array([SEQ = (SEQ+1)%0xFFFFFFFF])).buffer)]));
		for(const content of contents) {
			Log({t:log_time, l:'fatl', b:batch, p:{tags:curr_meta.tags, ctnt:content}});
		}
	}
}

function CloneMeta(meta:LogStreamMetaInfo):LogStreamMetaInfo {
	const {tags, ...new_meta} = meta;
	return Object.assign(new_meta, {tags:tags.slice(0)});
}

function Log(payload:LogInfoType) {
	if ( payload.p.ctnt instanceof Error ) {
		const error_info = payload.p.ctnt as CodedError;
		payload.p.ctnt = Object.assign({
			type: 'error', subtype:error_info.name,
			code: error_info.code,
			message: error_info.message,
			stack: error_info.stack!.split("\n").map((i)=>i.trim())
		}, error_info);
	}

	switch(payload.l) {
		case "debg":
		case "info":
		case "warn":
		case "eror":
		case "fatl":
			LoggerRuntime.writer(payload);
			break;
		default:
			throw new SyntaxError("Given log's level is invalid!");
	}
}

export const LogTool = Object.defineProperties(new LogStream(), {
	__writer:{
		configurable:true, enumerable:true,
		set:(writer:LogWriter)=>{
			if ( typeof writer !== "function" ) {
				throw new TypeError("__writer accepts only functions");
			}

			LoggerRuntime.writer = writer;
		},
		get:()=>LoggerRuntime.writer
	}
}) as LogStream&{__writer:LogWriter};



function ToLocalISOString(show_milli?:boolean):string;
function ToLocalISOString(ref_date:Date|string|number, show_milli?:boolean):string;
function ToLocalISOString(this:Date, ref_date?:Date|string|number, show_milli?:boolean):string;
function ToLocalISOString(this:Date, ref_date?:Date|string|number|boolean, show_milli?:boolean):string {
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



const FNV_PRIME_HIGH = 0x0100, FNV_PRIME_LOW = 0x0193;	// 16777619 0x01000193
const OFFSET_BASIS = new Uint8Array([0xC5, 0x9D, 0x1C, 0x81]);	// 2166136261 [0x81, 0x1C, 0x9D, 0xC5]
function fnv1a32(octets:Uint8Array) {
	const U8RESULT		= OFFSET_BASIS.slice(0);
	const U32RESULT		= new Uint32Array(U8RESULT.buffer);
	const RESULT_PROC	= new Uint16Array(U8RESULT.buffer);
	for( let i = 0; i < octets.length; i += 1 ) {
		U32RESULT[0] = U32RESULT[0] ^ octets[i];
		
		let hash_low = RESULT_PROC[0], hash_high = RESULT_PROC[1];
		
		RESULT_PROC[0] = hash_low * FNV_PRIME_LOW;
		RESULT_PROC[1] = hash_low * FNV_PRIME_HIGH + hash_high * FNV_PRIME_LOW + (RESULT_PROC[0]>>>16);
	}
	return U32RESULT[0];
}






// TermCtrl
type TerminateStages = 'terminate:init'|'terminate:preproc'|'terminate:predata'|'terminate:data'|'terminate:postproc'|'terminate:final';
declare global {
	namespace NodeJS {
		interface Process {
			emit(evt:'terminate', error?:CodedError|NodeJS.Signals):this;
			emit(evt:TerminateStages):this;

			on(evt:'terminate', handler:(error?:CodedError|NodeJS.Signals)=>void):this;
			on(evt:TerminateStages, handler:()=>void):this;

			once(evt:'terminate', handler:(error?:CodedError|NodeJS.Signals)=>void):this;
			once(evt:TerminateStages, handler:()=>void):this;
		}
	}
}

interface CallbackFunc {():Promise<void>|void};
const cleanup_stages :{[key in 'preproc'|'predata'|'data'|'postproc'|'final']:CallbackFunc[]}= { preproc:[], predata:[], data:[], postproc:[], final:[] };

export class ContextCtrl {
	static timeout:number = 30_000;
	static preproc(cb:CallbackFunc){
		cleanup_stages.preproc.push(cb);
	}
	static predata(cb:CallbackFunc){
		cleanup_stages.predata.push(cb);
	}
	static data(cb:CallbackFunc) {
		cleanup_stages.data.push(cb);
	}
	static postproc(cb:CallbackFunc){
		cleanup_stages.postproc.push(cb);
	}
	static final(cb:CallbackFunc) {
		cleanup_stages.final.push(cb);
	}
}

process.once('terminate', async(state)=>{
	process.emit('terminate:init');
	let timeout = setTimeout(()=>{
		console.error("Termination timeout!");
		process.exit(1);
	}, ContextCtrl.timeout);


	
	for(const stage of (['preproc', 'predata', 'data', 'postproc', 'final'] as const)) {
		process.emit(`terminate:${stage}`);
		const handlers = cleanup_stages[stage].filter((i)=>typeof i === "function");
		await Promise.all(handlers.map((i)=>i()));
	}


	clearTimeout(timeout);
	if ( state === undefined ) {
		process.exit(0);
	}

	if ( typeof state === "string" ) {
		let exit_code = 1;
		
		switch(state) {
			case 'SIGHUP':
				exit_code = 128 + 1;
				break;
			case 'SIGINT':
				exit_code = 128 + 2;
				break;
			case 'SIGQUIT':
				exit_code = 128 + 3;
				break;
			case 'SIGILL':
				exit_code = 128 + 4;
				break;
			case 'SIGTRAP':
				exit_code = 128 + 5;
				break;
			case 'SIGABRT':
			case 'SIGIOT':
				exit_code = 128 + 6;
				break;
			case 'SIGBUS':
				exit_code = 128 + 7;
				break;
			case 'SIGFPE':
				exit_code = 128 + 8;
				break;
			case 'SIGKILL':
				exit_code = 128 + 9;
				break;
			case 'SIGUSR1':
				exit_code = 128 + 10;
				break;
			case 'SIGSEGV':
				exit_code = 128 + 11;
				break;
			case 'SIGUSR2':
				exit_code = 128 + 12;
				break;
			case 'SIGPIPE':
				exit_code = 128 + 13;
				break;
			case 'SIGALRM':
				exit_code = 128 + 14;
				break;
			case 'SIGTERM':
				exit_code = 128 + 15;
				break;
			case 'SIGSTKFLT':
				exit_code = 128 + 16;
				break;
			case 'SIGCHLD':
				exit_code = 128 + 17;
				break;
			case 'SIGCONT':
				exit_code = 128 + 18;
				break;
			case 'SIGSTOP':
				exit_code = 128 + 19;
				break;
			case 'SIGTSTP':
				exit_code = 128 + 20;
				break;
			case 'SIGTTIN':
				exit_code = 128 + 21;
				break;
			case 'SIGTTOU':
				exit_code = 128 + 22;
				break;
			case 'SIGURG':
				exit_code = 128 + 23;
				break;
			case 'SIGXCPU':
				exit_code = 128 + 24;
				break;
			case 'SIGXFSZ':
				exit_code = 128 + 25;
				break;
			case 'SIGVTALRM':
				exit_code = 128 + 26;
				break;
			case 'SIGPROF':
				exit_code = 128 + 27;
				break;
			case 'SIGWINCH':
				exit_code = 128 + 28;
				break;
			case 'SIGIO':
			case 'SIGPOLL':
				exit_code = 128 + 29;
				break;
			case 'SIGPWR':
				exit_code = 128 + 30;
				break;
			case 'SIGSYS':
			case 'SIGUNUSED':
				exit_code = 128 + 31;
				break;
			default:
				exit_code = 1;
				break;
		}

		process.exit(exit_code);
	}
	
	if ( state instanceof Error ) {
		process.exit(1);
	}
});


export const Misc = Object.freeze({
	ToLocalISOString
});