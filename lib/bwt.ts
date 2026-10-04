import crypto from "node:crypto";
import beson from "beson";



const SIG_LEN = 32, SALT_LEN = 8;
const B32Format = /^[0123456789abcdefghijklmnopqrstuv]+$/;
const MAP:string[] = '0123456789abcdefghijklmnopqrstuv'.split('');
const RMAP:{[k:string]:number} = Object.fromEntries(MAP.map((key, val)=>[key, val]));

export default class BWT {
	static encode<DataType=AnyObject>(data:DataType, secret:Buffer):string {
		const raw_data = beson.Serialize(data);
		const salt = crypto.randomBytes(5);
		const signature = crypto.createHmac("sha1", secret).update(raw_data).update(salt).digest();
		return Base32Hex.encode(salt) + Base32Hex.encode(signature) + Base32Hex.encode(raw_data);
	}
	static decode<DataType=AnyObject>(data_str:string):DataType|null;
	static decode<DataType=AnyObject>(data_str:string, secret:Buffer):DataType|false|null;
	static decode<DataType=AnyObject>(data_str:string, secret?:Buffer):DataType|false|null {
		if ( data_str.length <= SIG_LEN ) return null;

		const salt		= Base32Hex.decode(data_str.substring(0, SALT_LEN));
		const input_sig	= Base32Hex.decode(data_str.substring(SALT_LEN, SALT_LEN+SIG_LEN));
		const raw_data	= Base32Hex.decode(data_str.substring(SALT_LEN+SIG_LEN));
		if ( !raw_data || !salt || !input_sig ) return null;

		const data = beson.Deserialize(raw_data);
		if ( !data ) return null;

		
		if ( secret ) {
			const signature = crypto.createHmac("sha1", secret).update(raw_data).update(salt).digest();
			if ( Buffer.compare(signature, input_sig) ) return false;
		}
		
		return data;
	}
}



export class Base32Hex {
	static encode(data:Uint8Array):string {
		if ( data.length < 1 ) return '';
		
		// Run complete bundles
		let encoded = '';
		let begin, loop = Math.floor(data.length/5);
		for (let run=0; run<loop; run++) {
			begin = run * 5;
			encoded += MAP[  data[begin]           >> 3];							// 0
			encoded += MAP[ (data[begin  ] & 0x07) << 2 | (data[begin+1] >> 6)];	// 1
			encoded += MAP[ (data[begin+1] & 0x3E) >> 1];							// 2
			encoded += MAP[ (data[begin+1] & 0x01) << 4 | (data[begin+2] >> 4)];	// 3
			encoded += MAP[ (data[begin+2] & 0x0F) << 1 | (data[begin+3] >> 7)];	// 4
			encoded += MAP[ (data[begin+3] & 0x7C) >> 2];							// 5
			encoded += MAP[ (data[begin+3] & 0x03) << 3 | (data[begin+4] >> 5)];	// 6
			encoded += MAP[  data[begin+4] & 0x1F];									// 7
		}
		
		// Run remains
		let remain = data.length % 5;
		if ( remain === 0 ) { return encoded; }
		
		
		begin = loop*5;
		if ( remain === 1 ) {
			encoded += MAP[  data[begin]           >> 3];								// 0
			encoded += MAP[ (data[begin  ] & 0x07) << 2];								// 1
		}
		else
		if ( remain === 2 ) {
			encoded += MAP[  data[begin]           >> 3];								// 0
			encoded += MAP[ (data[begin  ] & 0x07) << 2 | (data[begin+1] >> 6)];		// 1
			encoded += MAP[ (data[begin+1] & 0x3E) >> 1];								// 2
			encoded += MAP[ (data[begin+1] & 0x01) << 4];								// 3
		}
		else
		if ( remain === 3 ) {
			encoded += MAP[  data[begin]           >> 3];								// 0
			encoded += MAP[ (data[begin  ] & 0x07) << 2 | (data[begin+1] >> 6)];		// 1
			encoded += MAP[ (data[begin+1] & 0x3E) >> 1];								// 2
			encoded += MAP[ (data[begin+1] & 0x01) << 4 | (data[begin+2] >> 4)];		// 3
			encoded += MAP[ (data[begin+2] & 0x0F) << 1];								// 4
		}
		else
		if ( remain === 4 ) {
			encoded += MAP[  data[begin]           >> 3];								// 0
			encoded += MAP[ (data[begin  ] & 0x07) << 2 | (data[begin+1] >> 6)];		// 1
			encoded += MAP[ (data[begin+1] & 0x3E) >> 1];								// 2
			encoded += MAP[ (data[begin+1] & 0x01) << 4 | (data[begin+2] >> 4)];		// 3
			encoded += MAP[ (data[begin+2] & 0x0F) << 1 | (data[begin+3] >> 7)];		// 4
			encoded += MAP[ (data[begin+3] & 0x7C) >> 2];								// 5
			encoded += MAP[ (data[begin+3] & 0x03) << 3];								// 6
		}
		
		return encoded;
	}
	static decode(data:string):Uint8Array|null {
		if ( !B32Format.test(data) ) return null;
		
		let remain = data.length % 8;
		if ( [0, 2, 4, 5, 7].indexOf(remain) < 0 ) return null;
	
	
		
		const decoded = new Uint8Array(Math.floor(data.length * 5 / 8));
		data = data.toLowerCase();
		
	
		// Run complete bundles
		let dest, begin, loop = Math.floor(data.length/8);
		for (let run=0; run<loop; run++) {
			begin = run * 8;
			dest  = run * 5;
			decoded[dest] 	=  RMAP[data[begin]] << 3 | RMAP[data[begin+1]] >> 2;	// 0
			decoded[dest+1] = (RMAP[data[begin+1]] & 0x03) << 6 |								// 1
							   RMAP[data[begin+2]]		   << 1 |
							   RMAP[data[begin+3]]		   >> 4;
			decoded[dest+2] = (RMAP[data[begin+3]] & 0x0F) << 4 |								// 2
							   RMAP[data[begin+4]]		   >> 1;
			decoded[dest+3] = (RMAP[data[begin+4]] & 0x01) << 7 |								// 3
							   RMAP[data[begin+5]]		   << 2 |
							   RMAP[data[begin+6]]		   >> 3;
			decoded[dest+4] = (RMAP[data[begin+6]] & 0x07) << 5 |								// 4
							   RMAP[data[begin+7]];
		}
		
		if ( remain === 0 ) { return decoded; }
		
		
		
		begin = loop*8;
		dest  = loop*5;
		if ( remain >= 2 ) {
			decoded[dest] =  RMAP[data[begin]] << 3 | RMAP[data[begin+1]] >> 2;		// 0
		}
		
		if ( remain >= 4 ) {
			decoded[dest+1] = (RMAP[data[begin+1]] & 0x03) << 6 |								// 1
							   RMAP[data[begin+2]]		   << 1 |
							   RMAP[data[begin+3]]		   >> 4;
		}
		
		if ( remain >= 5 ) {
			decoded[dest+2] = (RMAP[data[begin+3]] & 0x0F) << 4 |								// 2
							   RMAP[data[begin+4]]		   >> 1;
		}
		
		if ( remain === 7 ) {
			decoded[dest+3] = (RMAP[data[begin+4]] & 0x01) << 7 |								// 3
							   RMAP[data[begin+5]]		   << 2 |
							   RMAP[data[begin+6]]		   >> 3;
		}
		
		return decoded;
	}
}