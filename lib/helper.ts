export default class Helper {
	static JSONEncode<DataType=any>(data:DataType):string {
		return JSON.stringify(data);
	}
	static JSONDecode<DataType=any>(json:string):DataType|undefined {
		try {
			return JSON.parse(json);
		} catch (e) {
			return undefined;
		}
	}

	static ToLocalISOString(ref_date: Date | string | number | undefined = undefined, show_milli = false): string {
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
	
	static async Idle(milli_seconds: number): Promise<void> {
		return new Promise((res)=>setTimeout(res, milli_seconds||0));
	}
}