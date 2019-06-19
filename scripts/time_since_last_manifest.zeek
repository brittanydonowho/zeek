module Manifest;

export {
	redef enum Log::ID += { LOG, LOG_SEEN };
	type Info: record {
		ts: time &log;
		port_a: port &log &optional;
		port_b: port &log &optional;
		payload: string &log;
	};
}

event zeek_init() {
	Log::create_stream(LOG, [$columns=Info, $path="manifest"]);
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
	print fmt("Request seen from %s:%d to %s:%d: %s %s - version %s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, method, original_URI, version);
}

event http_reply(c: connection, version: string, code: count, reason: string) {
	print fmt("Reply seen from %s:%d to %s:%d: %s - %d - %s", c$id$resp_h, c$id$resp_p, c$id$orig_h, c$id$orig_p, version, code, reason);
}

#event http_entity_data(c: connection, is_orig: bool, length: count, data: string) {
#	local id : string;
#	if (is_orig) {
#		id = fmt("from %s:%d to %s:%d", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
#	} else {
#		id = fmt("from %s:%d to %s:%d", c$id$resp_h, c$id$resp_p, c$id$orig_h, c$id$orig_p);
#	}
#	print fmt("Data seen %s: %s (length %d)", id, sha256_hash(data), length);
#}

event http_event(c: connection, event_type: string, detail: string) {
	print fmt("Error in http event %s - %s", event_type, detail);
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) {
	if (strstr(payload, "GET") == 1 && strstr(payload, ".mpd") > 0) {
		Log::write(Manifest::LOG, [$ts=c$start_time, $port_a=c$id$orig_p, $port_b=c$id$resp_p, $payload=payload]);
	}
}