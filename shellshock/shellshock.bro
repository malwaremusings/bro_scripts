module Shellshock;

@load active-http2

export {
	redef enum Log::ID += { LOG };

	type ShellshockInfo:record {
		ts:	time	&log;
		uid:	string	&log;
		id:	conn_id	&log;
		target_method:	string	&log;
		target_host:	string	&log;
		target_uri:	string	&log;
		headers:set[string]	&log;
		download_urls:	set[string]	&log;
		download_md5s:	set[string]	&log;
	};
}

redef record connection += {
	shellshock: ShellshockInfo &optional;
};

redef enum HTTP::Tags += {
	ATTACK
};

global shellshock_downloads: table[string] of set[string];


#function md5_file(filename: string): string {
#	local cmd = cat("md5summy -b \"",str_shell_escape(filename),"\"");
#	return when ( local result = Exec::run([$cmd = cmd])) {
#		if (result$exit_code == 0) {
#			local output = split1(result$stdout[0],/ /);
#			return output[1];
#		} else {
#			return "";
#		}
#	}
#}


event http_header(c:connection,is_orig:bool,name:string,value:string) &priority=5 {
	#print fmt("Connection: %s",c$uid);
	#print fmt("[-]   %s: %s",name,value);
	if (/\(\) \{[ 	][^\}]*;[ 	]*\}[ 	]*;/ in value) {
		print fmt("--- Shellshock ---");

		if (!c?$shellshock) {
			local ss:ShellshockInfo;

			c$shellshock = ss;
		}

		if (ATTACK ! in c$http$tags) {
			add c$http$tags[ATTACK];
		}

		add c$shellshock$headers[fmt("%s: %s",name,value)];

		local dlcmds = find_all(value,/(wget|curl|lwp-download)( |( [^;\"]* ))(((https?|ftp):\/\/)?([0-9A-Za-z]+\.){2,}[0-9A-Za-z]+(\/[^ ;\\\"]*)*)/);
		local urls:set[string];
		for (cmd in dlcmds) {
			local url = sub(cmd,/(wget|curl|lwp-download)( |( [^;\"]* ))/,"");
			print fmt("   url: %s",url);
			add urls[url];
		}

		for (url in urls) {
			add c$shellshock$download_urls[url];
			local req:ActiveHTTP2::Request;
			req$url = url;
			req$method = "GET";
			#req$addl_curl_args = "-w \"%{filename_effective} %{local_ip} %{local_port} %{remote_ip} %{remote_port} %{url_effective} %{http_code} %{content_type}\"";

			#local rsp:ActiveHTTP2::Response;
			#local dlfilename = cat("shellshock_downloads/",c$uid);
			print "before when";
			when (local rsp = ActiveHTTP2::request(req,c$uid)) {
				print "--- rsp ---";
				print rsp;
				#when (local md5hash = md5_file(dlfilename)) {
				#	print "--- md5hash ---";
				#	print md5hash;
				#	add c$shellshock$download_md5s[md5hash];

				#	c$shellshock$ts = network_time();
				#	c$shellshock$uid = c$uid;
				#	c$shellshock$id = c$id;
				#	if (c$http?$method) {
				#		c$shellshock$target_method = c$http$method;
				#	}
				#	if (c$http?$host) {
				#		c$shellshock$target_host = c$http$host;
				#	}
				#	if (c$http?$uri) {
				#		c$shellshock$target_uri = c$http$uri;
				#	}
				#	Log::write(Shellshock::LOG,c$shellshock);
				#}
				print "--- m ---";
				print c$shellshock;
			}
			print "after when";
		}
	}
}

event file_hash(f: fa_file,kind: string,hash: string) {
	print fmt("> file_hash(%s,%s,%s)",f$source,kind,hash);
}

event file_new(f: fa_file) {
	print "--- file_new() ---";
	#print f;
	#if (f?$conns) {
	#	for (c in f$conns) {
	#		print c;
	#	}
	#} else {
	#	print "No connection information";
	#}
	Files::add_analyzer(f, Files::ANALYZER_MD5);
	Files::add_analyzer(f, Files::ANALYZER_EXTRACT,[$extract_filename=f$id]);
}

#event file_over_new_connection(f:fa_file,c:connection,is_orig:bool) {
#	for (fc in f$conns) {
#		print fc,f$conns[fc]$uid;
#	}
#	local fname = fmt("%s-%s", f$source, f$id);
#
#	Files::add_analyzer(f,Files::ANALYZER_EXTRACT,[$extract_filename=fname]);
#}

event bro_init() {
	Log::create_stream(LOG, [$columns=ShellshockInfo]);
	mkdir("shellshock_downloads");
}
