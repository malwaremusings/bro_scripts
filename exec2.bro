##! A module for executing external command line programs.

@load base/frameworks/input

module Exec2;

export {
	type Command: record {
		## The command line to execute.  Use care to avoid injection
		## attacks (i.e., if the command uses untrusted/variable data,
		## sanitize it with :bro:see:`str_shell_escape`).
		cmd:         string;
		## Provide standard input to the program as a string.
		stdin:       string      &default="";
		## If additional files are required to be read in as part of the
		## output of the command they can be defined here.
		read_files:  set[string] &optional;
		## If additional files are required to be analysed
		## they can be defined here.
		analyse_files:	set[string] &optional;
		## The unique id for tracking executors.
		uid: string &default=unique_id("");
	};

	type Result: record {
		## Exit code from the program.
		exit_code:    count            &default=0;
		## True if the command was terminated with a signal.
		signal_exit:  bool             &default=F;
		## Each line of standard output.
		stdout:       vector of string &optional;
		## Each line of standard error.
		stderr:       vector of string &optional;
		## If additional files were requested to be read in
		## the content of the files will be available here.
		files:        table[string] of string_vec &optional;
	};

	## Function for running command line programs and getting
	## output.  This is an asynchronous function which is meant
	## to be run with the `when` statement.
	##
	## cmd: The command to run.  Use care to avoid injection attacks!
	##
	## Returns: A record representing the full results from the
	##          external program execution.
	global run: function(cmd: Command): Result;

	## The system directory for temporary files.
	const tmp_dir = "/tmp" &redef;
}

# Indexed by command uid.
global results: table[string] of Result;
global pending_commands: set[string];
global pending_files: table[string] of set[string];
global analyse_files: table[string] of set[string];

type OneLine: record {
	s: string;
	is_stderr: bool;
};

type FileLine: record {
	s: string;
};

event Exec2::line(description: Input::EventDescription, tpe: Input::Event, s: string, is_stderr: bool)
	{
	local result = results[description$name];
	if ( is_stderr )
		{
		if ( ! result?$stderr )
			result$stderr = vector(s);
		else
			result$stderr[|result$stderr|] = s;
		}
	else
		{
		if ( ! result?$stdout )
			result$stdout = vector(s);
		else
			result$stdout[|result$stdout|] = s;
		}
	}

event Exec2::file_line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	print fmt("> Exec2::file_line(%s): %s",description$name,s);
	local parts = split1(description$name, /_/);
	local name = parts[1];
	local track_file = parts[2];

	local result = results[name];
	if ( ! result?$files )
		result$files = table();

	if ( track_file !in result$files )
		result$files[track_file] = vector(s);
	else
		result$files[track_file][|result$files[track_file]|] = s;
	print fmt("< Exec2::file_line(%s): %s",description$name,s);
	}

event Input::end_of_data(name: string, source:string)
	{
	print fmt("> Exec2::end_of_data(%s,%s)",name,source);
	local parts = split1(name, /_/);
	name = parts[1];

	print fmt("    name in pending_commands: %d",name in pending_commands);
	print fmt("    |parts|: %d",|parts|);
	if ( name !in pending_commands || |parts| < 2 ) {
		return;
	}

	local track_file = parts[2];

	Input::remove(name);

	if ( name !in pending_files ) {
		print fmt("    removing pending_commands[%s]",name);
		delete pending_commands[name];
		}
	else
		{
		print fmt("    removing pending_files[%s][%s]",name,track_file);
		delete pending_files[name][track_file];
		if ( |pending_files[name]| == 0 )
			print fmt("        removing pending_commands[%s]",name);
			delete pending_commands[name];
		system(fmt("rm \"%s\"", str_shell_escape(track_file)));
		}
	print fmt("< Exec2::end_of_data(%s,%s)",name,source);
	}

event InputRaw::process_finished(name: string, source:string, exit_code:count, signal_exit:bool)
	{
	print fmt("> process_finished(%s,%s,%d,%d)",name,source,exit_code,signal_exit);
	if ( name !in pending_commands )
		return;

	Input::remove(name);
	results[name]$exit_code = exit_code;
	results[name]$signal_exit = signal_exit;

	local reading_done = F;
	if ( name in pending_files && |pending_files[name]| > 0 ) {
		for ( read_file in pending_files[name] ) {
			print fmt("Exec2::process_finished(%s) creating event (%s) to read file %s",name,fmt("%s_%s",name,read_file),read_file);
			Input::add_event([$source=fmt("%s", read_file),
			                  $name=fmt("%s_%s", name, read_file),
			                  $reader=Input::READER_RAW,
			                  $want_record=F,
			                  $fields=FileLine,
			                  $ev=Exec2::file_line]);
		}
	} else {
		reading_done = T;
	}

	local analysis_done = F;
	if ( name in analyse_files && |analyse_files[name]| > 0) {
		for ( analyse_file in analyse_files[name] ) {
			print fmt("Adding analysis for %s",analyse_file);
			Input::add_analysis([$source=fmt("%s", analyse_file),
			                  $name=fmt("%s", analyse_file)]);
		}
	} else {
		analysis_done = T;
	}

	print fmt("Exec2::process_finished() reading_done = %d	analysis_done = %d",reading_done,analysis_done);
	if (!reading_done) {
		for (f in pending_files[name]) {
			print fmt("  f: %s",f);
		}
	}
	if (reading_done && analysis_done) {
		# No extra files to read, nor files to analyse, command is done.
		print fmt("Exec2::process_finished() deleting %s from pending_commands",name);
		delete pending_commands[name];
	}
	print fmt("< process_finished(%s,%s,%d,%d)",name,source,exit_code,signal_exit);
	}

function run(cmd: Command): Result
	{
	print fmt("> Exec2::run(%s)",cmd$uid);
	add pending_commands[cmd$uid];
	results[cmd$uid] = [];

	if ( cmd?$read_files )
		{
		for ( read_file in cmd$read_files )
			{
			if ( cmd$uid !in pending_files )
				pending_files[cmd$uid] = set();
			add pending_files[cmd$uid][read_file];
			}
		}

	if ( cmd?$analyse_files ) {
		for ( analyse_file in cmd$analyse_files ) {
			if ( cmd$uid !in analyse_files ) {
				analyse_files[cmd$uid] = set();
			}
			add analyse_files[cmd$uid][analyse_file];
		}
	}

	local config_strings: table[string] of string = {
		["stdin"]       = cmd$stdin,
		["read_stderr"] = "1",
	};
	print fmt("    Creating event: %s",cmd$uid);
	Input::add_event([$name=cmd$uid,
	                  $source=fmt("%s |", cmd$cmd),
	                  $reader=Input::READER_RAW,
	                  $mode=Input::STREAM,
	                  $fields=Exec2::OneLine,
	                  $ev=Exec2::line,
	                  $want_record=F,
	                  $config=config_strings]);

	print "waiting in Exec2::run()";
	return when ( cmd$uid !in pending_commands )
		{
		print "when cmd$uid !in pending_commands";
		local result = results[cmd$uid];
		delete results[cmd$uid];
		return result;
		}
	}

event bro_done()
	{
	# We are punting here and just deleting any unprocessed files.
	for ( uid in pending_files )
		for ( fname in pending_files[uid] )
			system(fmt("rm \"%s\"", str_shell_escape(fname)));
	}
