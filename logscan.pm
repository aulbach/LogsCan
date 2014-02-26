#!/usr/bin/perl -w
#
# Logscan
#
# 2009-2014 Alex Aulbach
#
# Bugs:
#  No check if the logfile was truncated...
#
# TODO:
# - option for the position (and many other config via options)
# - read from pipe
# - create position-file automatically
# 


#use Data::Dumper; # helper for debugging

###############################################
# printLog
# prints the line with sprint( config{logline}  ...
# know three channels "OUT", "MATCH" and "ERR"
#
$outline=0;
$matchline=0;
$errline=0;
sub printLog(@)
{
	my ($text, $file) = @_;
	my $str = sprintf( $config{logline}, scalar(localtime(time)), $text );
	$str =~ s/\\n/\n/g;
	if ( $file eq 'OUT' ) {
		printf STDOUT $str, $outline;
		$outline += 1;
	} elsif ( $file eq 'MATCH' ) {
		printf MATCHOUT $str, $matchline;
		$matchline += 1;
	} else {
		printf STDERR $str, $errline;
		$errline += 1;
	}
}


##############################################
# sendScanMail
# Sends a mail with the found matches to configured mailaddr.
#
sub sendScanMail
{
	my ( $rule, $body, $bodycnt ) = @_;
	my $sendto = $scanruls->{$rule}->{'email'};
	my $messg  = $scanruls->{$rule}->{'messg'};
	my $subject = sprintf($config{sendmail_subject}, $rule, $config{logfile});
	open (SENDMAIL,"|$config{sendmail} -t -f $config{sendmail_from}") || die("sendmail misconfiguration ($!)\n");
	print SENDMAIL <<EOF;
To: $sendto
Subject: $subject
From: $config{sendmail_from}
Content-Type: text/plain; charset="iso-8859-1"
Content-Transfer-Encoding: 8bit

Rule   : '$rule' ($messg)
File   : '$config{logfile}'
Start  : $position   End: $lastpos / $currentpos
Matches: $bodycnt

Here are the found parts of this scan:

-------------------------------------------------
$body
-------------------------------------------------
EOF

	close SENDMAIL;

}


####################################################################
# parse_config
# scans the configuration-file.
# and returns two variables, one with global config and one with scanrules
#
# idea taken form here:
# http://www.patshaping.de/hilfen_ta/codeschnipsel/perl-configparser.htm
sub parse_config($)
{
	my $file = shift;
	local *CF;

	open(CF,'<'.$file) or die "cannot open '$file' ($!)\n";
	read(CF, my $data, -s $file);
	close(CF);


	# carrige-return or only return or only carrige
	my @lines  = split(/\015\012|\012|\015/,$data);
	my $config = {};
	my $scanruls = {};
	my $mode = 'global';
	my $scanrule = '';
	my $count  = 0;
	my $key;
	my $value;

	# this is a nice parser: 3 modes, 2 jumps
	foreach my $line(@lines)
	{
		$count++;
		
		# jump over comments
		next if($line =~ /^\s*#/);

		# lure for [SCANRULES]
		if ( $mode eq 'global' and $line =~ /^\[SCANRULES]/i ) {
			$mode = 'waitscanruls';
			next;
		}
		# lure for <RULES> and remember new rule
		elsif ( ( $mode eq 'waitscanruls' or $mode eq 'inscanruls' ) and $line =~ /^<(\w+)>/ ) {
			$mode = 'inscanruls';
			$scanrule = $1;
		}

		# jump over lines not looking like "abc = def"
		next if($line !~ /^\s*\S+\s*=.*$/ );

		if ( $mode eq 'global' ) {
			($key,$value) = split(/=/,$line,2);
			# Remove whitespaces at the beginning and at the end
			$key   =~ s/^\s+//g; $key   =~ s/\s+$//g;
			$value =~ s/^\s+//g; $value =~ s/\s+$//g;
			die "Configuration option '$key' defined twice in line $count\n" if($config{$key});
	#		print "CONF $key => $value \n";
			$config{$key} = $value;
		}
		elsif ( $mode eq 'inscanruls' and $scanrule ne '' ) {
			($key,$value) = split(/=/,$line,2);
			$key   =~ s/^\s+//g; $key   =~ s/\s+$//g;
			$value =~ s/^\s+//g; $value =~ s/\s+$//g;
			die "Scanrule option '$key' defined twice in line $count\n" if($scanruls->{$scanrule}->{$key});
#print "$scanrule CONF $key => $value \n";
			$scanruls->{$scanrule}->{$key} = $value;
		}
	}

	return $config,$scanruls;
}


%default_config = (
	logline          => '[%s #%%s] %s\n',
	positionfile     => '.logscan.pos',
	blockdelimit     => '/^\[\d\d-[A-Z][a-z][a-z]-\d{4} \d\d:\d\d:\d\d]\s/',
	skip_last_line   => 0,
	stdout           => '',
	matchout         => '',
	stderr           => '',
	maxfoundrules    => 500,
	maxblocklines    => 1000,
	maxblocks        => 0,
	sendmail         => '/usr/sbin/sendmail',
	sendmail_from    => 'logscanner@devbiz',
	sendmail_subject => '[LOGSCAN] %s in %s'
);



#########################################
# readPos
# Read the current position from a file
# You can define a positionjumpback in bytes,
# which is jumped back to ensure reread of previously unready written lines.
# This should also lock the POS-file to hinder other processes to run twice
#
sub readPos($)
{
	($posfile) = @_;

	# read the position file

	open( POSFILE, "<" . $posfile ) || die "cannot open '$posfile' ($!), plz create an empty file!\n";
	# LOCK_EX | LOCK_NB
	flock( POSFILE, 2 | 4 ) || die "cannot lock '$posfile' ($!) - maybe another process is running!\n";

	if ( -z $posfile ) {
		$position = 0;
	} else {
		$position = <POSFILE>;
		chomp( $position );
		# remove everything after first non-digit
		$position =~ s/\D.*$//g;
		# move back to 
		if ( $position <= 0 ) {
			$position = 0;
		}
	}
	# keep the file open to keep the lock
	return $position;
}

############################################
# writePos
# writes a new position into posfile
sub writePos($$)
{
	($posfile, $pos) = @_;
	open( POSFILE, ">" . $posfile ) || die "cannot write '$posfile'!\n";
	print POSFILE "$pos\n";
}


###########################################
# read_next_block
# Read the next log-entry-line.
# It uses the blockdelimiter to find the next logentry-line
# Note: A block can be maximum 10000 lines, if longer the script fails!
# Note: This is tricky because it uses global vars!
sub read_next_block()
{

	# nextline and lastpos is GLOBAL!

	# at the beginning
	if ( ! defined($nextline) ) {
		$nextline = <LOG>;
	}
	# at the end of file
	if ( ! defined($nextline) ) {
		return '';
	}

	# read last position!
	my $rememberpos = $lastpos;
	$lastpos = tell(LOG);

	my $logline = '';
	my $lines = 0;
	# read until eof or
	# the next logline (eg. '[15-Apr-2009 13:01:16] ') is found
	do {
		$logline .= $nextline;
		$nextline = <LOG>;
		# overread empty lines
		while ( defined($nextline) and $nextline eq '' ) {
			$nextline = <LOG>;
		}
		$lines += 1;
		if ( $lines > $config{maxblocklines} ) {
			die "Logline is longer than $config{maxblocklines} lines, giving up  @ " .
			    tell(LOG) . " (is your blockdelimiter correctly configured?)\n";
		}
	} while ( defined($nextline) and ( eval( '$nextline !~ ' . $config{blockdelimit}) ) );
	# skip last line
	if ( ! defined($nextline) and $config{skip_last_line} ) {
		$lastpos = $rememberpos;
		$logline = '';
	}
	# return
	return $logline;
}

#########################################################################



# start

# parse runtime arguments
foreach $arg ( @ARGV ) {
	if ( $arg eq '--help' ) {
		print <DATA>;
		exit;
	}
	elsif ( $arg eq '--showconfig' ) {
		$showconfig = 1;
	}
	else {
		$configfile = $arg;
	}
}	

if ( ! $configfile ) {
	print "need a logfile...!\n\n";
	print <DATA>;
	exit;
}


# read in the configuration
( $config, $scanruls ) = parse_config($configfile);

# set default config
while ( ($key, $value) = each(%default_config) ) {
	if ( ! defined($config{$key}) ) {
		$config{$key} = $value;
	}
}
if ( $config{maxblocks} !~ /\d+/ ) {
	$config{maxblocks} = 0;
}



# print config
if ( defined($showconfig) ) {
	print "Configuration read from '$configfile':\n";
	while ( ($key, $value) = each(%config) ) {
		print "	$key	=>	$value\n";
	}

	print "Would scan for errors:\n";
	$cnt = 0;
	while ( ($key, $value) = each(%$scanruls) ) {
		$cnt += 1;
		print "	Rule #$cnt : '$key'\n";
		while ( ($k, $v) = each(%$value) ) {
			print "		$k => '$v'\n";
		}
	}

	exit;
}

# make redirects for STDOUT and STDERR
# NOTE: If you redirect STDERR
if ( $config{stdout} ne '' ) {
	open( STDOUT, $config{stdout} ) || die "cannot open stdout '$config{stdout}' ($!)\n";
}
select(STDOUT); $| = 1;     # make unbuffered

if ( $config{matchout} ne '' ) {
	open( MATCHOUT, $config{matchout} ) || die "cannot open stdout '$config{matchout}' ($!)\n";
} else {
	# otherwise print to STDOUT
	open( MATCHOUT, '>&STDOUT' );
}
select(MATCHOUT); $| = 1;     # make unbuffered

if ( $config{stderr} ne '' ) {
	open( STDERR, $config{stderr} ) || die "cannot open stderr '$config{stderr}' ($!)\n";
}
select(STDERR); $| = 1;     # make unbuffered
printLog("START with configuration '$configfile', " . localtime(time) , 'OUT' );


#############################
# configuration is done!

# open logfile and jump to position
$position = readPos($config{positionfile});
$lastpos  = $position;
open( LOG, "<" . $config{logfile} ) || die "Cannot open '" . $config{logfile} . "' ($!)\n";
seek( LOG, $position, 0 );


printLog("READ $config{logfile} @ $position", 'OUT');

$cnt = 0;
@matches = ();
my $found;
while ( $block = read_next_block() ) {
	# print status message every 100000th line
	if ( $cnt % 1000000 == 0 and $cnt != 0 ) {
		$newblock = $block;
		chomp($newblock);
		printLog("$cnt - $newblock - CNT: " . scalar(@matches), 'OUT' );
	}
	# go through every rule and search for regex
	while ( ($key, $value) = each(%$scanruls) ) {
		if ( defined($value->{'regex'}) ) {
			if ( eval('$block =~ ' . $value->{'regex'} ) ) {
				my $tmp;
				$tmp->{'rule'} = $key;
				$tmp->{'block'} = $block;
				if ( defined($value->{'find'})
				 and $found = eval('$block =~ ' . $value->{'find'} .'; return $1;') ) {
					$tmp->{'found'} = $found;
				}
				push( @matches, $tmp );
			}
		}
	}
	# too many matches found?
	if ( scalar(@matches) >= $config{maxfoundrules} ) {
		printLog("Too many matches found (> $config{maxfoundrules}), cleanly aborting scan now!", 'ERR');
		last;
	}
	$cnt += 1;
	# too many blocks read?
	if ( $config{maxblocks} >= 1 and $cnt >= $config{maxblocks} ) {
		printLog("Too many blocks (=lines) read (> $config{maxblocks}), cleanly aborting scan now!", 'ERR');
		last;
	}
}

# remeber current position in log
# and write back to positionfile
writePos($config{positionfile}, $lastpos );
$currentpos = tell(LOG);
printLog("SCANNED, last position: $lastpos (read " . ($lastpos - $position) . " bytes, $cnt blocks)" .
	(  $currentpos != $lastpos ? "\n; EOF : $currentpos (because skip_last_line=1 or clean abort of scan)" : '' ) ,
	'OUT' );


################################################################
# print found errors
printLog("Matches found: " . scalar(@matches), 'OUT' );
my %bodies;
my %bodiescnt;
foreach $match ( @matches ) {
	$rule = $match->{'rule'};
	$body = $match->{'block'};
	chomp($body);
	if ( defined($match->{'found'}) ) {
		$found = "\nFOUND: ". $match->{'found'} ;
		chomp($found);
	} else {
		$found = '';
	}
	$bodies{$rule} .= $body.$found."\n--\n";
	$bodiescnt{$rule} += 1;
	printLog("$rule -> " . substr($body, 0, 80) . $found, 'MATCH' );
}


while ( ($rule, $body) = each(%bodies) ) {
	printLog("Matches for '$rule': " . $bodiescnt{$rule}, 'OUT');
	if ( defined($scanruls->{$rule}->{'email'}) ) {
		printLog("Send mail for rule '$rule' to " . $scanruls->{$rule}->{'email'}, 'OUT');
		sendScanMail($rule,$body,$bodiescnt{$rule});
	}
}

printLog("FINISHED, " . localtime(time), 'OUT');

__END__
NAME
	logscan searches for patterns in logfiles and outputs found matches


SYNOPSIS
	logscan [--help] [--showconfig] configfile

DESCRIPTION
	Reads in any text-base logfile-format (also multi-line-formats).
	Scans for any regex in every "block" and reports found matches to STDERR.
	
	logscan needs a configure-file to run.

AUTHOR
	logscan,
	2009-2014, <alex.aulbach@mayflower.de>


EXAMPLE

----------------------------------------------------------------
###########################################
# Global section
#
# where to store the position, till where the logfile was scanned at the last time
positionfile  = .logscan-aul-dev-php_error.pos

# This number of bytes we "jump back" into the logfile to make sure we scan unfinished written blocks
positionjumpback = 5000

# the logfile itself
logfile       = /home/prg/apache_php5/logs/vrnet/aul-dev/php_error.log

# the blockdelimiter;
# logscan reads line by line, until this marker is found,
# the read lines are one block and so it can be parsed as one string
blockdelimit  = /^\[\d\d-[A-Z][a-z][a-z]-\d{4} \d\d:\d\d:\d\d]\s/

# a block cannot be longer than this number of lines (to prevent eating up memory)
maxblocklines = 1000

# so many blocks should be read in maximum
# use this option for very, very high log traffic to limit load and overrun!
# set empty or 0 to ignore
maxblocks     =

# by default everything is printed to STDOUT and STDERR
stdout        = 
stderr        =

# some more examples, which make sense
#
# This makes sense if you use crontab to mail the errors.
# In this case you DO NOT NEED to configure the email-addresses for the rules,
# and every error goes to ONE adress:
#
# stdout = >/dev/null
# stderr = 
#
# You can of course log into different logfiles,
# but also log everything into ONE logfile:
#
# stdout        = >>./logscan.log
# stderr        = >>./logscan.log

# logline uses sprintf to echo a line
# this looks like: [Tue Apr 21 12:57:18 2009 #0] START with configuration 'logscan.config'
logline       = [%s #%%s] %s\n

# this makes also sense:
# logline = %2$s\n

# sendmail config
sendmail      = /usr/sbin/sendmail
sendmail_from = logscanner@devbiz
sendmail_subject = [LOGSCAN] %s in %s

# this number of rules can be found,
# after this the script ends itself as when the eof has reached
maxfoundrules = 500


###########################################
# rules-section
# you can add here as many rules as you want, every rule begins with "<..RULENAME..>"
[SCANRULES]
# "regex" : regular expression for this rule, must match a block (= line)
# "find"  : regular expression: if "regex" is found match with this. If found then $1 is taken for special output.
# "messg" : Message for this rule
# "email" : email-address to send reports - if unset no mail is sent!
<FATAL>
regex   = /] PHP Fatal error:/
messg   = Fatal PHP-error
email   = alex.aulbach@mayflower.de

<ALARMS>
regex   = /] INCOMING ALARM from/
find    = /sernum:(\w+)/
messg   = Incoming Alarms
email   = alex.aulbach@mayflower.de
---------------------------------------------------------------
