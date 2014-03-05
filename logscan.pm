#!/usr/bin/perl -w
#
# LogsCan
#
# 2009-2014 Alex Aulbach
#
# Bugs:
#  No check if the logfile was truncated...
#
# TODO:
# - checksum over last block to make sure, that after recall the file is really correct
# - consider log-rotation
# - example configs
# - unit-tests
# - generating test-events (to test is mail works etc.)
# - option for the position (and many other config via options)
# - read from pipe (deamon-like)
# - charset!
#


use Data::Dumper; # helper for debugging

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
    open (SENDMAIL,"|$config{sendmail} -t -f $config{sendmail_from}") || die("ERROR: sendmail misconfiguration ($!)\n");
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
    my $configpath = shift;

    $content = read_config($configpath);

    # carrige-return or only return or only carrige
    my @lines  = split(/\015\012|\012|\015/,$content);
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
            $value =~ s/^(['"])(.*)\1$/$2/ ;  # Remove quotes
            die "ERROR: Configuration option '$key' defined twice in line $count\n" if($config{$key});
            $config{$key} = $value;
        }
        elsif ( $mode eq 'inscanruls' and $scanrule ne '' ) {
            ($key,$value) = split(/=/,$line,2);
            $key   =~ s/^\s+//g; $key   =~ s/\s+$//g;
            $value =~ s/^\s+//g; $value =~ s/\s+$//g;
            $value =~ s/^(['"])(.*)\1$/$2/ ;  # Remove quotes
            die "ERROR: Scanrule option '$key' defined twice in line $count\n" if($scanruls->{$scanrule}->{$key});
            # special rule for email, if it doesn't look like email adress
            if ($key eq 'email' && $value !~ /^.+@.+$/ && defined $config{$value} && $config{$value} =~ /^.+@.+$/) {
                $value = $config{$value} . " (from config $value)";
            }

            $scanruls->{$scanrule}->{$key} = $value;
        }
    }

    return $config,$scanruls;
}


####################################################################
# compute_configpath
# if the configpath is just a directory we assume the filename as
# 'logscan.cfg in that dir
sub read_config($)
{
    my ($configpath) = @_;

    if (-f $configpath) {
        return read_config_file($configpath);
    }

    if (-d $configpath) {
        return read_precompiled_directory_config($configpath);
    }

    die "ERROR: this is not a CONFIGFILE: '$configpath'";
}

####################################################################
# read_config_file
# reads config file
sub read_config_file($)
{
    my $configfile = shift;
    local *CF;

    open(CF,'<'.$configfile) or die "ERROR: cannot open CONFIG '$configfile' ($!)\n";
    read(CF, my $data, -s $configfile);
    close(CF);

    return $data;
}

####################################################################
# read_precompiled_directory_config
# only called, if used together with a directory as config
# joins together the main-config and the scan rules and replaces paths
sub read_precompiled_directory_config($)
{
    my ($configdir) = @_;
    local @configs;
    local @scanrules;
    local *DIR;
    local *FILE;

    opendir(DIR, $configdir) || die "ERROR: cannot open DIRECTORY '$configdir' ($!)\n";;
    while (my $file = readdir(DIR)) {
        if ( $file =~ /^logscan.*\.cfg$/ ) {
            push(@configs, $configdir . '/' . $file);
        }
        if ( $file =~ /^scanrule.*\.cfg$/ ) {
            push(@scanrules, $configdir . '/' . $file);
        }
    }
    close DIR;

    local $content;
    local $filecontent;
    foreach $file (sort(@configs)) {
        open FILE, $file or die "ERROR: cannot open CONFIG '$file' ($!)\n";;
        read(FILE, $filecontent, -s $file);
        $content .= "\n$filecontent";
        close FILE;
    }
    foreach $file (sort(@scanrules)) {
        open FILE, $file or die "ERROR: cannot open SCANRULE '$file' ($!)\n";;
        read(FILE, $filecontent, -s $file);
        $content .= "\n$filecontent";
        close FILE;
    }

    $content =~ s/\{%DIR%}/$configdir/g;

    $default_config{read_config_from_dir} = 'yes';

    return $content;
}




%default_config = (
    logline          => '[%s #%%s] %s\n',
    positionfile     => '%s.pos',
    blockdelimit     => '/^\[\d\d-[A-Z][a-z][a-z]-\d{4} \d\d:\d\d:\d\d]\s/',
    skip_last_line   => 0,
    stdout           => '',
    matchout         => '',
    stderr           => '',
    maxfoundrules    => 500,
    maxblocklines    => 1000,
    maxblocks        => 0,
    sendmail         => '/usr/sbin/sendmail',
    sendmail_from    => 'unkown@unknown',
    sendmail_subject => '[LogsCan] %s in %s'
);

#########################################
# resetPos
# creates a posfile if not existing and set it's position to 0
sub resetPos($)
{
    ($posfile) = @_;

    open( POSFILE, ">" . $posfile) || die "ERROR: cannot create POSFILE '$posfile' ($!).\n";
    print POSFILE "0\n";
    close POSFILE;
}


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

    open( POSFILE, "<" . $posfile ) || die "ERROR: cannot open POSFILE '$posfile' ($!), plz create an empty file!\n";
    # LOCK_EX | LOCK_NB
    flock( POSFILE, 2 | 4 ) || die "ERROR: cannot lock POSFILE '$posfile' ($!) - maybe another process is running!\n";

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
    open( POSFILE, ">" . $posfile ) || die "ERROR: cannot write POSFILE '$posfile'!\n";
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
            die "ERROR: Logline is longer than $config{maxblocklines} lines, giving up  @ " .
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

###########################################
# print_config
# print the config human readable
sub print_config($%)
{
    my ($configfile, %config) = @_;

    print "# Configuration read from '$configfile':\n";
    foreach my $key (sort {lc $a cmp lc $b} keys %config) {
        printf("  %20s   =   '%s'\n", $key, $config{$key});
    }

    print "\n";
    print "[SCANRULES]\n";
    $cnt = 0;
    foreach my $key (sort {lc $a cmp lc $b} keys %$scanruls) {
        $cnt += 1;
        print "\n";
        print "#    Rule #$cnt : '$key'\n";
        print "<$key>\n";
        foreach my $k (sort {lc $a cmp lc $b} keys $scanruls->{$key}) {
            printf("    %20s = '%s'\n", $k, $scanruls->{$key}->{$k});
        }
    }
}

#########################################################################



# start

# parse runtime arguments
local %args;
foreach $arg ( @ARGV ) {
    if ( $arg eq '--help' ) {
        print <DATA>;
        exit;
    }
    elsif ( $arg =~ /--(\w+)/ ) {
        $args{$1} = 1;
    }
    else {
        $configfile = $arg;
    }
}

if ( ! $configfile ) {
    print "ERROR: need a configuration-file!\n\n";
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


########################################################################
# print config
if ( defined($args{showconfig}) ) {
    print_config($configfile, %config);
    exit;
}

########################################################################
# make redirects for STDOUT and STDERR
# NOTE: If you redirect STDERR
if ( $config{stdout} ne '' ) {
    open( STDOUT, $config{stdout} ) || die "ERROR: cannot open STDOUT '$config{stdout}' ($!) ". __LINE__ . "\n";
}
select(STDOUT); $| = 1;     # make unbuffered

if ( $config{matchout} ne '' ) {
    open( MATCHOUT, $config{matchout} ) || die "ERROR: cannot open STDOUT '$config{matchout}' ($!) ". __LINE__ . "\n";
} else {
    # otherwise print to STDOUT
    open( MATCHOUT, '>&STDOUT' );
}
select(MATCHOUT); $| = 1;     # make unbuffered

if ( $config{stderr} ne '' ) {
    open( STDERR, $config{stderr} ) || die "ERROR: cannot open STDERR '$config{stderr}' ($!)\n";
}
select(STDERR); $| = 1;     # make unbuffered
printLog("START with configuration '$configfile', " . localtime(time) , 'OUT' );


#############################
# configuration is done!

# open logfile and jump to position
if (! -f $config{positionfile}) {
    resetPos($config{positionfile});
    printLog("CREATING new POSFILE '$posfile', cause not existing, ", 'OUT');
} elsif (defined $args{resetposfile}) {
    resetPos($config{positionfile});
    printLog("RESET POSFILE '$posfile' due to given call-argument.", 'OUT');
}

$position = readPos($config{positionfile});
$lastpos  = $position;
open( LOG, "<" . $config{logfile} ) || die "ERROR: Cannot open '" . $config{logfile} . "' ($!)\n";
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
        printLog("WARNING: Too many matches found (> $config{maxfoundrules}), cleanly aborting scan now!", 'ERR');
        last;
    }
    $cnt += 1;
    # too many blocks read?
    if ( $config{maxblocks} >= 1 and $cnt >= $config{maxblocks} ) {
        printLog("WARNING: Too many blocks (=lines) read (> $config{maxblocks}), cleanly aborting scan now!", 'ERR');
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
        if (defined $args{donotsendmail}) {
            printLog("Would send mail for rule '$rule' to " . $scanruls->{$rule}->{'email'} . ", but 'donotsendmail' is set.", 'OUT');
        } else {
            printLog("Send mail for rule '$rule' to " . $scanruls->{$rule}->{'email'}, 'OUT');
            sendScanMail($rule,$body,$bodiescnt{$rule});
        }
    }
}

printLog("FINISHED, " . localtime(time), 'OUT');

__END__
NAME
    logscan searches for patterns in logfiles and outputs found matches

SYNOPSIS
    logscan [--help] [--showconfig] configfile/-dir

DESCRIPTION
    Reads in any text-base logfile-format (also multi-line-formats).
    Scans for any regex in every "block" and reports found matches to STDERR.
    logscan needs a configure-file to run or a configuration-directory (see down!)
    Output are three streams:
     - stdout    - messages, what the program is currently doing, by default send to STDOUT
     - matchout  - the found results from the logfile, by default linked to stdout
     - stderr    - error-messages, by default send to STDERR
    You can rename all the streams to real files in the config-file!
    For every rule you can send an email at the end, if configured.

CONFIGURATION DIRECTORY
    If the configdir-parameter points to a directory, logscan assumes, that it is
    a configuration-directory and takes every files ending with
         "logscan*.cfg" (in alphabetic order) and
         "scanrule*.cfg" for the scanrules (alphabetic, too)
    to create a big, merged configuration file out of it.
    It replaces also all occurences of "{%DIR%}" in that joined file with the
    given configdir-parameter, which makes it possible to place any output
    relative to this parameter.

PARAMETERS
    --showconfig
      display the computed configuration and scanrules. The output can be used as input for the scanrules
    --donotsendmail
      suppress sending mails
    --resetposition
      resets the positionfile to 0

AUTHOR
    logscan,
    2009-2014, <alex.aulbach@mayflower.de>

