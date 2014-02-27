#### NAME ####
LogsCan searches for patterns in logfiles and outputs found matches.
It remembers the correct position from the last scan and scans only
the needed new lines since then.
It writes logfiles and/or sends emails with a list of results after scan.

#### SYNOPSIS ####
        logscan [--help] [--showconfig] configfile

#### DESCRIPTION ####
Reads in any text-base logfile-format (also multi-line-formats).
Scans for any regex in every "block" and reports found matches to STDERR.
LogsCan needs a configure-file to run.

