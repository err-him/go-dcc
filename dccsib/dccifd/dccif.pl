#! /usr/bin/perl -w

# a sample Perl interface to the DCC interface daemon, dccifd

# Copyright (c) 2017 by Rhyolite Software, LLC
#
# This agreement is not applicable to any entity which sells anti-spam
# solutions to others or provides an anti-spam solution as part of a
# security solution sold to other entities, or to a private network
# which employs the DCC or uses data provided by operation of the DCC
# but does not provide corresponding data to other users.
#
# Permission to use, copy, modify, and distribute this software without
# changes for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear in all
# copies and any distributed versions or copies are either unchanged
# or not called anything similar to "DCC" or "Distributed Checksum
# Clearinghouse".
#
# Parties not eligible to receive a license under this agreement can
# obtain a commercial license to use DCC by contacting Rhyolite Software
# at sales@rhyolite.com.
#
# A commercial license would be for Distributed Checksum and Reputation
# Clearinghouse software.  That software includes additional features.  This
# free license for Distributed ChecksumClearinghouse Software does not in any
# way grant permision to use Distributed Checksum and Reputation Clearinghouse
# software
#
# THE SOFTWARE IS PROVIDED "AS IS" AND RHYOLITE SOFTWARE, LLC DISCLAIMS ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL RHYOLITE SOFTWARE, LLC
# BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES
# OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
# ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

# Rhyolite Software DCC 1.3.163-1.12 $Revision$
# Generated automatically from dccif.pl.in by configure.

# check this file by running it separately
use strict 'subs';

use Socket;

# so this file can be used with constructions like do('../dccif.pl')
#   in dccif-test/dccif-test.pl
return 1;


# Returns a string
#   The first character indicates the overall result of the the operation.
#	If the dccifd daemon is not running or there were other problems,
#	the first character is '?', the second is '\n', and the rest of the
#	string is an error message.
#	If things are ok, the first character is one of the
#	DCCIF_RESULT_* values from include/dccif.h and the second is '\n'.
#   If things are ok, the second line is a string of characters, each
#	indicating whether message should be delivered to the corresponding
#	recipient (DCCIF_RCPT_ACCEPT or 'A') or rejected (DCCIF_RCPT_REJECT
#	or 'R').  This string is also ended with a newline ('\n') character.
# The body including headers of the message is read from one file or
#	file handle (e.g. "-").
#	The X-DCC header (if the "header" option is present) or the body
#	with added X-DCC header (if the "body" option is present) is
#	written to a second file or filehandle (e.g. "-").
# The result depends on the -t thresholds given dccifd.
# If the $env_tos or list of targets of the message is empty, this acts
#	as if dccifd is being run with -Q.
sub dccif {
    my($out,			# write X-DCC header or entire body to this
       $opts,			# blank separated string of "spam", ... options
       $clnt_addr,		# SMTP client IP address as a string
       $clnt_name,		# null or SMTP client hostname
       $helo,			# value of SMTP HELO command
       $env_from,		# envelope Mail_From value
       $env_tos,		# array of "address\rname" env_To strings
       $in,			# read body from this
       $homedir) = @_;		# DCC home directory

    my($env_to, $result, $body, $oks, $i);

    $homedir = "/var/dcc"
	if (! $homedir);

    if ($clnt_addr) {
	inet_aton($clnt_addr)
	    || return ("", "inet_aton($clnt_addr) failed: $!\n");
    } else {
	$clnt_name = '';
    }

    socket(SOCK, AF_UNIX, SOCK_STREAM, 0)
	|| return("", "socket(AF_UNIX): $!\n");
    connect(SOCK, sockaddr_un("$homedir/dccifd"))
	|| return("", "connect($homedir/dccifd): $!\n");

    # send the options and other parameters to the daemon
    $result = dccif_write($opts . "\012"
			  . $clnt_addr . "\015" . $clnt_name . "\012"
			  . $helo . "\012"
			  . $env_from . "\012",
			  "opts helo clnt");
    return $result if ($result);

    foreach $env_to (@$env_tos) {
	$result = dccif_write($env_to . "\012", "rcpt");
	return $result if ($result);
    }
    $result = dccif_write("\012", "end rcpts");
    return $result if ($result);

    # send the body of the message to the daemon
    if (! open(IFH, $in)) {
	$result = "?\nopen($in): $!\n";
	close(SOCK);
	return $result
    }
    for (;;) {
	$i = sysread(IFH, $body, 8192);
	if (!defined($i)) {
	    $result = "?\nsysread(body): $!\n";
	    close(SOCK);
	    close(IFH);
	    return $result;
	}
	if ($i == 0) {
	    close(IFH);
	    last;
	}
	$result = dccif_write($body, "body");
	if ($result) {
	    close(IFH);
	    return $result;
	}
    }

    # tell the daemon it has all of the message
    if (!shutdown(SOCK, 1)) {
	$result = "shutdown($homedir/dccifd): $!\n";
	close(SOCK);
	return $result;
    }

    # get the result from the daemon
    $result = <SOCK>;
    if (!defined $result) {
	$result = "read($homedir/dccifd): $!\n";
	close(SOCK);
	return $result;
    }
    $oks = <SOCK>;
    if (!defined $oks) {
	$result = "read($homedir/dccifd): $!\n";
	close(SOCK);
	return $result;
    }

    # copy the header or body from the daemon
    if (! open(OFH, ">" . $out)) {
	$result = "?\nopen($in): $!\n";
	close(SOCK);
	return $result
    }
    for (;;) {
	$i = read(SOCK, $body, 8192);
	if (!defined $i) {
	    $result = "?\nread(body): $!\n";
	    close(SOCK);
	    close(OFH);
	    return $result;
	}
	if ($i == 0) {
	    close(SOCK);
	    close(OFH);
	    return $result . $oks;
	}
	if (! syswrite(OFH, $body)) {
	    $result = "?\nsyswrite($out): $!\n";
	    close(SOCK);
	    close(OFH);
	    return $result;
	}
    }
}



sub dccif_write {
    my($buf, $emsg) = @_;
    my $result;

    if (! syswrite(SOCK, $buf)) {
	$result = ("?\nsyswrite($emsg): $!\n");
	close(SOCK);
	return $result
    }
    return "";
}
