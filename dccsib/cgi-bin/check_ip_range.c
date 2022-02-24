/* Distributed Checksum Clearinghouse
 *
 * check a supposed IP address range for the CGI scripts
 *
 * Copyright (c) 2017 by Rhyolite Software, LLC
 *
 * This agreement is not applicable to any entity which sells anti-spam
 * solutions to others or provides an anti-spam solution as part of a
 * security solution sold to other entities, or to a private network
 * which employs the DCC or uses data provided by operation of the DCC
 * but does not provide corresponding data to other users.
 *
 * Permission to use, copy, modify, and distribute this software without
 * changes for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear in all
 * copies and any distributed versions or copies are either unchanged
 * or not called anything similar to "DCC" or "Distributed Checksum
 * Clearinghouse".
 *
 * Parties not eligible to receive a license under this agreement can
 * obtain a commercial license to use DCC by contacting Rhyolite Software
 * at sales@rhyolite.com.
 *
 * A commercial license would be for Distributed Checksum and Reputation
 * Clearinghouse software.  That software includes additional features.  This
 * free license for Distributed ChecksumClearinghouse Software does not in any
 * way grant permision to use Distributed Checksum and Reputation Clearinghouse
 * software
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND RHYOLITE SOFTWARE, LLC DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL RHYOLITE SOFTWARE, LLC
 * BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES
 * OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Rhyolite Software DCC 1.3.163-1.8 $Revision$
 */

#include "dcc_defs.h"
#include <arpa/inet.h>

static DCC_EMSG dcc_emsg;

static void DCC_NORET
usage(void)
{
	dcc_logbad(EX_USAGE, "usage: [-V] range");
}



int
main(int argc, char **argv)
{
	u_char print_version = 0;
	DCC_IP_RANGE range;
	char buf[INET6_ADDRSTRLEN+1+INET6_ADDRSTRLEN+1];
	const char *str;
	int i, result;

	while ((i = getopt(argc, argv, "V")) != EOF) {
		switch (i) {
		case 'V':
			dcc_version_print();
			print_version = 1;

		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc == 0) {
		if (print_version)
			exit(EX_OK);
		usage();
	}

	result = EX_OK;
	while ((str = *argv++) != 0) {
		i = str2range(&dcc_emsg, &range, 0, str, 0, 0);
		if (0 > i) {
			result = emsg_ex_code(&dcc_emsg);
			fprintf(stderr, "%s\n", dcc_emsg.c);
		} else if (i == 0) {
			result = EX_DATAERR;
			fprintf(stderr, "invalid IP address \"%s\"\n", str);
		} else {
			printf("%s\n", range2str(buf, sizeof(buf), &range));
		}
	}

	exit(result);
}
