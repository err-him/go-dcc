/* Distributed Checksum Clearinghouse
 *
 * convert an ID to binary
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
 * Rhyolite Software DCC 1.3.163-1.21 $Revision$
 */

#include "dcc_defs.h"
#include "dcc_xhdr.h"


/* get client or server-ID */
DCC_CLNT_ID				/* ID or DCC_ID_INVALID */
dcc_get_id(DCC_EMSG *emsg, const char *id_str,
	   const char *fnm, int lno)
{
	char *p;
	unsigned long id;
	DCC_FNM_LNO_BUF fnm_buf;

	id_str += strspn(id_str, DCC_WHITESPACE);
	id = strtoul(id_str, &p, 10);
	if (*p != '\0'
	    || (id != DCC_ID_ANON
		&& (id < DCC_SRVR_ID_MIN || id > DCC_CLNT_ID_MAX))) {
		if (!strcasecmp(id_str, DCC_XHDR_ID_ANON))
			return DCC_ID_ANON;

		dcc_pemsg(EX_DATAERR, emsg, "invalid ID \"%s\"%s",
			  id_str, dcc_fnm_lno(&fnm_buf, fnm, lno));
		return DCC_ID_INVALID;
	}

	return id;
}



/* get server-ID */
const char *				/* rest of string */
dcc_get_srvr_id(DCC_EMSG *emsg,
		DCC_SRVR_ID *result,	/* ID or DCC_ID_INVALID */
		const char *id_str, const char *dlims,
		const char *fnm, int lno)
{
	char *p;
	unsigned long id;
	DCC_FNM_LNO_BUF fnm_buf;

	if (!dlims)
		dlims = "";
	id = strtoul(id_str, &p, 10);
	if (p == id_str
	    || (*p && !strchr(dlims, *p))
	    || !DCC_ID_SRVR_NORMAL(id)) {
		dcc_pemsg(EX_DATAERR, emsg, "invalid server-ID \"%s\"%s",
			  id_str, dcc_fnm_lno(&fnm_buf, fnm, lno));
		*result = DCC_ID_INVALID;
		return 0;
	}

	*result = id;
	return p;
}
