/* Distributed Checksum Clearinghouse
 *
 * supplement or replace missing /usr/include/paths.h
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
 *
 * Rhyolite Software DCC 1.3.163-1.6 $Revision$
 */

#ifndef DCC_PATHS_H
#define DCC_PATHS_H

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif

#ifdef DCC_WIN32
extern const char *_PATH_TMP;

#ifndef _PATH_DEVNULL
#define _PATH_DEVNULL "NUL"
#endif

#else /* !DCC_WIN32 */

#ifndef _PATH_TMP
#define _PATH_TMP "/tmp/"
#endif

#ifndef _PATH_DEVNULL
#define _PATH_DEVNULL "/dev/null"
#endif

#ifndef _PATH_VARRUN
#define _PATH_VARRUN "/var/run/"
#endif

#endif /* !DCC_WIN32 */

#endif	/* DCC_PATHS_H */
