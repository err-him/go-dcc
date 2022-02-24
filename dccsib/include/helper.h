/* Distributed Checksum Clearinghouse
 *
 * DNS white- and blacklist definitions
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
 * Rhyolite Software DCC 1.3.163-1.42 $Revision$
 */

#ifndef HELPER_H
#define HELPER_H

#include "dcc_ck.h"

#define HELPER_IDLE_STOP_SECS	(60*60)	/* helpers die of this much boredom */
#define HELPER_IDLE_RESTART	(HELPER_IDLE_STOP_SECS - 30)
#define HELPER_AUTO_REAP	(HELPER_IDLE_STOP_SECS / 20)

#define HELPER_PAT "helper=%d,%d,%d,%d"

typedef struct helper_gen {
    struct helper_gen *fwd, *bak;
    int		ref_cnt;
    int		num;
    time_t	idle_restart;		/* restart helpers after then */
    DCC_SOCKU	su;			/* helpers receive requests and */
    DCC_SOCKET	soc;			/*	send responses here */
    char	su_name[DCC_SU2STR_SIZE];
    int		fin_pipe[2];		/* pipe for end of job signals */
    int		total_helpers;
    int		idle_helpers;
    int		total_pids;
    int		num_pids;
    pid_t	*pids;
} HELPER_GEN;

typedef struct {
    u_int	sn;			/* serial # of request from parent */
    int		argc;
    int		free_args;
    char const	**argv;
    HELPER_GEN	*gens;
    int		gen_num;
    int		max_helpers;
    int		debug;
    int		helpers_debug;
    u_char	is_child;
} HELPERS;

extern HELPERS helpers;


typedef struct {
    u_int	version;
    u_int	magic;
    u_int	sn;
    struct timeval start;		/* when job started */
    time_t	avail_us;		/* microseconds available for job */
    char	id[MSG_ID_LEN+1];
} HELPER_REQ_HDR;

typedef struct {
    u_int	version;
    u_int	magic;
    u_int	sn;
} HELPER_RESP_HDR;

#define HELPER_VERSION	    0x10
#define HELPER_MAGIC_REQ    0xbeefdead
#define HELPER_MAGIC_RESP   0xdeadbeef

typedef struct {
    HELPER_REQ_HDR hdr;
    DNSBL_HIT	src;			/* where name or address was found */
    DNSBL_HIT	ghits[NUM_DNSBL_GROUPS];    /* existing hits */
    DNSBL_TGT	tgt;
} DNSBL_REQ;

typedef struct {
    DNSBL_HIT	hit;			/* what was found */
    int		num;			/* # of list hit */
    char	ip[DCC_SU2STR_SIZE];    /* IP address found in DNS list */
    DNSBL_DOM	tgt;			/* name or address sought in list */
    DNSBL_DOM	probe;			/* what was actually looked up */
} DNSBL_RESP_HGROUP;
typedef struct {
    HELPER_RESP_HDR hdr;
    DNSBL_RESP_HGROUP hgroups[NUM_DNSBL_GROUPS];
} DNSBL_RESP;


extern void DCC_NORET helper_child(int, int, int, int);
extern void reap_helpers(void);
extern void stop_helpers(void);
extern u_char ask_helper(DNSBL_WORK *,
			 HELPER_REQ_HDR *, int, HELPER_RESP_HDR *, int);

extern u_char dnsbl_helper_work(const DNSBL_REQ *, DNSBL_RESP *);

#endif /* HELPER_H */
