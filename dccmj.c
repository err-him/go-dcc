/* Distributed Checksum Clearinghouse server
 *
 * report a message for such as procmail
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
 * Rhyolite Software DCC 1.3.163-1.215 $Revision$
 */
#include "dccmj.h"
#include "./dccsib/include/dcc_ck.h"
#include "./dccsib/include/dcc_xhdr.h"
#include "./dccsib/include/dcc_heap_debug.h"
#include <signal.h>			/* for Linux and SunOS*/
#ifndef DCC_WIN32
#include <arpa/inet.h>
#endif


static DCC_EMSG dcc_emsg;

static const char *mapfile_nm = DCC_MAP_NM_DEF;

static u_char priv_logdir;
static DCC_PATH log_path;
static int lfd = -1;
static struct timeval ldate;

static u_char logging = 1;		/* 0=no log, 1=have file, 2=used it */
static size_t log_size;

static char id[MSG_ID_LEN+1];
static DCC_PATH tmp_nm;
static u_char tmp_rewound;
static int hdrs_len, body_len;
static u_char seen_hdr;

static u_char end_process;

static int exit_code = EX_NOUSER;
static DCC_TGTS local_tgts;
static u_char local_tgts_spam, local_tgts_set;
static int total_hdrs, cr_hdrs;

static const char* white_nm;
static FILE *ifile;

static DCC_CLNT_CTXT *ctxt;
static char xhdr_fname[sizeof(DCC_XHDR_START)+sizeof(DCC_BRAND)+1];
static int xhdr_fname_len;
static u_char add_xhdr;			/* add instead of replace header */
static u_char cksums_only;		/* output only checksums */
static u_char x_dcc_only;		/* output only the X-DCC header */
static u_char fake_envelope;		/* fake envelope log lines */
static int std_received;		/* Received: line is standard */

static ASK_ST ask_st;
static FLTR_SWS rcpt_sws;
static GOT_CKS cks;
static CKS_WTGTS wtgts;
static char helo[HELO_MAX];
static char sender_name[DCC_MAXDOMAINLEN];
static char sender_str[INET6_ADDRSTRLEN];
static u_char sender_set;
static struct in6_addr clnt_addr;

static char env_from_buf[HDR_CK_MAX+1];
static const char *env_from = 0;

static char mail_host[DCC_MAXDOMAINLEN];

static DCC_HEADER_BUF header;

static EARLY_LOG early_log;

static void start_dccifd(void);
static u_char check_mx_listing(void);
static int get_hdr(char *, int);
static void add_hdr(void *, const char *, u_int);
static void log_write(const void *, int);
static void log_body_write(const char *, u_int);
static void thr_log_write(void *, const char *, u_int);
static void log_late(void);
static int log_print(u_char, const char *, ...) DCC_PF(2,3);
#define LOG_CAPTION(s) log_write((s), LITZ(s))
#define LOG_EOL() LOG_CAPTION("\n")
static void log_fin(void);
static void log_ck(void *, const char *, u_int);
static void dccproc_error_msg(const char *, ...) DCC_PF(1,2);
static void sigterm(int);


static const char *usage_str =
"[-VdAQCHEPR]  [-h homedir] [-m map] [-w whiteclnt] [-T tmpdir]\n"
"   [-a IP-address] [-f env_from] [-t targets] [-x exitcode]\n"
"   [-c type,[log-thold,][spam-thold]] [-g [not-]type] [-S header]\n"
"   [-i infile] [-o outfile] [-l logdir] [-B dnsbl-option]\n"
"   [-L ltype,facility.level]";

static void DCC_NORET
usage(const char* barg)
{
	if (barg) {
		dcc_logbad(EX_USAGE, "unrecognized \"%s\"\nusage: %s\n",
			   barg, usage_str);
	} else {
		dcc_logbad(EX_USAGE, "%s\n", usage_str);
	}
}



int fingerprint(char *message, char *checksum)
{
	u_char print_version = 0;
	char buf[20*HDR_CK_MAX];	/* at least HDR_CK_MAX*3 */
	u_char log_tgts_set = 0;
	const char *homedir = 0;
	const char *logdir = 0;
	const char *tmpdir = 0;
	u_char ask_result;
	char *p;
	const char *p2;
	u_long l;
	int error, blen, i;

	/* because stderr is often mixed with stdout and effectively
	 * invisible, also complain to syslog */
	//dcc_syslog_init(1, "libdccmj.so", 0);
	dcc_clear_tholds();
	/* get ready for the IP and From header checksums */
	cks_init(&cks);

	ifile = fmemopen(message, strlen(message), "r");
	env_from = "env@from";

	/* get the headers */
	for (;;) {
		int hlen;

		hlen = get_hdr(buf, sizeof(buf));
		// end loop something went bad
		if (end_process) {
			break;
		}
		if (hlen <= 2
		    && (buf[0] == '\n'
			|| (buf[0] == '\r' && buf[1] == '\n'))) {
			/* stop at the separator between the body and headers */
			if (!seen_hdr) {
				// dcc_logbad(EX_DATAERR,"missing SMTP header lines");
				end_process = 1;
			}
			hdrs_len -= hlen;
			body_len = hlen;
			break;
		}
#define GET_HDR_CK(h,t) {						\
			if (!CLITCMP(buf, h)) {				\
				get_cks(&cks,DCC_CK_##t, &buf[LITZ(h)], 1);\
				seen_hdr = 1;				\
				continue;}}
		GET_HDR_CK(DCC_XHDR_TYPE_FROM":", FROM);
		GET_HDR_CK(DCC_XHDR_TYPE_MESSAGE_ID":", MESSAGE_ID);
#undef GET_HDR_CK

		/* notice UNIX From_ line */
		if (!seen_hdr
		    && !env_from
		    && parse_unix_from(buf, env_from_buf,
				       sizeof(env_from_buf))) {
			env_from = env_from_buf;
			seen_hdr = 1;
			continue;
		}

		if (!env_from && parse_return_path(buf, env_from_buf,
						   sizeof(env_from_buf))) {
			env_from = env_from_buf;
			seen_hdr = 1;
			continue;
		}

		if (!CLITCMP(buf, DCC_XHDR_TYPE_RECEIVED":")) {
			seen_hdr = 1;

			p2 = &buf[LITZ(DCC_XHDR_TYPE_RECEIVED":")];

			/* compute checksum of the last Received: header */
			get_cks(&cks, DCC_CK_RECEIVED, p2, 1);

			/* pick IP address out of Nth Received: header
			 * unless we had a good -a value */
			if (sender_set)
				continue;
			if (!std_received)
				continue;
			if (--std_received > 0)
				continue;

			p2 = parse_received(p2, &cks, helo, sizeof(helo),
					    sender_str, sizeof(sender_str),
					    sender_name, sizeof(sender_name));
			if (p2 == 0) {
				/* to avoid being fooled by forged Received:
				 * fields, do not skip unrecognized forms */
				std_received = 0;
			} else if (*p2 != '\0') {
				log_print(1, "skip %s Received: header\n", p2);
				std_received = 1;
			} else {
				std_received = check_mx_listing();
			}
			continue;
		}
		/* Notice MIME multipart boundary definitions */
		ck_mime_hdr(&cks, buf, 0);

		if (ck_get_sub(&cks, buf, 0))
			seen_hdr = 1;

		/* notice any sort of header */
		if (!seen_hdr) {
			for (p = buf; ; ++p) {
				if (*p == ':') {
					seen_hdr = 1;
					break;
				}
				if (*p <= ' ' || *p >= 0x7f)
					break;
			}
		}
	}

	// ending process early something went wrong
	if (end_process) {
		return -1;
	}

	/* Create a checksum for a null Message-ID header if there
	 * was no Message-ID header.  */
	if (cks.sums[DCC_CK_MESSAGE_ID].type != DCC_CK_MESSAGE_ID)
		get_cks(&cks, DCC_CK_MESSAGE_ID, "", 0);

	if (env_from) {
		get_cks(&cks, DCC_CK_ENV_FROM, env_from, 1);
		if (parse_mail_host(env_from, mail_host, sizeof(mail_host))) {
			ck_get_sub(&cks, "mail_host", mail_host);
			dcc_mail_host_dnsbl(cks.dlw, mail_host);
		}
	}
	/* collect the body */
	do {
		blen = fread(buf, 1, sizeof(buf), ifile);
		if (blen != sizeof(buf)) {
			if (!blen)
				break;
		}

		body_len += blen;
		ck_body(&cks, buf, blen);
	} while (!feof(ifile));
	fclose(ifile);

	cks_fin(&cks);
	const GOT_SUM *g;
	int inx;
	int csp=0;
	for (g = &cks.sums[inx = DCC_CK_TYPE_FIRST];
	     g <= LAST(cks.sums);
	     ++g) {
		/* ignore checksums we don't have */
		if (g->type == DCC_CK_INVALID)
			continue;
		sprintf(checksum+csp*42,"\"cs%02d\":\"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\",",
		  g->type,g->sum.b[0],g->sum.b[1],g->sum.b[2],g->sum.b[3],g->sum.b[4],g->sum.b[5],
		  g->sum.b[6],g->sum.b[7],g->sum.b[8],g->sum.b[9],g->sum.b[10],g->sum.b[11],
		  g->sum.b[12],g->sum.b[13],g->sum.b[14],g->sum.b[15]);
		++csp;

	}
	return csp*42;

}



static void
start_dccifd(void)
{
#ifndef DCC_WIN32
	time_t t;
	int c;
	pid_t pid;

	assert_info_locked();

	/* once an hour,
	 * start dccifd if dccproc is run more often than
	 * DCCPROC_MAX_CREDITS times at an average rate of at least
	 * DCCPROC_COST times per second */

	t = (ctxt->start.tv_sec/DCCPROC_COST
	     - dcc_clnt_info->dccproc_last/DCCPROC_COST);
	if (t > DCCPROC_MAX_CREDITS*2)	/* don't overflow */
		t = DCCPROC_MAX_CREDITS*2;
	else if (t < 0)
		t = 0;
	c = t + dcc_clnt_info->dccproc_c;
	if (c > DCCPROC_MAX_CREDITS)
		c = DCCPROC_MAX_CREDITS;
	--c;
	if (c < -DCCPROC_MAX_CREDITS)
		c = -DCCPROC_MAX_CREDITS;
	dcc_clnt_info->dccproc_c = c;
	dcc_clnt_info->dccproc_last = ctxt->start.tv_sec;

	if (dcc_clnt_info->dccproc_c >= 0)
		return;

	if (!DCC_IS_TIME(ctxt->start.tv_sec,
			 dcc_clnt_info->dccproc_dccifd_try,
			 DCCPROC_TRY_DCCIFD))
		return;
	dcc_clnt_info->dccproc_dccifd_try = (ctxt->start.tv_sec
					     + DCCPROC_TRY_DCCIFD);
	pid = fork();
	if (pid) {
		if (pid < 0)
			dccproc_error_msg("fork(): %s", ERROR_STR());
		return;
	}

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	dcc_clean_stdio();

	dcc_get_priv();
	if (0 > setuid(dcc_effective_uid))
		dccproc_error_msg("setuid(dcc_effective_uid): %s", ERROR_STR());
	if (0 > setgid(dcc_effective_gid))
		dccproc_error_msg("setgid(dcc_effective_gid): %s", ERROR_STR());

	dcc_trace_msg("try to start dccifd");
	execl(DCC_LIBEXECDIR"/start-dccifd",
	      "start-dccifd", "-A", (const char *)0);
	dcc_trace_msg("exec("DCC_LIBEXECDIR"/start-dccifd): %s", ERROR_STR());
	exit(0);
#endif /* DCC_WIN32 */
}



/* If the immediate SMTP client is a listed MX server,
 *	then we must ignore its IP address and keep looking for the
 *	real SMTP client. */
static u_char				/* 1=listed MX server */
check_mx_listing(void)
{
	DCC_TGTS tgts;

	if (!white_mx(&dcc_emsg, &tgts, &cks))
		dccproc_error_msg("%s", dcc_emsg.c);

	if (tgts == DCC_TGTS_OK) {
		/* do not tell the server about the IP address */
		no_ip_rpt2srvr(&cks);
		return 0;
	}

	if (tgts == DCC_TGTS_SUBMIT_CLIENT) {
		log_print(1, "%s is a listed 'submit' client\n",
			  dcc_trim_ffff(sender_str));
		/* do not tell the server about the IP address */
		no_ip_rpt2srvr(&cks);
		return 0;
	}

	if (tgts == DCC_TGTS_OK_MXDCC) {
		log_print(1, "%s is a whitelisted MX server with DCC client\n",
			  dcc_trim_ffff(sender_str));
		ask_st |= ASK_ST_QUERY;

	} else if (tgts == DCC_TGTS_OK_MX) {
		log_print(1, "%s is a whitelisted MX server\n",
			  dcc_trim_ffff(sender_str));

	} else {
		/* not listed */
		return 0;
	}

	no_ip_rpt2srvr(&cks);

	/* tell caller to look at the next Received: header */
	return 1;
}



/* get the next header line */
static int				/* header length */
get_hdr(char *buf,
	int buflen)			/* >HDR_CK_MAX*3 */
{
	u_char no_copy;
	int hlen, wpos;
	const char *line;
	char c;
	int llen, i;

	no_copy = 0;
	hlen = wpos = 0;
	for (;;) {
		line = fgets(&buf[hlen], buflen-hlen, ifile);
		if (!line) {
			//dcc_logbad(EX_DATAERR, "missing message body");
			end_process = 1;
			return hlen;
		}
		llen = strlen(line);

		/* delete our X-DCC header at the start of a field */
		if (hlen == 0 && !add_xhdr
		    && is_xhdr(buf, llen)) {
			seen_hdr = 1;
			no_copy = 1;
		}

		/* do not crash on too-long headers */
		hlen += llen;
		if (hlen > HDR_CK_MAX*2) {
			/* truncate headers too big for our buffer */
			if (!no_copy
			    && ((i = (hlen - wpos)) > 0)) {
				hdrs_len += i;
			}
			c = buf[hlen-1];
			hlen = HDR_CK_MAX;
			buf[hlen++] = '\r';
			buf[hlen++] = '\n';
			wpos = hlen;
			if (c != '\n')
				continue;
		}

		/* get the next character after the end-of-line to see if
		 * the next line is a continuation */
		if (hlen > 2) {
			i = getc(ifile);
			if (i != EOF)
				ungetc(i, ifile);
			if (i == ' ' || i == '\t')
				continue;
		}

		/* not a continuation, so stop reading the field */
		++total_hdrs;
		/* notice if this line ended with "\r\n" */
		if (hlen > 1 && buf[hlen-2] == '\r')
			++cr_hdrs;

		if (!no_copy) {
			i = hlen - wpos;
			if (i > 0) {
				hdrs_len += i;
			}
			return hlen;
		}

		/* at the end of our X-DCC header, look for another */
		no_copy = 0;
		hlen = wpos = 0;
	}
}




static void
log_write(const void *buf, int len)
{
	int i;

	if (lfd < 0)
		return;

	i = write(lfd, buf, len);
	if (i == len) {
		logging = 2;
		log_size += len;
	} else {
		dcc_error_msg("write(log %s): %s", log_path.c, ERROR_STR());
		dcc_log_close(0, log_path.c, lfd, &ldate);
		lfd = -1;
		logging = 0;
		log_path.c[0] = '\0';
	}
}



static void
log_body_write(const char *buf, u_int buflen)
{
	int trimlen;
	const char *p, *lim;

	if (lfd < 0)
		return;

	/* just write if there is room */
	trimlen = MAX_LOG_KBYTE*1024 - log_size;
	if (trimlen >= (int)buflen) {
		log_write(buf, buflen);
		return;
	}

	/* do nothing if too much already written */
	if (trimlen < 0)
		return;

	/* look for and end-of-line near the end of the buffer
	 * so that we can make the truncation pretty */
	lim = buf;
	p = lim+trimlen;
	if (trimlen > 90)
		lim += trimlen-90;
	while (--p > lim) {
		if (*p == '\n') {
			trimlen = p-buf+1;
			break;
		}
	}
	log_write(buf, trimlen);
	if (buf[trimlen-1] != '\n')
		LOG_EOL();
	LOG_CAPTION(DCC_LOG_TRN_MSG_CR);
	log_size = MAX_LOG_KBYTE*1024+1;
}



static void
thr_log_write(void *context DCC_UNUSED, const char *buf, u_int len)
{
	log_write(buf, len);
}



/* does not append '\n' */
static int
vlog_print(u_char error, const char *p, va_list args)
{
	char logbuf[LOGBUF_SIZE];
	int i;

	/* buffer the message if we cannot write to the log file */
	if (error &&  (lfd < 0 || !tmp_rewound))
		return vearly_log(&early_log, p, args);

	if (lfd < 0)
		return 0;
	i = vsnprintf(logbuf, sizeof(logbuf), p, args);
	if (i >= ISZ(logbuf))
		i = sizeof(logbuf)-1;
	log_write(logbuf, i);
	return i;
}



static void
log_late(void)
{
	if (early_log.len) {
		log_write(early_log.buf, early_log.len);
		early_log.len = 0;
	}
}



/* does not append '\n' */
static int DCC_PF(2,3)
log_print(u_char error, const char *p, ...)
{
	va_list args;
	int i;

	va_start(args, p);
	i = vlog_print(error, p, args);
	va_end(args);
	return i;
}



/* does not append '\n' */
int
thr_log_print(void *cp DCC_UNUSED, u_char error, const char *p, ...)
{
	va_list args;
	int i;

	va_start(args, p);
	i = vlog_print(error, p, args);
	va_end(args);
	return i;
}



static void
log_fin(void)
{
	if (log_path.c[0] == '\0')
		return;

	/* Close before renaming to accomodate WIN32 foolishness.
	 * Assuming dcc_mkstemp() works properly, there is no race */
	dcc_log_close(0, log_path.c, lfd, &ldate);
	lfd = -1;
	if (priv_logdir)
		dcc_get_priv_home(dcc_main_logdir.c);
	if (!(ask_st & ASK_ST_LOGIT)
	    || !dcc_log_keep(0, &log_path)) {
		if (0 > unlink(log_path.c))
			dccproc_error_msg("unlink(%s): %s",
					  log_path.c, ERROR_STR());
		log_path.c[0] = '\0';
	}
	if (priv_logdir)
		dcc_rel_priv();
}



static void
log_ck(void *arg DCC_UNUSED, const char *buf, u_int buf_len)
{
	log_write(buf, buf_len);
}



/* try to send error message to dccproc log file as well as sendmail */
static int
dccproc_verror_msg(const char *p, va_list args)
{
	char logbuf[LOGBUF_SIZE];

	/* Some systems including Linux with gcc 3.4.2 on AMD 64 processors
	 * do not allow two uses of a va_list but requires va_copy()
	 * Other systems do not have any notion of va_copy(). */
	if (vsnprintf(logbuf, sizeof(logbuf), p, args) >= ISZ(logbuf))
		strcpy(&logbuf[ISZ(logbuf)-sizeof("...")], "...");

	dcc_error_msg("%s", logbuf);

	ask_st |= ASK_ST_LOGIT;
	return log_print(1, "%s\n", logbuf);
}



/* try to send error message to dccproc log file as well as sendmail */
static void DCC_PF(1,2)
dccproc_error_msg(const char *p, ...)
{
	va_list args;

	va_start(args, p);
	dccproc_verror_msg(p, args);
	va_end(args);
}



int
thr_error_msg(void *cp DCC_UNUSED, const char *p, ...)
{
	va_list args;
	int i;

	va_start(args, p);
	i = dccproc_verror_msg(p, args);
	va_end(args);

	return i;
}



void
thr_trace_msg(void *cp DCC_UNUSED, const char *p, ...)
{
	va_list args;

	va_start(args, p);
	dccproc_verror_msg(p, args);
	va_end(args);
}



/* things are so sick that we must bail out */
void DCC_NORET
dcc_logbad(int ex_code, const char *p, ...)
{
	char buf[BUFSIZ];
	va_list args;
	size_t len;

	log_late();
	if (*p >= ' ' && !tmp_rewound) {
		va_start(args, p);
		dcc_vfatal_msg(p, args);
		va_end(args);

		ask_st |= ASK_ST_LOGIT;
		if (logging > 1)
			log_write("\n", 1);
		/* on some systems cannot use args twice after 1 va_start() */
		va_start(args, p);
		vlog_print(0, p, args);
		va_end(args);
		log_write("\n\n", 2);
		p = 0;
	}

	if (p && *p >= ' ') {
		va_start(args, p);
		dcc_vfatal_msg(p, args);
		va_end(args);

		log_write("\n\n", 2);
		va_start(args, p);
		vlog_print(0,p, args);
		va_end(args);
		log_write("\n", 1);
	}
	log_fin();

	if (ex_code == EX_SOFTWARE)
		abort();
	exit(EX_OK);			/* don't tell procmail to reject mail */
}



/* watch for fatal signals */
static void DCC_NORET
sigterm(int sig)
{
	log_fin();
	exit(-sig);
}
