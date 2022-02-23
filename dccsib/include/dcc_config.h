/* Distributed Checksum Clearinghouse
 *
 * configuration settings
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
 * Rhyolite Software DCC 1.3.163-1.178 $Revision$
 * Generated automatically by configure
 */

#ifndef DCC_CONFIG_H
#define DCC_CONFIG_H

#define DCC_VERSION "1.3.163"
#define DCC_CONFIGURE " --disable-dccm"


#define DCC_UNIX 1
#undef DCC_WIN32			/* define DCC_WIN32 in the makefiles */
#if !defined(DCC_UNIX) && !defined(DCC_WIN32)
#error "you must run ./configure"
#endif

#define DCC_TARGET_SYS "Darwin"


#define DCC_HOMEDIR "/var/dcc"
#define DCC_LIBEXECDIR "/var/dcc/libexec"
#define DCC_RUNDIR "/var/run/dcc"

/* use kludge file if asked */
#undef HAVE_KLUDGE_H

#define DCC_LITTLE_ENDIAN 1

/* some systems have uint32_t, others have u_int32_t, and some have both
 * and then there is u_*int64_t */
#undef DCC_U_INT8_T
#undef DCC_U_INT16_T
#undef DCC_U_INT32_T
#undef DCC_U_INT64_T

/* 64-bit long int */
#define HAVE_64BIT_LONG 1

/* use %ll for 64-bit values */
#define DCC_USE_LL 1

#define HAVE_INTTYPES_H 1

/* 64-bit void* */
#define HAVE_64BIT_PTR 1

/* 64-bit time_t */
#define HAVE_64BIT_TIME_T 1

/* ./configure does not check for pid_t on the grounds that only WIN32
 * lacks it, and Windows is handled by the genbundle script */
#define HAVE_PID_T 1

/* maximum number of DCC server rate-limiting blocks */
#define DCC_RL_MAX 0

/* turn off dccifd AF_UNIX sockets on HP-UX */
#undef DCC_HP_UX_BAD_AF_UNIX

/* Use poll() instead of select() because socket() can yield file descripters
 * larger than FD_SETSIZE. */
#undef DCC_USE_POLL

/* number of cached open per-user whitelist files */
#define DCC_NUM_CWFS 20

#define DCC_TIME_WITH_SYS_TIME 1
#define HAVE_UTIME_H 1
#define HAVE_FUTIMES 1

#define HAVE_SETPGID 1

#define HAVE_GCC_ATTRIBUTES 1
#define HAVE_GCC_INLINE 1

/* fill holes in the target */
#define HAVE_DAEMON 1
#define HAVE_VSYSLOG 1
#define HAVE_HSTRERROR 1
#define HAVE_INET_NTOP 1
#define HAVE_INET_PTON 1
#define HAVE_INET_ATON 1
#define HAVE_GETHOSTID 1
#define HAVE_LOCALTIME_R 1
#define HAVE_GMTIME_R 1
#define HAVE_TIMEGM 1
#undef HAVE_EACCESS
#undef HAVE_ALTZONE
#define HAVE_BUILTIN_FFSL 1
#define HAVE_FFSL 1

#undef DCC_NEED_STRINGS_H
#define HAVE_STRLCPY 1
#define HAVE_STRLCAT 1

/* A way to get the size of physical memory
 *  Linux and Solaris have sysconf(_SC_PHYS_PAGES)
 *  BSD systems have sysctl(HW_PHYSMEM)
 *  HP-UX has pstat_getstatic() */
#undef HAVE_PHYSMEM_TOTAL
#define HAVE__SC_PHYS_PAGES 1
#undef HAVE_HW_PHYSMEM
#undef HAVE_PSTAT_GETSTATIC
#define DCC_HAVE_PHYSMEM 1
/* use `dbclean -F` on Solaris to force less unneeded disk I/O */
#undef DCC_USE_DBCLEAN_F

/* can assume the hash table is junk after a reboot */
#define HAVE_BOOTTIME 1


/* files with 64-bit offsets */
#define HAVE_BIG_FILES 1

/* 0 or minimum size of server database buffer or window */
#define DCC_DB_MIN_MBYTE 0
/* 0 or maximum size of server database buffer */
#define DCC_DB_MAX_MBYTE 0


/* 4.4BSD sockets */
#define HAVE_SOCKLEN_T 1
#define HAVE_SA_LEN 1
#define HAVE_IN_ADDR_T 1
#define HAVE_SA_FAMILY_T 1
#define HAVE_IN_PORT_T 1
#define HAVE_SIN6_SCOPE_ID 1
#define HAVE_AF_LOCAL 1
#define HAVE_AF_INET6 1

#define HAVE_GETADDRINFO 1
#define HAVE_GETNAMEINFO 1
#define HAVE_FREEADDRINFO 1
#define HAVE_GAI_STRERROR 1

#define HAVE_GETIPNODEBYNAME 1
#define HAVE_GETIPNODEBYADDR 1
#define HAVE_FREEHOSTENT 1

#undef DCC_NO_IPV6
#define DCC_CONF_S6_ADDR32 __u6_addr.__u6_addr32

#define DCC_GETIFADDRS_COMPAT DCC_GETIFADDRS_COMPAT_NATIVE
#define HAVE_GETIFADDRS 1
#define HAVE_FREEIFADDRS 1

/* BIND resolver library */
#define HAVE_RESOLV_H 1
#define HAVE_ARPA_NAMESER_H 1
#define HAVE__RES 1
#define HAVE_RES_INIT 1
#undef HAVE_BAD__RES
#define HAVE_RES_QUERY 1
#define HAVE_DN_EXPAND 1

/* Solaris and WIN32 do not have paths.h */
#define HAVE_PATHS_H 1

/* Some systems have their own MD5 libraries */
#undef HAVE_MD5

#define HAVE_SIGINTERRUPT 1

#define HAVE_PTHREADS 1
#define HAVE_PTHREAD_ATTR_SETSTACKSIZE 1

/* HP_UX has sys/pthread.h instead of pthread.h */
#define HAVE_PTHREAD_H 1

/* Windows systems lack UNIX permission bits */
#define HAVE_PRIVATE_FILES 1

/* __progname defined by crt0 and so a reasonable default for syslog */
#define HAVE___PROGNAME 1
/* slightly more portable way to get the program name */
#define HAVE_GETPROGNAME 1

/* very old BSD/OS has only 2 parameters for msync()
 * and newer versions ignore the third parameter */
#undef HAVE_OLD_MSYNC

#undef DCC_FSTATFS_COMPAT

/* use SOCKS */
#undef HAVE_RSENDTO

/* save only this much of mail messages in log files */
#define MAX_LOG_KBYTE 32

#define HAVE_EDITLINE 1

/* FUZ2 dictionaries */
#define DCC_LANG_ENGLISH 1
#define DCC_LANG_SPANISH 1
#define DCC_LANG_POLISH 1
#define DCC_LANG_DUTCH 1

#endif /* DCC_CONFIG_H */
