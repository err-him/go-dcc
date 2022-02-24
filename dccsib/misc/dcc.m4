divert(-1)
#
# This feature causes sendmail to check with a local DCCM deamon about
# all incoming mail
#
# Use this file by copying it to your sendmail/cf/feature directory
# and by adding a line like the following to your sendmail.mc configuration
# file:
#	`FEATURE(dcc)'
#
# To change the default milter failture settings or timeouts as described
# in the sendmail milter README file, use something like:
#	`FEATURE(dcc,``F=T, T=C:30s;S:30s;R:30s;E:30s'')'
# The default parameters wait 30 seconds for the initial connection from
#   sendmail to dccm (C), 30 seconds sendmail sending (S) as well as receiving
#   responses (R) from dccm, and 30 seconds for dccm to check the message
#   at its end (E).
#   Adding "F=T" to the parameters cases sendmail to give SMTP clients
#   a temporary failure when dccm fails.  "F=R" causes sendmail to reject
#   mail when dccm fails.  When neither "F=T" nor "F=R" is present, sendmail
#   quietly accepts the message if dccm fails or is absent.
#   (A failure by dccm would be a serious bug.)
#   misc/hackmc changes the default to "F=T".
#
# To use common directories and whiteclnt files for mail relayed to domains
#   listed in /etc/mail/relay-domains, use a third argument as in
#	`FEATURE(dcc, , ``local'')'
#   If domain.com is in the relay-domains, file, then mail for all users
#   forwarded there will use userdirs/local/domain.com/whiteclnt and
#   userdirs/local/domain.com/log.
#
# To connect dccm to sendmail via TCP or use a UNIX domain socket
# other than /var/run/dcc/dccm, or other fancy changes, consider modifying
# this file or the resulting sendmail.cf file.
#
# See also /var/dcc/libexec/hackmc
#
# Generated automatically from dcc.m4.in by configure.


divert(0)
VERSIONID(`dcc.m4 Rhyolite Software DCC 1.3.163-1.15 $Revision$')
divert(-1)

ifdef(`_DCC_DEF_',`',`dnl
dnl define map to communicate blacklist results to DCC via dccm
define(_NEED_MACRO_MAP_,1)dnl
dnl set Xdcc milter parameters
define(`_DCC_DEF_', ifelse(len(X`'_ARG_), `1', ``, T=C:30s;S:30s;R:30s;E:30s'',
``,' _ARG_'))dnl
dnl Sendmail version 8.11 requires _FFR_MILTER
define(`_FFR_MILTER',`')dnl
dnl
dnl always pass the DCC is/notspam macros to not need FEATURE(`delay_checks')
define(`confMILTER_MACROS_ENVFROM',confMILTER_MACROS_ENVFROM``, {dcc_mail_host}'')dnl
define(`confMILTER_MACROS_ENVRCPT',confMILTER_MACROS_ENVRCPT``, {dcc_isspam}, {dcc_notspam}, {dcc_userdir}'')dnl
define(`confMILTER_MACROS_EOM',confMILTER_MACROS_EOM``, {dcc_isspam}, {dcc_notspam}'')dnl
INPUT_MAIL_FILTER(`dcc', ``S=unix:/var/run/dcc/dccm'_DCC_DEF_')'dnl
dnl
`LOCAL_RULESETS
# Define a macro for dccm that has the SMTP client host name even if
#   a smart relay is used.
#   This works only if ``FEATURE(delay_checks)'' is not used.
SLocal_check_mail
R$*			$: $1 $| $>canonify $1
R$* $| $* < @$* > $*	$: $1 $| $3
R$* $| $*		$: $1 $(macro {dcc_mail_host} $@ $2 $)'
ifelse(len(X`'_ARG2_), `1', ``dnl'',``
# use _ARG2_/domain.name/whiteclnt and _ARG2_/domain.name/log for the
#   DCC whitelist and log directory for relayed mail
SLocal_check_rcpt
R$*			$: $1 $| $>canonify $1
R$* $| $*<@ $*$=R .> $*	$: $1 $(macro {dcc_userdir} $@ _ARG2_/$4 $)
R$* $| $*<@ $ $=R > $*	$: $1 $(macro {dcc_userdir} $@ _ARG2_/$4 $)''))
