
/*  A Bison parser, made from parse.y
    by GNU Bison version 1.28  */

#define YYBISON 1  /* Identify Bison output.  */

#define	CREATE	257
#define	ADD	258
#define	PORT	259
#define	BIND	260
#define	CLONE	261
#define	DOT	262
#define	BLOCK	263
#define	OPEN	264
#define	RESET	265
#define	DEFAULT	266
#define	SET	267
#define	ACTION	268
#define	PERSONALITY	269
#define	RANDOM	270
#define	ANNOTATE	271
#define	NO	272
#define	FINSCAN	273
#define	FRAGMENT	274
#define	DROP	275
#define	OLD	276
#define	NEW	277
#define	COLON	278
#define	PROXY	279
#define	UPTIME	280
#define	DROPRATE	281
#define	IN	282
#define	SYN	283
#define	UID	284
#define	GID	285
#define	ROUTE	286
#define	ENTRY	287
#define	LINK	288
#define	NET	289
#define	UNREACH	290
#define	SLASH	291
#define	LATENCY	292
#define	MS	293
#define	LOSS	294
#define	BANDWIDTH	295
#define	SUBSYSTEM	296
#define	OPTION	297
#define	TO	298
#define	SHARED	299
#define	NETWORK	300
#define	SPOOF	301
#define	FROM	302
#define	TEMPLATE	303
#define	TUNNEL	304
#define	TARPIT	305
#define	DYNAMIC	306
#define	USE	307
#define	IF	308
#define	OTHERWISE	309
#define	EQUAL	310
#define	SOURCE	311
#define	OS	312
#define	IP	313
#define	BETWEEN	314
#define	DELETE	315
#define	LIST	316
#define	ETHERNET	317
#define	DHCP	318
#define	ON	319
#define	MAXFDS	320
#define	RESTART	321
#define	DEBUG	322
#define	DASH	323
#define	TIME	324
#define	INTERNAL	325
#define	STRING	326
#define	CMDSTRING	327
#define	IPSTRING	328
#define	NUMBER	329
#define	PROTO	330
#define	FLOAT	331

#line 7 "parse.y"

#include <sys/types.h>

#include "config.h"

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/tree.h>
#include <sys/queue.h>

#define _XOPEN_SOURCE /* glibc2 is stupid and needs this */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <pcap.h>
#include <dnet.h>

#include <event.h>

#include "honeyd.h"
#include "personality.h"
#include "router.h"
#include "plugins_config.h"
#include "plugins.h"
#include "template.h"
#include "condition.h"
#include "interface.h"
#include "ethernet.h"
#include "pfvar.h"
#include "dhcpclient.h"
#include "subsystem.h"
#include "util.h"
#ifdef HAVE_PYTHON
#include "pyextend.h"
#endif

int hydlex(void);
int hydparse(void);
int hyderror(char *, ...);
int hydwarn(char *, ...);
int hydprintf(char *, ...);
void *hyd_scan_string(char *);
int hyd_delete_buffer(void *);

#define yylex hydlex
#define yyparse hydparse
#define yy_scan_string hyd_scan_string
#define yy_delete_buffer hyd_delete_buffer
#define yyerror hyderror
#define yywarn hydwarn
#define yyprintf hydprintf
#define yyin hydin

extern int honeyd_verify_config;

pf_osfp_t pfctl_get_fingerprint(const char *);
struct action *honeyd_protocol(struct template *, int);
void port_action_clone(struct action *, struct action *);
static void dhcp_template(struct template *tmpl,
    char *interface, char *mac_addr);

static struct evbuffer *buffer = NULL;
int lineno;
char *filename;
int errors = 0;
int curtype = -1;	/* Lex sets it to SOCK_STREAM or _DGRAM */


#line 116 "parse.y"
typedef union {
	char *string;
	int number;
	struct link_drop drop;
	struct addr addr;
	struct action action;
	struct template *tmpl;
	struct personality *pers;
	struct addrinfo *ai;
	enum fragpolicy fragp;
	float floatp;
	struct condition condition;
	struct tm time;
	struct condition_time timecondition;
} YYSTYPE;
#include <stdio.h>

#ifndef __cplusplus
#ifndef __STDC__
#define const
#endif
#endif



#define	YYFINAL		208
#define	YYFLAG		-32768
#define	YYNTBASE	78

#define YYTRANSLATE(x) ((unsigned)(x) <= 331 ? yytranslate[x] : 108)

static const char yytranslate[] = {     0,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     1,     3,     4,     5,     6,
     7,     8,     9,    10,    11,    12,    13,    14,    15,    16,
    17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
    27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
    37,    38,    39,    40,    41,    42,    43,    44,    45,    46,
    47,    48,    49,    50,    51,    52,    53,    54,    55,    56,
    57,    58,    59,    60,    61,    62,    63,    64,    65,    66,
    67,    68,    69,    70,    71,    72,    73,    74,    75,    76,
    77
};

#if YYDEBUG != 0
static const short yyprhs[] = {     0,
     0,     1,     4,     7,    10,    13,    16,    19,    22,    25,
    28,    31,    34,    37,    40,    43,    46,    52,    59,    66,
    72,    79,    83,    88,    93,    98,   105,   109,   115,   121,
   129,   136,   141,   146,   151,   157,   163,   168,   173,   180,
   184,   188,   192,   198,   209,   218,   223,   228,   230,   233,
   236,   239,   242,   244,   246,   250,   254,   257,   260,   264,
   268,   274,   280,   286,   288,   290,   293,   295,   297,   299,
   301,   303,   305,   307,   309,   310,   314,   315,   318,   319,
   323,   326,   327,   335,   340,   345,   350,   356,   359,   363,
   367,   370,   374,   378,   382,   383,   385,   386,   388,   389,
   391,   396,   401,   406,   409,   411,   413,   418,   423
};

static const short yyrhs[] = {    -1,
    78,    79,     0,    78,    81,     0,    78,    80,     0,    78,
    82,     0,    78,    83,     0,    78,    84,     0,    78,    85,
     0,    78,    86,     0,    78,   100,     0,    78,   101,     0,
     3,    72,     0,     3,    49,     0,     3,    12,     0,    52,
    72,     0,    61,    93,     0,    61,    93,    76,     5,    75,
     0,     4,    93,    76,     5,    75,    92,     0,     4,    93,
    53,    93,    54,   105,     0,     4,    93,    55,    53,    93,
     0,     4,    93,    42,    73,   102,   103,     0,     6,    89,
    93,     0,     6,   105,    89,    93,     0,     6,    89,    44,
    72,     0,    64,    93,    65,    72,     0,    64,    93,    65,
    72,    63,    73,     0,     7,    72,    93,     0,    13,    93,
    47,    48,    89,     0,    13,    93,    47,    44,    89,     0,
    13,    93,    47,    48,    89,    44,    89,     0,    13,    93,
    12,    76,    14,    92,     0,    13,    93,    15,    94,     0,
    13,    93,    63,    73,     0,    13,    93,    26,    75,     0,
    13,    93,    27,    28,    95,     0,    13,    93,    27,    29,
    95,     0,    13,    93,    66,    75,     0,    13,    93,    30,
    75,     0,    13,    93,    30,    75,    31,    75,     0,    17,
    94,    87,     0,    17,    94,    88,     0,    32,    33,    89,
     0,    32,    33,    89,    46,    90,     0,    32,    89,     4,
    35,    90,    89,    96,    97,    98,    99,     0,    32,    89,
     4,    35,    90,    50,    89,    89,     0,    32,    89,    34,
    90,     0,    32,    89,    36,    90,     0,    19,     0,    18,
    19,     0,    20,    21,     0,    20,    22,     0,    20,    23,
     0,    74,     0,    73,     0,    89,    37,    75,     0,    89,
    24,    75,     0,   104,    72,     0,   104,    73,     0,   104,
    71,    73,     0,   104,    25,    91,     0,   104,    25,    72,
    24,    75,     0,   104,    25,    72,    24,    72,     0,   104,
    25,    89,    24,    72,     0,     9,     0,    11,     0,   104,
    10,     0,    72,     0,    49,     0,    12,     0,    89,     0,
    73,     0,    16,     0,    77,     0,    75,     0,     0,    38,
    75,    39,     0,     0,    40,    95,     0,     0,    41,    75,
    75,     0,    41,    75,     0,     0,    21,    60,    75,    39,
    69,    75,    39,     0,    43,    72,    72,    75,     0,    43,
    72,    72,    77,     0,    43,    72,    72,    72,     0,    43,
    72,    72,    37,    72,     0,    62,    49,     0,    62,    49,
    73,     0,    62,    49,    72,     0,    62,    42,     0,    62,
    42,    72,     0,    62,    42,    73,     0,    68,    72,    75,
     0,     0,    45,     0,     0,    67,     0,     0,    51,     0,
    57,    58,    56,    73,     0,    57,    59,    56,    89,     0,
    57,    59,    56,    90,     0,    70,   106,     0,    76,     0,
    55,     0,    60,   107,    69,   107,     0,    75,    24,    75,
    72,     0,    73,     0
};

#endif

#if YYDEBUG != 0
static const short yyrline[] = { 0,
   133,   134,   135,   136,   137,   138,   139,   140,   141,   142,
   143,   146,   152,   157,   162,   172,   177,   188,   207,   215,
   224,   241,   267,   291,   319,   325,   333,   340,   348,   356,
   366,   384,   390,   404,   410,   421,   432,   442,   453,   467,
   473,   480,   486,   492,   523,   536,   549,   564,   565,   567,
   568,   569,   571,   577,   597,   618,   630,   637,   647,   661,
   669,   695,   711,   726,   732,   738,   747,   754,   760,   766,
   773,   781,   788,   792,   797,   798,   803,   804,   809,   810,
   814,   819,   820,   829,   840,   851,   863,   879,   883,   891,
   895,   899,   903,   909,   929,   933,   939,   943,   949,   953,
   959,   972,   980,   988,   996,  1004,  1012,  1019,  1041
};
#endif


#if YYDEBUG != 0 || defined (YYERROR_VERBOSE)

static const char * const yytname[] = {   "$","error","$undefined.","CREATE",
"ADD","PORT","BIND","CLONE","DOT","BLOCK","OPEN","RESET","DEFAULT","SET","ACTION",
"PERSONALITY","RANDOM","ANNOTATE","NO","FINSCAN","FRAGMENT","DROP","OLD","NEW",
"COLON","PROXY","UPTIME","DROPRATE","IN","SYN","UID","GID","ROUTE","ENTRY","LINK",
"NET","UNREACH","SLASH","LATENCY","MS","LOSS","BANDWIDTH","SUBSYSTEM","OPTION",
"TO","SHARED","NETWORK","SPOOF","FROM","TEMPLATE","TUNNEL","TARPIT","DYNAMIC",
"USE","IF","OTHERWISE","EQUAL","SOURCE","OS","IP","BETWEEN","DELETE","LIST",
"ETHERNET","DHCP","ON","MAXFDS","RESTART","DEBUG","DASH","TIME","INTERNAL","STRING",
"CMDSTRING","IPSTRING","NUMBER","PROTO","FLOAT","config","creation","delete",
"addition","subsystem","binding","set","annotate","route","finscan","fragment",
"ipaddr","ipnet","ipaddrplusport","action","template","personality","rate","latency",
"packetloss","bandwidth","randomearlydrop","option","ui","shared","restart",
"flags","condition","timecondition","time", NULL
};
#endif

static const short yyr1[] = {     0,
    78,    78,    78,    78,    78,    78,    78,    78,    78,    78,
    78,    79,    79,    79,    79,    80,    80,    81,    81,    81,
    82,    83,    83,    83,    83,    83,    83,    83,    83,    83,
    84,    84,    84,    84,    84,    84,    84,    84,    84,    85,
    85,    86,    86,    86,    86,    86,    86,    87,    87,    88,
    88,    88,    89,    89,    90,    91,    92,    92,    92,    92,
    92,    92,    92,    92,    92,    92,    93,    93,    93,    93,
    94,    94,    95,    95,    96,    96,    97,    97,    98,    98,
    98,    99,    99,   100,   100,   100,   100,   101,   101,   101,
   101,   101,   101,   101,   102,   102,   103,   103,   104,   104,
   105,   105,   105,   105,   105,   105,   106,   107,   107
};

static const short yyr2[] = {     0,
     0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     5,     6,     6,     5,
     6,     3,     4,     4,     4,     6,     3,     5,     5,     7,
     6,     4,     4,     4,     5,     5,     4,     4,     6,     3,
     3,     3,     5,    10,     8,     4,     4,     1,     2,     2,
     2,     2,     1,     1,     3,     3,     2,     2,     3,     3,
     5,     5,     5,     1,     1,     2,     1,     1,     1,     1,
     1,     1,     1,     1,     0,     3,     0,     2,     0,     3,
     2,     0,     7,     4,     4,     4,     5,     2,     3,     3,
     2,     3,     3,     3,     0,     1,     0,     1,     0,     1,
     4,     4,     4,     2,     1,     1,     4,     4,     1
};

static const short yydefact[] = {     1,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     2,     4,     3,     5,     6,     7,
     8,     9,    10,    11,    14,    13,    12,    69,    68,    67,
    54,    53,    70,     0,   106,     0,     0,   105,     0,     0,
     0,     0,    72,    71,     0,     0,     0,     0,    15,    16,
    91,    88,     0,     0,     0,     0,     0,     0,     0,     0,
     0,   104,     0,    22,     0,    27,     0,     0,     0,     0,
     0,     0,     0,     0,     0,    48,     0,    40,    41,    42,
     0,     0,     0,     0,     0,    92,    93,    90,    89,     0,
    94,    95,     0,     0,     0,     0,     0,   109,     0,     0,
    24,    23,     0,    32,    34,     0,     0,    38,     0,     0,
    33,    37,    49,    50,    51,    52,     0,     0,     0,    46,
    47,     0,    86,    84,    85,     0,    25,    96,    97,     0,
    20,    99,   101,   102,   103,     0,     0,    99,    74,    73,
    35,    36,     0,    29,    28,    43,     0,     0,    87,    17,
     0,    98,    21,    19,    64,    65,   100,    18,     0,     0,
   107,    31,    39,     0,     0,    75,    55,    26,    66,     0,
     0,    57,    58,   108,    30,     0,     0,    77,     0,     0,
    60,    59,    45,     0,     0,    79,     0,     0,    76,    78,
     0,    82,    62,    61,    63,    56,    81,     0,    44,    80,
     0,     0,     0,     0,     0,    83,     0,     0
};

static const short yydefgoto[] = {     1,
    15,    16,    17,    18,    19,    20,    21,    22,    78,    79,
    33,   120,   181,   158,    34,    45,   141,   178,   186,   192,
   199,    23,    24,   129,   153,   159,    40,    62,   100
};

static const short yypact[] = {-32768,
    20,   -11,    13,    52,   -37,    13,   -13,   -16,   -28,     1,
    13,   -33,    13,     5,-32768,-32768,-32768,-32768,-32768,-32768,
-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
-32768,-32768,-32768,   -23,-32768,   -30,    35,-32768,     2,    56,
    13,    85,-32768,-32768,    29,    56,    30,    11,-32768,   -17,
    62,    66,    37,    33,    31,    13,    57,   122,    77,    80,
    26,-32768,    45,-32768,    13,-32768,    68,   -13,    67,   112,
    70,    23,    73,    72,   130,-32768,    69,-32768,-32768,   104,
   117,    56,    56,   -32,   148,-32768,-32768,-32768,-32768,    82,
-32768,   110,   102,    13,    83,    84,    56,-32768,   135,    93,
-32768,-32768,   149,-32768,-32768,    21,    21,   133,    56,    56,
-32768,-32768,-32768,-32768,-32768,-32768,    56,    56,   128,-32768,
-32768,    95,-32768,-32768,-32768,    94,   105,-32768,   103,    61,
-32768,    -1,-32768,   128,-32768,    96,    26,    -1,-32768,-32768,
-32768,-32768,    98,-32768,   131,-32768,   -19,    99,-32768,-32768,
   106,-32768,-32768,-32768,-32768,-32768,-32768,-32768,    -3,   108,
-32768,-32768,-32768,    56,    56,   138,-32768,-32768,-32768,    47,
   109,-32768,-32768,-32768,-32768,    56,   111,   137,   154,   157,
-32768,-32768,-32768,   144,    21,   143,   -60,   -54,-32768,-32768,
   113,   164,-32768,-32768,-32768,-32768,   114,   127,-32768,-32768,
   115,   152,   123,   118,   155,-32768,   195,-32768
};

static const short yypgoto[] = {-32768,
-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
    -4,     6,-32768,    58,     0,   129,  -105,-32768,-32768,-32768,
-32768,-32768,-32768,-32768,-32768,-32768,    71,-32768,    63
};


#define	YYLAST		201


static const short yytable[] = {    39,
    25,   142,    43,    47,   122,    42,   169,   155,    51,   156,
    50,   193,    53,    28,   194,    52,    46,   195,    55,   207,
   196,   170,     2,     3,    28,     4,     5,    59,    60,    56,
   165,    57,     6,    81,    41,    65,     7,    26,    64,   123,
    66,    80,   124,    48,   125,    63,    75,    76,    77,   157,
    29,     8,    58,    31,    32,    93,    31,    32,    85,    44,
    27,    29,     9,    82,   102,    83,   109,   171,   172,   173,
   110,    10,    49,    30,    31,    32,    54,   119,   119,   190,
    11,    12,    84,    13,    30,    31,    32,    14,   121,   114,
   115,   116,   134,   131,    61,   139,    67,   140,    98,    68,
    99,    90,   135,    92,   144,   145,    35,    91,    36,    94,
    69,    70,   119,   119,    71,    35,   101,    36,   179,    31,
    32,    37,   146,   147,    31,    32,    95,    38,    31,    32,
    37,    72,    96,    86,    87,    97,    38,    88,    89,   106,
   107,   105,   166,   103,   108,   111,   112,    73,   113,   117,
    74,   118,   126,   127,   128,   130,   133,   132,   136,   175,
   176,   137,   138,   143,   148,   180,   149,   151,   150,   152,
   160,   183,   163,   167,   164,   177,   185,   187,   168,   174,
   188,   182,   189,   191,   198,   184,   201,   197,   200,   202,
   203,   204,   205,   206,   208,   162,   104,     0,     0,   161,
   154
};

static const short yycheck[] = {     4,
    12,   107,    16,     8,    37,     6,    10,     9,    42,    11,
    11,    72,    13,    12,    75,    49,    33,    72,    42,     0,
    75,    25,     3,     4,    12,     6,     7,    58,    59,    53,
    50,    55,    13,     4,    72,    40,    17,    49,    39,    72,
    41,    46,    75,    72,    77,    44,    18,    19,    20,    51,
    49,    32,    76,    73,    74,    56,    73,    74,    76,    73,
    72,    49,    43,    34,    65,    36,    44,    71,    72,    73,
    48,    52,    72,    72,    73,    74,    72,    82,    83,   185,
    61,    62,    72,    64,    72,    73,    74,    68,    83,    21,
    22,    23,    97,    94,    60,    75,    12,    77,    73,    15,
    75,    65,    97,    73,   109,   110,    55,    75,    57,    53,
    26,    27,   117,   118,    30,    55,    72,    57,    72,    73,
    74,    70,   117,   118,    73,    74,     5,    76,    73,    74,
    70,    47,    56,    72,    73,    56,    76,    72,    73,    28,
    29,    75,   147,    76,    75,    73,    75,    63,    19,    46,
    66,    35,     5,    72,    45,    54,    73,    75,    24,   164,
   165,    69,    14,    31,    37,   170,    72,    63,    75,    67,
    75,   176,    75,    75,    44,    38,    40,    24,    73,    72,
    24,    73,    39,    41,    21,    75,    60,    75,    75,    75,
    39,    69,    75,    39,     0,   138,    68,    -1,    -1,   137,
   130
};
/* -*-C-*-  Note some compilers choke on comments on `#line' lines.  */
#line 3 "/usr/share/bison.simple"
/* This file comes from bison-1.28.  */

/* Skeleton output parser for bison,
   Copyright (C) 1984, 1989, 1990 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* This is the parser code that is written into each bison parser
  when the %semantic_parser declaration is not specified in the grammar.
  It was written by Richard Stallman by simplifying the hairy parser
  used when %semantic_parser is specified.  */

#ifndef YYSTACK_USE_ALLOCA
#ifdef alloca
#define YYSTACK_USE_ALLOCA
#else /* alloca not defined */
#ifdef __GNUC__
#define YYSTACK_USE_ALLOCA
#define alloca __builtin_alloca
#else /* not GNU C.  */
#if (!defined (__STDC__) && defined (sparc)) || defined (__sparc__) || defined (__sparc) || defined (__sgi) || (defined (__sun) && defined (__i386))
#define YYSTACK_USE_ALLOCA
#include <alloca.h>
#else /* not sparc */
/* We think this test detects Watcom and Microsoft C.  */
/* This used to test MSDOS, but that is a bad idea
   since that symbol is in the user namespace.  */
#if (defined (_MSDOS) || defined (_MSDOS_)) && !defined (__TURBOC__)
#if 0 /* No need for malloc.h, which pollutes the namespace;
	 instead, just don't use alloca.  */
#include <malloc.h>
#endif
#else /* not MSDOS, or __TURBOC__ */
#if defined(_AIX)
/* I don't know what this was needed for, but it pollutes the namespace.
   So I turned it off.   rms, 2 May 1997.  */
/* #include <malloc.h>  */
 #pragma alloca
#define YYSTACK_USE_ALLOCA
#else /* not MSDOS, or __TURBOC__, or _AIX */
#if 0
#ifdef __hpux /* haible@ilog.fr says this works for HPUX 9.05 and up,
		 and on HPUX 10.  Eventually we can turn this on.  */
#define YYSTACK_USE_ALLOCA
#define alloca __builtin_alloca
#endif /* __hpux */
#endif
#endif /* not _AIX */
#endif /* not MSDOS, or __TURBOC__ */
#endif /* not sparc */
#endif /* not GNU C */
#endif /* alloca not defined */
#endif /* YYSTACK_USE_ALLOCA not defined */

#ifdef YYSTACK_USE_ALLOCA
#define YYSTACK_ALLOC alloca
#else
#define YYSTACK_ALLOC malloc
#endif

/* Note: there must be only one dollar sign in this file.
   It is replaced by the list of actions, each action
   as one case of the switch.  */

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		-2
#define YYEOF		0
#define YYACCEPT	goto yyacceptlab
#define YYABORT 	goto yyabortlab
#define YYERROR		goto yyerrlab1
/* Like YYERROR except do call yyerror.
   This remains here temporarily to ease the
   transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */
#define YYFAIL		goto yyerrlab
#define YYRECOVERING()  (!!yyerrstatus)
#define YYBACKUP(token, value) \
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    { yychar = (token), yylval = (value);			\
      yychar1 = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { yyerror ("syntax error: cannot back up"); YYERROR; }	\
while (0)

#define YYTERROR	1
#define YYERRCODE	256

#ifndef YYPURE
#define YYLEX		yylex()
#endif

#ifdef YYPURE
#ifdef YYLSP_NEEDED
#ifdef YYLEX_PARAM
#define YYLEX		yylex(&yylval, &yylloc, YYLEX_PARAM)
#else
#define YYLEX		yylex(&yylval, &yylloc)
#endif
#else /* not YYLSP_NEEDED */
#ifdef YYLEX_PARAM
#define YYLEX		yylex(&yylval, YYLEX_PARAM)
#else
#define YYLEX		yylex(&yylval)
#endif
#endif /* not YYLSP_NEEDED */
#endif

/* If nonreentrant, generate the variables here */

#ifndef YYPURE

int	yychar;			/*  the lookahead symbol		*/
YYSTYPE	yylval;			/*  the semantic value of the		*/
				/*  lookahead symbol			*/

#ifdef YYLSP_NEEDED
YYLTYPE yylloc;			/*  location data for the lookahead	*/
				/*  symbol				*/
#endif

int yynerrs;			/*  number of parse errors so far       */
#endif  /* not YYPURE */

#if YYDEBUG != 0
int yydebug;			/*  nonzero means print parse trace	*/
/* Since this is uninitialized, it does not stop multiple parsers
   from coexisting.  */
#endif

/*  YYINITDEPTH indicates the initial size of the parser's stacks	*/

#ifndef	YYINITDEPTH
#define YYINITDEPTH 200
#endif

/*  YYMAXDEPTH is the maximum size the stacks can grow to
    (effective only if the built-in stack extension method is used).  */

#if YYMAXDEPTH == 0
#undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
#define YYMAXDEPTH 10000
#endif

/* Define __yy_memcpy.  Note that the size argument
   should be passed with type unsigned int, because that is what the non-GCC
   definitions require.  With GCC, __builtin_memcpy takes an arg
   of type size_t, but it can handle unsigned int.  */

#if __GNUC__ > 1		/* GNU C and GNU C++ define this.  */
#define __yy_memcpy(TO,FROM,COUNT)	__builtin_memcpy(TO,FROM,COUNT)
#else				/* not GNU C or C++ */
#ifndef __cplusplus

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__yy_memcpy (to, from, count)
     char *to;
     char *from;
     unsigned int count;
{
  register char *f = from;
  register char *t = to;
  register int i = count;

  while (i-- > 0)
    *t++ = *f++;
}

#else /* __cplusplus */

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__yy_memcpy (char *to, char *from, unsigned int count)
{
  register char *t = to;
  register char *f = from;
  register int i = count;

  while (i-- > 0)
    *t++ = *f++;
}

#endif
#endif

#line 217 "/usr/share/bison.simple"

/* The user can define YYPARSE_PARAM as the name of an argument to be passed
   into yyparse.  The argument should have type void *.
   It should actually point to an object.
   Grammar actions can access the variable by casting it
   to the proper pointer type.  */

#ifdef YYPARSE_PARAM
#ifdef __cplusplus
#define YYPARSE_PARAM_ARG void *YYPARSE_PARAM
#define YYPARSE_PARAM_DECL
#else /* not __cplusplus */
#define YYPARSE_PARAM_ARG YYPARSE_PARAM
#define YYPARSE_PARAM_DECL void *YYPARSE_PARAM;
#endif /* not __cplusplus */
#else /* not YYPARSE_PARAM */
#define YYPARSE_PARAM_ARG
#define YYPARSE_PARAM_DECL
#endif /* not YYPARSE_PARAM */

/* Prevent warning if -Wstrict-prototypes.  */
#ifdef __GNUC__
#ifdef YYPARSE_PARAM
int yyparse (void *);
#else
int yyparse (void);
#endif
#endif

int
yyparse(YYPARSE_PARAM_ARG)
     YYPARSE_PARAM_DECL
{
  register int yystate;
  register int yyn;
  register short *yyssp;
  register YYSTYPE *yyvsp;
  int yyerrstatus;	/*  number of tokens to shift before error messages enabled */
  int yychar1 = 0;		/*  lookahead token as an internal (translated) token number */

  short	yyssa[YYINITDEPTH];	/*  the state stack			*/
  YYSTYPE yyvsa[YYINITDEPTH];	/*  the semantic value stack		*/

  short *yyss = yyssa;		/*  refer to the stacks thru separate pointers */
  YYSTYPE *yyvs = yyvsa;	/*  to allow yyoverflow to reallocate them elsewhere */

#ifdef YYLSP_NEEDED
  YYLTYPE yylsa[YYINITDEPTH];	/*  the location stack			*/
  YYLTYPE *yyls = yylsa;
  YYLTYPE *yylsp;

#define YYPOPSTACK   (yyvsp--, yyssp--, yylsp--)
#else
#define YYPOPSTACK   (yyvsp--, yyssp--)
#endif

  int yystacksize = YYINITDEPTH;
  int yyfree_stacks = 0;

#ifdef YYPURE
  int yychar;
  YYSTYPE yylval;
  int yynerrs;
#ifdef YYLSP_NEEDED
  YYLTYPE yylloc;
#endif
#endif

  YYSTYPE yyval;		/*  the variable used to return		*/
				/*  semantic values from the action	*/
				/*  routines				*/

  int yylen;

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Starting parse\n");
#endif

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss - 1;
  yyvsp = yyvs;
#ifdef YYLSP_NEEDED
  yylsp = yyls;
#endif

/* Push a new state, which is found in  yystate  .  */
/* In all cases, when you get here, the value and location stacks
   have just been pushed. so pushing a state here evens the stacks.  */
yynewstate:

  *++yyssp = yystate;

  if (yyssp >= yyss + yystacksize - 1)
    {
      /* Give user a chance to reallocate the stack */
      /* Use copies of these so that the &'s don't force the real ones into memory. */
      YYSTYPE *yyvs1 = yyvs;
      short *yyss1 = yyss;
#ifdef YYLSP_NEEDED
      YYLTYPE *yyls1 = yyls;
#endif

      /* Get the current used size of the three stacks, in elements.  */
      int size = yyssp - yyss + 1;

#ifdef yyoverflow
      /* Each stack pointer address is followed by the size of
	 the data in use in that stack, in bytes.  */
#ifdef YYLSP_NEEDED
      /* This used to be a conditional around just the two extra args,
	 but that might be undefined if yyoverflow is a macro.  */
      yyoverflow("parser stack overflow",
		 &yyss1, size * sizeof (*yyssp),
		 &yyvs1, size * sizeof (*yyvsp),
		 &yyls1, size * sizeof (*yylsp),
		 &yystacksize);
#else
      yyoverflow("parser stack overflow",
		 &yyss1, size * sizeof (*yyssp),
		 &yyvs1, size * sizeof (*yyvsp),
		 &yystacksize);
#endif

      yyss = yyss1; yyvs = yyvs1;
#ifdef YYLSP_NEEDED
      yyls = yyls1;
#endif
#else /* no yyoverflow */
      /* Extend the stack our own way.  */
      if (yystacksize >= YYMAXDEPTH)
	{
	  yyerror("parser stack overflow");
	  if (yyfree_stacks)
	    {
	      free (yyss);
	      free (yyvs);
#ifdef YYLSP_NEEDED
	      free (yyls);
#endif
	    }
	  return 2;
	}
      yystacksize *= 2;
      if (yystacksize > YYMAXDEPTH)
	yystacksize = YYMAXDEPTH;
#ifndef YYSTACK_USE_ALLOCA
      yyfree_stacks = 1;
#endif
      yyss = (short *) YYSTACK_ALLOC (yystacksize * sizeof (*yyssp));
      __yy_memcpy ((char *)yyss, (char *)yyss1,
		   size * (unsigned int) sizeof (*yyssp));
      yyvs = (YYSTYPE *) YYSTACK_ALLOC (yystacksize * sizeof (*yyvsp));
      __yy_memcpy ((char *)yyvs, (char *)yyvs1,
		   size * (unsigned int) sizeof (*yyvsp));
#ifdef YYLSP_NEEDED
      yyls = (YYLTYPE *) YYSTACK_ALLOC (yystacksize * sizeof (*yylsp));
      __yy_memcpy ((char *)yyls, (char *)yyls1,
		   size * (unsigned int) sizeof (*yylsp));
#endif
#endif /* no yyoverflow */

      yyssp = yyss + size - 1;
      yyvsp = yyvs + size - 1;
#ifdef YYLSP_NEEDED
      yylsp = yyls + size - 1;
#endif

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Stack size increased to %d\n", yystacksize);
#endif

      if (yyssp >= yyss + yystacksize - 1)
	YYABORT;
    }

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Entering state %d\n", yystate);
#endif

  goto yybackup;
 yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* yychar is either YYEMPTY or YYEOF
     or a valid token in external form.  */

  if (yychar == YYEMPTY)
    {
#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Reading a token: ");
#endif
      yychar = YYLEX;
    }

  /* Convert token to internal form (in yychar1) for indexing tables with */

  if (yychar <= 0)		/* This means end of input. */
    {
      yychar1 = 0;
      yychar = YYEOF;		/* Don't call YYLEX any more */

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Now at end of input.\n");
#endif
    }
  else
    {
      yychar1 = YYTRANSLATE(yychar);

#if YYDEBUG != 0
      if (yydebug)
	{
	  fprintf (stderr, "Next token is %d (%s", yychar, yytname[yychar1]);
	  /* Give the individual parser a way to print the precise meaning
	     of a token, for further debugging info.  */
#ifdef YYPRINT
	  YYPRINT (stderr, yychar, yylval);
#endif
	  fprintf (stderr, ")\n");
	}
#endif
    }

  yyn += yychar1;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != yychar1)
    goto yydefault;

  yyn = yytable[yyn];

  /* yyn is what to do for this token type in this state.
     Negative => reduce, -yyn is rule number.
     Positive => shift, yyn is new state.
       New state is final state => don't bother to shift,
       just return success.
     0, or most negative number => error.  */

  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrlab;

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Shifting token %d (%s), ", yychar, yytname[yychar1]);
#endif

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;
#ifdef YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  /* count tokens shifted since error; after three, turn off error status.  */
  if (yyerrstatus) yyerrstatus--;

  yystate = yyn;
  goto yynewstate;

/* Do the default action for the current state.  */
yydefault:

  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;

/* Do a reduction.  yyn is the number of a rule to reduce with.  */
yyreduce:
  yylen = yyr2[yyn];
  if (yylen > 0)
    yyval = yyvsp[1-yylen]; /* implement default value of the action */

#if YYDEBUG != 0
  if (yydebug)
    {
      int i;

      fprintf (stderr, "Reducing via rule %d (line %d), ",
	       yyn, yyrline[yyn]);

      /* Print the symbols being reduced, and their result.  */
      for (i = yyprhs[yyn]; yyrhs[i] > 0; i++)
	fprintf (stderr, "%s ", yytname[yyrhs[i]]);
      fprintf (stderr, " -> %s\n", yytname[yyr1[yyn]]);
    }
#endif


  switch (yyn) {

case 12:
#line 147 "parse.y"
{
		if (template_create(yyvsp[0].string) == NULL)
			yyerror("Template \"%s\" exists already", yyvsp[0].string);
		free(yyvsp[0].string);
	;
    break;}
case 13:
#line 153 "parse.y"
{
		if (template_create("template") == NULL)
			yyerror("Template \"template\" exists already");
	;
    break;}
case 14:
#line 158 "parse.y"
{
		if (template_create("default") == NULL)
			yyerror("Template \"default\" exists already");
	;
    break;}
case 15:
#line 163 "parse.y"
{		
		struct template *tmpl;
		if ((tmpl = template_create(yyvsp[0].string)) == NULL)
			yyerror("Template \"%s\" exists already", yyvsp[0].string);
		tmpl->flags |= TEMPLATE_DYNAMIC;
		free(yyvsp[0].string);
	;
    break;}
case 16:
#line 173 "parse.y"
{
		if (yyvsp[0].tmpl != NULL)
			template_free(yyvsp[0].tmpl);
	;
    break;}
case 17:
#line 178 "parse.y"
{
		struct port *port;
		if ((port = port_find(yyvsp[-3].tmpl, yyvsp[-2].number, yyvsp[0].number)) == NULL) {
			yyerror("Cannot find port %d in \"%s\"",
			    yyvsp[0].number, yyvsp[-3].tmpl->name);
		} else {
			port_free(yyvsp[-3].tmpl, port);
		}
	;
    break;}
case 18:
#line 189 "parse.y"
{
		struct action *action;

		if (yyvsp[-4].tmpl == NULL) {
			yyerror("No template");
			break;
		}
		
		if ((action = honeyd_protocol(yyvsp[-4].tmpl, yyvsp[-3].number)) == NULL) {
			yyerror("Bad protocol");
			break;
		}
		if (yyvsp[-4].tmpl != NULL && template_add(yyvsp[-4].tmpl, yyvsp[-3].number, yyvsp[-1].number, &yyvsp[0].action) == -1)
			yyerror("Cannot add port %d to template \"%s\"",
			    yyvsp[-1].number, yyvsp[-4].tmpl != NULL ? yyvsp[-4].tmpl->name : "<unknown>");
		if (yyvsp[0].action.action)
			free(yyvsp[0].action.action);
	;
    break;}
case 19:
#line 208 "parse.y"
{	
		if (yyvsp[-4].tmpl == NULL || yyvsp[-2].tmpl == NULL)
			break;
		if (!(yyvsp[-4].tmpl->flags & TEMPLATE_DYNAMIC))
			yyerror("Cannot add templates to non-dynamic template \"%s\"", yyvsp[-4].tmpl->name);
		template_insert_dynamic(yyvsp[-4].tmpl, yyvsp[-2].tmpl, &yyvsp[0].condition);
	;
    break;}
case 20:
#line 216 "parse.y"
{	
		if (yyvsp[-3].tmpl == NULL || yyvsp[0].tmpl == NULL)
			break;
		if (!(yyvsp[-3].tmpl->flags & TEMPLATE_DYNAMIC))
			yyerror("Cannot add templates to non-dynamic template \"%s\"", yyvsp[-3].tmpl->name);
		template_insert_dynamic(yyvsp[-3].tmpl, yyvsp[0].tmpl, NULL);
	;
    break;}
case 21:
#line 225 "parse.y"
{
		int flags = 0;

		if (yyvsp[-1].number)
			flags |= SUBSYSTEM_SHARED;		
		if (yyvsp[0].number)
			flags |= SUBSYSTEM_RESTART;		

		yyvsp[-2].string[strlen(yyvsp[-2].string) - 1] = '\0';
		if (yyvsp[-4].tmpl != NULL &&
		    template_subsystem(yyvsp[-4].tmpl, yyvsp[-2].string+1, flags) == -1)
			yyerror("Can not add subsystem \"%s\" to template \"%s\"",
			    yyvsp[-2].string+1, yyvsp[-4].tmpl != NULL ? yyvsp[-4].tmpl->name : "<unknown>");
		free(yyvsp[-2].string);
	;
    break;}
case 22:
#line 242 "parse.y"
{
		/* Bind to an IP address and start subsystems */
		if (yyvsp[0].tmpl == NULL) {
			yyerror("Unknown template");
			break;
		}

		if (yyvsp[0].tmpl->ethernet_addr != NULL) {
			struct interface *inter;
			inter = interface_find_responsible(&yyvsp[-1].addr);
			if (inter == NULL ||
			    inter->if_ent.intf_link_addr.addr_type != ADDR_TYPE_ETH) {
				yyerror("Template \"%s\" is configured with "
				    "ethernet address but there is no "
				    "interface that can reach %s",
				    yyvsp[0].tmpl->name, addr_ntoa(&yyvsp[-1].addr));
				break;
			}
		}

		if (template_clone(addr_ntoa(&yyvsp[-1].addr), yyvsp[0].tmpl, NULL, 1) == NULL) {
			yyerror("Binding to %s failed", addr_ntoa(&yyvsp[-1].addr));
			break;
		}
	;
    break;}
case 23:
#line 268 "parse.y"
{
		struct template *tmpl;

		/* Special magic */
		if ((tmpl = template_find(addr_ntoa(&yyvsp[-1].addr))) != NULL) {
			if (!(tmpl->flags & TEMPLATE_DYNAMIC)) {
				yyerror("Template \"%s\" already specified as "
				    "non-dynamic template", addr_ntoa(&yyvsp[-1].addr));
				break;
			}
		} else if ((tmpl = template_create(addr_ntoa(&yyvsp[-1].addr))) == NULL) {
			yyerror("Could not create template \"%s\"",
			    addr_ntoa(&yyvsp[-1].addr));
			break;
		}
		tmpl->flags |= TEMPLATE_DYNAMIC;

		/* 
		 * Add this point we do have the right template.
		 * We just need to add the proper condition.
		 */
		template_insert_dynamic(tmpl, yyvsp[0].tmpl, &yyvsp[-2].condition);
	;
    break;}
case 24:
#line 292 "parse.y"
{
		struct interface *inter;
		struct template *tmpl;

		/* Bind an IP address to an external interface */
		if ((inter = interface_find(yyvsp[0].string)) == NULL) {
			yyerror("Interface \"%s\" does not exist.", yyvsp[0].string);
			free(yyvsp[0].string);
			break;
		}
		if (inter->if_ent.intf_link_addr.addr_type != ADDR_TYPE_ETH) {
			yyerror("Interface \"%s\" does not support ARP.", yyvsp[0].string);
			free(yyvsp[0].string);
			break;
		}

		if ((tmpl = template_create(addr_ntoa(&yyvsp[-2].addr))) == NULL) {
			yyerror("Template \"%s\" exists already",
			    addr_ntoa(&yyvsp[-2].addr));
			break;
		}

		/* Make this template external. */
		tmpl->flags |= TEMPLATE_EXTERNAL;
		tmpl->inter = inter;
		free(yyvsp[0].string);
	;
    break;}
case 25:
#line 320 "parse.y"
{		
		/* Automagically assign DHCP address */
		dhcp_template(yyvsp[-2].tmpl, yyvsp[0].string, NULL);
		free(yyvsp[0].string);
	;
    break;}
case 26:
#line 326 "parse.y"
{		
		/* Automagically assign DHCP address with MAC address */
		yyvsp[0].string[strlen(yyvsp[0].string) - 1] = '\0';
		dhcp_template(yyvsp[-4].tmpl, yyvsp[-2].string, yyvsp[0].string + 1);
		free(yyvsp[-2].string);
		free(yyvsp[0].string);
	;
    break;}
case 27:
#line 334 "parse.y"
{
		/* Just clone.  This is not the final destination yet */
		if (yyvsp[0].tmpl == NULL || template_clone(yyvsp[-1].string, yyvsp[0].tmpl, NULL, 0) == NULL)
			yyerror("Cloning to %s failed", yyvsp[-1].string);
		free(yyvsp[-1].string);
	;
    break;}
case 28:
#line 341 "parse.y"
{
		if (yyvsp[-3].tmpl == NULL) {
			yyerror("No template");
			break;
		}
		yyvsp[-3].tmpl->spoof.new_src = yyvsp[0].addr;
	;
    break;}
case 29:
#line 349 "parse.y"
{
		if (yyvsp[-3].tmpl == NULL) {
			yyerror("No template");
			break;
		}
		yyvsp[-3].tmpl->spoof.new_dst = yyvsp[0].addr;
	;
    break;}
case 30:
#line 357 "parse.y"
{
		if (yyvsp[-5].tmpl == NULL) {
			yyerror("No template");
			break;
		}
		yyvsp[-5].tmpl->spoof.new_src = yyvsp[-2].addr;
		yyvsp[-5].tmpl->spoof.new_dst = yyvsp[0].addr;
	;
    break;}
case 31:
#line 367 "parse.y"
{
		struct action *action;

		if (yyvsp[-4].tmpl == NULL) {
			yyerror("No template");
			break;
		}
		
		if ((action = honeyd_protocol(yyvsp[-4].tmpl, yyvsp[-2].number)) == NULL) {
			yyerror("Bad protocol");
			break;
		}

		port_action_clone(action, &yyvsp[0].action);
		if (yyvsp[0].action.action != NULL)
			free(yyvsp[0].action.action);
	;
    break;}
case 32:
#line 385 "parse.y"
{
		if (yyvsp[-2].tmpl == NULL || yyvsp[0].pers == NULL)
			break;
		yyvsp[-2].tmpl->person = personality_clone(yyvsp[0].pers);
	;
    break;}
case 33:
#line 391 "parse.y"
{
		extern int need_arp;
		if (yyvsp[-2].tmpl == NULL || yyvsp[0].string == NULL)
			break;
		yyvsp[0].string[strlen(yyvsp[0].string) - 1] = '\0';
		yyvsp[-2].tmpl->ethernet_addr = ethernetcode_make_address(yyvsp[0].string + 1);
		if (yyvsp[-2].tmpl->ethernet_addr == NULL) {
			yyerror("Unknown ethernet vendor \"%s\"", yyvsp[0].string + 1);
		}
		free (yyvsp[0].string);

		need_arp = 1;
	;
    break;}
case 34:
#line 405 "parse.y"
{
		if (yyvsp[-2].tmpl == NULL || yyvsp[0].number == 0)
			break;
		yyvsp[-2].tmpl->timestamp = yyvsp[0].number * 2;
	;
    break;}
case 35:
#line 411 "parse.y"
{
		if (yyvsp[-3].tmpl == NULL)
			break;
		if (yyvsp[0].floatp > 100) {
			yyerror("Droprate too high: %f", yyvsp[0].floatp);
			break;
		}

		yyvsp[-3].tmpl->drop_inrate = yyvsp[0].floatp * 100;
	;
    break;}
case 36:
#line 422 "parse.y"
{
		if (yyvsp[-3].tmpl == NULL)
			break;
		if (yyvsp[0].floatp > 100) {
			yyerror("Droprate too high: %f", yyvsp[0].floatp);
			break;
		}

		yyvsp[-3].tmpl->drop_synrate = yyvsp[0].floatp * 100;
	;
    break;}
case 37:
#line 433 "parse.y"
{
		if (yyvsp[-2].tmpl == NULL)
			break;
		if (yyvsp[0].number <= 3) {
			yyerror("Bad number of max file descriptors %d", yyvsp[0].number);
			break;
		}
		yyvsp[-2].tmpl->max_nofiles = yyvsp[0].number;
	;
    break;}
case 38:
#line 443 "parse.y"
{
		if (yyvsp[-2].tmpl == NULL)
			break;
		if (!yyvsp[0].number) {
			yyerror("Bad uid %d", yyvsp[0].number);
			break;
		}
		yyvsp[-2].tmpl->uid = yyvsp[0].number;
		honeyd_use_uid(yyvsp[0].number);
	;
    break;}
case 39:
#line 454 "parse.y"
{
		if (yyvsp[-4].tmpl == NULL)
			break;
		if (!yyvsp[-2].number || !yyvsp[0].number) {
			yyerror("Bad uid %d, gid %d", yyvsp[-2].number, yyvsp[0].number);
			break;
		}
		yyvsp[-4].tmpl->uid = yyvsp[-2].number;
		yyvsp[-4].tmpl->gid = yyvsp[0].number;
		honeyd_use_uid(yyvsp[-2].number);
		honeyd_use_gid(yyvsp[0].number);
	;
    break;}
case 40:
#line 468 "parse.y"
{
		if (yyvsp[-1].pers == NULL)
			break;
		yyvsp[-1].pers->disallow_finscan = !yyvsp[0].number;
	;
    break;}
case 41:
#line 474 "parse.y"
{
		if (yyvsp[-1].pers == NULL)
			break;
		yyvsp[-1].pers->fragp = yyvsp[0].fragp;
	;
    break;}
case 42:
#line 481 "parse.y"
{
		if (router_start(&yyvsp[0].addr, NULL) == -1)
			yyerror("Defining entry point failed: %s",
			    addr_ntoa(&yyvsp[0].addr));
	;
    break;}
case 43:
#line 487 "parse.y"
{
		if (router_start(&yyvsp[-2].addr, &yyvsp[0].addr) == -1)
			yyerror("Defining entry point failed: %s",
			    addr_ntoa(&yyvsp[-2].addr));
	;
    break;}
case 44:
#line 493 "parse.y"
{
		struct router *r, *newr;
		struct addr defroute;

		if ((r = router_find(&yyvsp[-8].addr)) == NULL &&
		    (r = router_new(&yyvsp[-8].addr)) == NULL) {
			yyerror("Cannot make forward reference for router %s",
			    addr_ntoa(&yyvsp[-8].addr));
			break;
		}
		if ((newr = router_find(&yyvsp[-4].addr)) == NULL)
			newr = router_new(&yyvsp[-4].addr);
		if (router_add_net(r, &yyvsp[-5].addr, newr, yyvsp[-3].number, yyvsp[-2].number, yyvsp[-1].number, &yyvsp[0].drop) == -1)
			yyerror("Could not add route to %s", addr_ntoa(&yyvsp[-5].addr));

		if (yyvsp[-1].number == 0 && yyvsp[0].drop.high != 0)
			yywarn("Ignoring drop between statement without "
			       "specified bandwidth.");

		addr_pton("0.0.0.0/0", &defroute);
		defroute.addr_bits = 0; /* work around libdnet bug */

		/* Only insert a reverse route, if the current route is
		 * not the default route.
		 */
		if (addr_cmp(&defroute, &yyvsp[-5].addr) != 0 &&
		    router_add_net(newr, &defroute, r, yyvsp[-3].number, yyvsp[-2].number, yyvsp[-1].number, &yyvsp[0].drop) == -1)
			yyerror("Could not add default route to %s",
			    addr_ntoa(&yyvsp[-5].addr));
	;
    break;}
case 45:
#line 524 "parse.y"
{
		struct router *r;

		if ((r = router_find(&yyvsp[-6].addr)) == NULL &&
		    (r = router_new(&yyvsp[-6].addr)) == NULL) {
			yyerror("Cannot make forward reference for router %s",
			    addr_ntoa(&yyvsp[-6].addr));
			break;
		}
		if (router_add_tunnel(r, &yyvsp[-3].addr, &yyvsp[-1].addr, &yyvsp[0].addr) == -1)
			yyerror("Could not add tunnel to %s", addr_ntoa(&yyvsp[0].addr));
	;
    break;}
case 46:
#line 537 "parse.y"
{
		struct router *r;

		if ((r = router_find(&yyvsp[-2].addr)) == NULL &&
		    (r = router_new(&yyvsp[-2].addr)) == NULL) {
			yyerror("Cannot make forward reference for router %s",
			    addr_ntoa(&yyvsp[-2].addr));
			break;
		}
		if (router_add_link(r, &yyvsp[0].addr) == -1)
			yyerror("Could not add link %s", addr_ntoa(&yyvsp[0].addr));
	;
    break;}
case 47:
#line 550 "parse.y"
{
		struct router *r;

		if ((r = router_find(&yyvsp[-2].addr)) == NULL &&
		    (r = router_new(&yyvsp[-2].addr)) == NULL) {
			yyerror("Cannot make forward reference for router %s",
			    addr_ntoa(&yyvsp[-2].addr));
			break;
		}
		if (router_add_unreach(r, &yyvsp[0].addr) == -1)
			yyerror("Could not add unreachable net %s",
			    addr_ntoa(&yyvsp[0].addr));
	;
    break;}
case 48:
#line 564 "parse.y"
{ yyval.number = 1; ;
    break;}
case 49:
#line 565 "parse.y"
{ yyval.number = 0; ;
    break;}
case 50:
#line 567 "parse.y"
{ yyval.fragp = FRAG_DROP; ;
    break;}
case 51:
#line 568 "parse.y"
{ yyval.fragp = FRAG_OLD; ;
    break;}
case 52:
#line 569 "parse.y"
{ yyval.fragp = FRAG_NEW; ;
    break;}
case 53:
#line 572 "parse.y"
{
		if (addr_pton(yyvsp[0].string, &yyval.addr) < 0)
			yyerror("Illegal IP address %s", yyvsp[0].string);
		free(yyvsp[0].string);
	;
    break;}
case 54:
#line 578 "parse.y"
{
		struct addrinfo ai, *aitop;

		memset(&ai, 0, sizeof (ai));
		ai.ai_family = AF_INET;
		ai.ai_socktype = 0;
		ai.ai_flags = 0;

		/* Remove quotation marks */
		yyvsp[0].string[strlen(yyvsp[0].string) - 1] = '\0';
		if (getaddrinfo(yyvsp[0].string+1, NULL, &ai, &aitop) != 0) {
			yyerror("getaddrinfo failed: %s", yyvsp[0].string+1);
			break;
		}
		addr_ston(aitop->ai_addr, &yyval.addr);
		freeaddrinfo(aitop);
		free(yyvsp[0].string);
	;
    break;}
case 55:
#line 598 "parse.y"
{
		char src[25];
		struct addr b;
		snprintf(src, sizeof(src), "%s/%d",
		    addr_ntoa(&yyvsp[-2].addr), yyvsp[0].number);
		if (addr_pton(src, &yyval.addr) < 0)
			yyerror("Illegal IP network %s", src);
		/* Fix libdnet error */
		if (yyvsp[0].number == 0)
			yyval.addr.addr_bits = 0;

		/* Test if this is a legal network */
		addr_net(&yyval.addr, &b);
		b.addr_bits = yyval.addr.addr_bits;
		if (memcmp(&yyval.addr.addr_ip, &b.addr_ip, IP_ADDR_LEN)) {
			yyval.addr = b;
			yywarn("Bad network mask in %s", src);
		}
	;
    break;}
case 56:
#line 619 "parse.y"
{
		if (curtype == -1) {
			yyerror("Bad port type");
			break;
		}
		yyval.ai = cmd_proxy_getinfo(addr_ntoa(&yyvsp[-2].addr), curtype, yyvsp[0].number);
		curtype = -1;
		if (yyval.ai == NULL)
			yyerror("Illegal IP address port pair");
	;
    break;}
case 57:
#line 631 "parse.y"
{
		memset(&yyval.action, 0, sizeof(yyval.action));
		yyval.action.action = yyvsp[0].string;
		yyval.action.flags = yyvsp[-1].number;
		yyval.action.status = PORT_OPEN;
	;
    break;}
case 58:
#line 638 "parse.y"
{
		memset(&yyval.action, 0, sizeof(yyval.action));
		yyvsp[0].string[strlen(yyvsp[0].string) - 1] = '\0';
		if ((yyval.action.action = strdup(yyvsp[0].string + 1)) == NULL)
			yyerror("Out of memory");
		yyval.action.status = PORT_OPEN;
		yyval.action.flags = yyvsp[-1].number;
		free(yyvsp[0].string);
	;
    break;}
case 59:
#line 648 "parse.y"
{
#ifdef HAVE_PYTHON
		memset(&yyval.action, 0, sizeof(yyval.action));
		yyvsp[0].string[strlen(yyvsp[0].string) - 1] = '\0';
		if ((yyval.action.action_extend = pyextend_load_module(yyvsp[0].string+1)) == NULL)
			yyerror("Bad python module: \"%s\"", yyvsp[0].string+1);
		yyval.action.status = PORT_PYTHON;
		yyval.action.flags = yyvsp[-2].number;
		free(yyvsp[0].string);
#else
		yyerror("Python support is not available.");
#endif
	;
    break;}
case 60:
#line 662 "parse.y"
{
		memset(&yyval.action, 0, sizeof(yyval.action));
		yyval.action.status = PORT_PROXY;
		yyval.action.action = NULL;
		yyval.action.aitop = yyvsp[0].ai;
		yyval.action.flags = yyvsp[-2].number;
	;
    break;}
case 61:
#line 670 "parse.y"
{
		memset(&yyval.action, 0, sizeof(yyval.action));
		yyval.action.status = PORT_PROXY;
		yyval.action.action = NULL;
		yyval.action.aitop = NULL;
		yyval.action.flags = yyvsp[-4].number;
		if (yyvsp[-2].string[0] != '$') {
			if (curtype == -1) {
				yyerror("Bad port type");
				break;
			}
			yyval.action.aitop = cmd_proxy_getinfo(yyvsp[-2].string, curtype, yyvsp[0].number);
			curtype = -1;
			if (yyval.action.aitop == NULL)
				yyerror("Illegal host name in proxy");
		} else {
			char proxy[1024];

			snprintf(proxy, sizeof(proxy), "%s:%d", yyvsp[-2].string, yyvsp[0].number);
			yyval.action.action = strdup(proxy);
			if (yyval.action.action == NULL)
				yyerror("Out of memory");
		}
		free(yyvsp[-2].string);
	;
    break;}
case 62:
#line 696 "parse.y"
{
		char proxy[1024];
		memset(&yyval.action, 0, sizeof(yyval.action));
		yyval.action.status = PORT_PROXY;
		yyval.action.action = NULL;
		yyval.action.aitop = NULL;
		yyval.action.flags = yyvsp[-4].number;

		snprintf(proxy, sizeof(proxy), "%s:%s", yyvsp[-2].string, yyvsp[0].string);
		yyval.action.action = strdup(proxy);
		if (yyval.action.action == NULL)
				yyerror("Out of memory");
		free(yyvsp[-2].string);
		free(yyvsp[0].string);
	;
    break;}
case 63:
#line 712 "parse.y"
{
		char proxy[1024];
		memset(&yyval.action, 0, sizeof(yyval.action));
		yyval.action.status = PORT_PROXY;
		yyval.action.action = NULL;
		yyval.action.aitop = NULL;
		yyval.action.flags = yyvsp[-4].number;

		snprintf(proxy, sizeof(proxy), "%s:%s", addr_ntoa(&yyvsp[-2].addr), yyvsp[0].string);
		yyval.action.action = strdup(proxy);
		if (yyval.action.action == NULL)
				yyerror("Out of memory");
		free(yyvsp[0].string);
	;
    break;}
case 64:
#line 727 "parse.y"
{
		memset(&yyval.action, 0, sizeof(yyval.action));
		yyval.action.status = PORT_BLOCK;
		yyval.action.action = NULL;
	;
    break;}
case 65:
#line 733 "parse.y"
{
		memset(&yyval.action, 0, sizeof(yyval.action));
		yyval.action.status = PORT_RESET;
		yyval.action.action = NULL;
	;
    break;}
case 66:
#line 739 "parse.y"
{
		memset(&yyval.action, 0, sizeof(yyval.action));
		yyval.action.status = PORT_OPEN;
		yyval.action.action = NULL;
		yyval.action.flags = yyvsp[-1].number;
	;
    break;}
case 67:
#line 748 "parse.y"
{
		yyval.tmpl = template_find(yyvsp[0].string);
		if (yyval.tmpl == NULL)
			yyerror("Unknown template \"%s\"", yyvsp[0].string);
		free(yyvsp[0].string);
	;
    break;}
case 68:
#line 755 "parse.y"
{
		yyval.tmpl = template_find("template");
		if (yyval.tmpl == NULL)
			yyerror("Unknown template \"%s\"", "template");
	;
    break;}
case 69:
#line 761 "parse.y"
{
		yyval.tmpl = template_find("default");
		if (yyval.tmpl == NULL)
			yyerror("Unknown template \"%s\"", "default");
	;
    break;}
case 70:
#line 767 "parse.y"
{
		yyval.tmpl = template_find(addr_ntoa(&yyvsp[0].addr));
		if (yyval.tmpl == NULL)
			yyerror("Unknown template \"%s\"", addr_ntoa(&yyvsp[0].addr));
	;
    break;}
case 71:
#line 774 "parse.y"
{
		yyvsp[0].string[strlen(yyvsp[0].string) - 1] = '\0';
		yyval.pers = personality_find(yyvsp[0].string+1);
		if (yyval.pers == NULL)
			yyerror("Unknown personality \"%s\"", yyvsp[0].string+1);
		free(yyvsp[0].string);
	;
    break;}
case 72:
#line 782 "parse.y"
{
		yyval.pers = personality_random();
		if (yyval.pers == NULL)
			yyerror("Random personality failed");
	;
    break;}
case 73:
#line 789 "parse.y"
{
		yyval.floatp = yyvsp[0].floatp;
	;
    break;}
case 74:
#line 793 "parse.y"
{
		yyval.floatp = yyvsp[0].number;
	;
    break;}
case 75:
#line 797 "parse.y"
{ yyval.number = 0; ;
    break;}
case 76:
#line 799 "parse.y"
{
		yyval.number = yyvsp[-1].number;
	;
    break;}
case 77:
#line 803 "parse.y"
{ yyval.number = 0; ;
    break;}
case 78:
#line 805 "parse.y"
{
		yyval.number = yyvsp[0].floatp * 100;
	;
    break;}
case 79:
#line 809 "parse.y"
{ yyval.number = 0; ;
    break;}
case 80:
#line 811 "parse.y"
{
		yyval.number = yyvsp[-1].number * yyvsp[0].number;
	;
    break;}
case 81:
#line 815 "parse.y"
{
		yyval.number = yyvsp[0].number;
	;
    break;}
case 82:
#line 819 "parse.y"
{ memset(&yyval.drop, 0, sizeof(yyval.drop)); ;
    break;}
case 83:
#line 821 "parse.y"
{
		if (yyvsp[-1].number <= yyvsp[-4].number)
			yyerror("Incorrect thresholds. First number needs to "
				"be smaller than second number.");
		yyval.drop.low = yyvsp[-4].number;
		yyval.drop.high = yyvsp[-1].number;
	;
    break;}
case 84:
#line 830 "parse.y"
{
		struct honeyd_plugin_cfg cfg;

		memset(&cfg, 0, sizeof(struct honeyd_plugin_cfg));
		cfg.cfg_int = yyvsp[0].number;
		cfg.cfg_type = HD_CONFIG_INT;
		plugins_config_item_add(yyvsp[-2].string, yyvsp[-1].string, &cfg);
		
		free(yyvsp[-2].string); free(yyvsp[-1].string);
	;
    break;}
case 85:
#line 841 "parse.y"
{
		struct honeyd_plugin_cfg cfg;

		memset(&cfg, 0, sizeof(struct honeyd_plugin_cfg));
		cfg.cfg_flt = yyvsp[0].floatp;
		cfg.cfg_type = HD_CONFIG_FLT;
		plugins_config_item_add(yyvsp[-2].string, yyvsp[-1].string, &cfg);

		free(yyvsp[-2].string); free(yyvsp[-1].string);
        ;
    break;}
case 86:
#line 852 "parse.y"
{
		struct honeyd_plugin_cfg cfg;

		memset(&cfg, 0, sizeof(struct honeyd_plugin_cfg));
		cfg.cfg_str = yyvsp[0].string;
		cfg.cfg_type = HD_CONFIG_STR;
		plugins_config_item_add(yyvsp[-2].string, yyvsp[-1].string, &cfg);

		free(yyvsp[-2].string); free(yyvsp[-1].string); free(yyvsp[0].string);
        ;
    break;}
case 87:
#line 864 "parse.y"
{
		struct honeyd_plugin_cfg cfg;
		char path[MAXPATHLEN];

		snprintf(path, sizeof(path), "/%s", yyvsp[0].string);

		memset(&cfg, 0, sizeof(struct honeyd_plugin_cfg));
		cfg.cfg_str = path;
		cfg.cfg_type = HD_CONFIG_STR;
		plugins_config_item_add(yyvsp[-3].string, yyvsp[-2].string, &cfg);

		free(yyvsp[-3].string); free(yyvsp[-2].string); free(yyvsp[0].string);
        ;
    break;}
case 88:
#line 880 "parse.y"
{
	template_list_glob(buffer, "*");
;
    break;}
case 89:
#line 884 "parse.y"
{
	yyvsp[0].string[strlen(yyvsp[0].string)-1] = '\0';

	template_list_glob(buffer, yyvsp[0].string+1);

	free (yyvsp[0].string);
;
    break;}
case 90:
#line 892 "parse.y"
{
	template_list_glob(buffer, yyvsp[0].string);
;
    break;}
case 91:
#line 896 "parse.y"
{
	template_subsystem_list_glob(buffer, "*");
;
    break;}
case 92:
#line 900 "parse.y"
{
	template_subsystem_list_glob(buffer, yyvsp[0].string);
;
    break;}
case 93:
#line 904 "parse.y"
{
	yyvsp[0].string[strlen(yyvsp[0].string)-1] = '\0';
	template_subsystem_list_glob(buffer, yyvsp[0].string+1);
	free(yyvsp[0].string);
;
    break;}
case 94:
#line 910 "parse.y"
{
	if (strcasecmp(yyvsp[-1].string, "fd") == 0) {
		yyprintf("%d: %d\n", yyvsp[0].number, fdshare_inspect(yyvsp[0].number));
	} else if (strcasecmp(yyvsp[-1].string, "trace") == 0) {
		struct evbuffer *evbuf = evbuffer_new();
		if (evbuf == NULL)
			err(1, "%s: malloc");

		trace_inspect(yyvsp[0].number, evbuf);

		yyprintf("%s", EVBUFFER_DATA(evbuf));

		evbuffer_free(evbuf);
	} else {
		yyerror("Unsupported debug command: \"%s\"\n", yyvsp[-1].string);
	}
	free(yyvsp[-1].string);
;
    break;}
case 95:
#line 930 "parse.y"
{
	yyval.number = 0;
;
    break;}
case 96:
#line 934 "parse.y"
{
	yyval.number = 1;
;
    break;}
case 97:
#line 940 "parse.y"
{
	yyval.number = 0;
;
    break;}
case 98:
#line 944 "parse.y"
{
	yyval.number = 1;
;
    break;}
case 99:
#line 950 "parse.y"
{
	yyval.number = 0;
;
    break;}
case 100:
#line 954 "parse.y"
{
	yyval.number = PORT_TARPIT;
;
    break;}
case 101:
#line 960 "parse.y"
{
		pf_osfp_t fp;
		yyvsp[0].string[strlen(yyvsp[0].string) - 1] = '\0';
		if ((fp = pfctl_get_fingerprint(yyvsp[0].string+1)) == PF_OSFP_NOMATCH)
			yyerror("Unknown fingerprint \"%s\"", yyvsp[0].string+1);
		if ((yyval.condition.match_arg = malloc(sizeof(fp))) == NULL)
			yyerror("Out of memory");
		memcpy(yyval.condition.match_arg, &fp, sizeof(fp));
		yyval.condition.match = condition_match_osfp;
		yyval.condition.match_arglen = sizeof(fp);
		free (yyvsp[0].string);
	;
    break;}
case 102:
#line 973 "parse.y"
{
		if ((yyval.condition.match_arg = malloc(sizeof(struct addr))) == NULL)
			yyerror("Out of memory");
		memcpy(yyval.condition.match_arg, &yyvsp[0].addr, sizeof(struct addr));
		yyval.condition.match = condition_match_addr;
		yyval.condition.match_arglen = sizeof(struct addr);
	;
    break;}
case 103:
#line 981 "parse.y"
{
		if ((yyval.condition.match_arg = malloc(sizeof(struct addr))) == NULL)
			yyerror("Out of memory");
		memcpy(yyval.condition.match_arg, &yyvsp[0].addr, sizeof(struct addr));
		yyval.condition.match = condition_match_addr;
		yyval.condition.match_arglen = sizeof(struct addr);
	;
    break;}
case 104:
#line 989 "parse.y"
{
		if ((yyval.condition.match_arg = malloc(sizeof(struct condition_time))) == NULL)
			yyerror("Out of memory");
		memcpy(yyval.condition.match_arg, &yyvsp[0].timecondition, sizeof(struct condition_time));
		yyval.condition.match = condition_match_time;
		yyval.condition.match_arglen = sizeof(struct condition_time);
	;
    break;}
case 105:
#line 997 "parse.y"
{
		if ((yyval.condition.match_arg = malloc(sizeof(struct addr))) == NULL)
			yyerror("Out of memory");
		memcpy(yyval.condition.match_arg, &yyvsp[0].number, sizeof(int));
		yyval.condition.match = condition_match_proto;
		yyval.condition.match_arglen = sizeof(int);
	;
    break;}
case 106:
#line 1005 "parse.y"
{
		yyval.condition.match_arg = 0;
		yyval.condition.match = condition_match_otherwise;
		yyval.condition.match_arglen = 0;
	;
    break;}
case 107:
#line 1013 "parse.y"
{
		yyval.timecondition.tm_start = yyvsp[-2].time;
		yyval.timecondition.tm_end = yyvsp[0].time;
	;
    break;}
case 108:
#line 1020 "parse.y"
{
		int ispm = -1;
		int hour, minute;

		if (strcmp(yyvsp[0].string, "am") == 0) {
			ispm = 0;
		} else if (strcmp(yyvsp[0].string, "pm") == 0) {
			ispm = 1;
		} else {
			yyerror("Bad time specifier, use 'am' or 'pm': %s", yyvsp[0].string);
			break;
		}
		free (yyvsp[0].string);

		hour = yyvsp[-3].number + (ispm ? 12 : 0);
		minute = yyvsp[-1].number;

		memset(&yyval.time, 0, sizeof(yyval.time));
		yyval.time.tm_hour = hour;
		yyval.time.tm_min = minute;
	;
    break;}
case 109:
#line 1042 "parse.y"
{
		char *time = yyvsp[0].string + 1;
		time[strlen(time)-1] = '\0';

		if (strptime(time, "%T", &yyval.time) != NULL) {
			; /* done */
		} else if (strptime(time, "%r", &yyval.time) != NULL) {
			; /* done */
		} else {
			yyerror("Bad time specification; use \"hh:mm:ss\"");
		}

		free(yyvsp[0].string);
	;
    break;}
}
   /* the action file gets copied in in place of this dollarsign */
#line 543 "/usr/share/bison.simple"

  yyvsp -= yylen;
  yyssp -= yylen;
#ifdef YYLSP_NEEDED
  yylsp -= yylen;
#endif

#if YYDEBUG != 0
  if (yydebug)
    {
      short *ssp1 = yyss - 1;
      fprintf (stderr, "state stack now");
      while (ssp1 != yyssp)
	fprintf (stderr, " %d", *++ssp1);
      fprintf (stderr, "\n");
    }
#endif

  *++yyvsp = yyval;

#ifdef YYLSP_NEEDED
  yylsp++;
  if (yylen == 0)
    {
      yylsp->first_line = yylloc.first_line;
      yylsp->first_column = yylloc.first_column;
      yylsp->last_line = (yylsp-1)->last_line;
      yylsp->last_column = (yylsp-1)->last_column;
      yylsp->text = 0;
    }
  else
    {
      yylsp->last_line = (yylsp+yylen-1)->last_line;
      yylsp->last_column = (yylsp+yylen-1)->last_column;
    }
#endif

  /* Now "shift" the result of the reduction.
     Determine what state that goes to,
     based on the state we popped back to
     and the rule number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTBASE] + *yyssp;
  if (yystate >= 0 && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTBASE];

  goto yynewstate;

yyerrlab:   /* here on detecting error */

  if (! yyerrstatus)
    /* If not already recovering from an error, report this error.  */
    {
      ++yynerrs;

#ifdef YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (yyn > YYFLAG && yyn < YYLAST)
	{
	  int size = 0;
	  char *msg;
	  int x, count;

	  count = 0;
	  /* Start X at -yyn if nec to avoid negative indexes in yycheck.  */
	  for (x = (yyn < 0 ? -yyn : 0);
	       x < (sizeof(yytname) / sizeof(char *)); x++)
	    if (yycheck[x + yyn] == x)
	      size += strlen(yytname[x]) + 15, count++;
	  msg = (char *) malloc(size + 15);
	  if (msg != 0)
	    {
	      strcpy(msg, "parse error");

	      if (count < 5)
		{
		  count = 0;
		  for (x = (yyn < 0 ? -yyn : 0);
		       x < (sizeof(yytname) / sizeof(char *)); x++)
		    if (yycheck[x + yyn] == x)
		      {
			strcat(msg, count == 0 ? ", expecting `" : " or `");
			strcat(msg, yytname[x]);
			strcat(msg, "'");
			count++;
		      }
		}
	      yyerror(msg);
	      free(msg);
	    }
	  else
	    yyerror ("parse error; also virtual memory exceeded");
	}
      else
#endif /* YYERROR_VERBOSE */
	yyerror("parse error");
    }

  goto yyerrlab1;
yyerrlab1:   /* here on error raised explicitly by an action */

  if (yyerrstatus == 3)
    {
      /* if just tried and failed to reuse lookahead token after an error, discard it.  */

      /* return failure if at end of input */
      if (yychar == YYEOF)
	YYABORT;

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Discarding token %d (%s).\n", yychar, yytname[yychar1]);
#endif

      yychar = YYEMPTY;
    }

  /* Else will try to reuse lookahead token
     after shifting the error token.  */

  yyerrstatus = 3;		/* Each real token shifted decrements this */

  goto yyerrhandle;

yyerrdefault:  /* current state does not do anything special for the error token. */

#if 0
  /* This is wrong; only states that explicitly want error tokens
     should shift them.  */
  yyn = yydefact[yystate];  /* If its default is to accept any token, ok.  Otherwise pop it.*/
  if (yyn) goto yydefault;
#endif

yyerrpop:   /* pop the current state because it cannot handle the error token */

  if (yyssp == yyss) YYABORT;
  yyvsp--;
  yystate = *--yyssp;
#ifdef YYLSP_NEEDED
  yylsp--;
#endif

#if YYDEBUG != 0
  if (yydebug)
    {
      short *ssp1 = yyss - 1;
      fprintf (stderr, "Error: state stack now");
      while (ssp1 != yyssp)
	fprintf (stderr, " %d", *++ssp1);
      fprintf (stderr, "\n");
    }
#endif

yyerrhandle:

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yyerrdefault;

  yyn += YYTERROR;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != YYTERROR)
    goto yyerrdefault;

  yyn = yytable[yyn];
  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrpop;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrpop;

  if (yyn == YYFINAL)
    YYACCEPT;

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Shifting error token, ");
#endif

  *++yyvsp = yylval;
#ifdef YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  yystate = yyn;
  goto yynewstate;

 yyacceptlab:
  /* YYACCEPT comes here.  */
  if (yyfree_stacks)
    {
      free (yyss);
      free (yyvs);
#ifdef YYLSP_NEEDED
      free (yyls);
#endif
    }
  return 0;

 yyabortlab:
  /* YYABORT comes here.  */
  if (yyfree_stacks)
    {
      free (yyss);
      free (yyvs);
#ifdef YYLSP_NEEDED
      free (yyls);
#endif
    }
  return 1;
}
#line 1057 "parse.y"


static void
dhcp_template(struct template *tmpl, char *interface, char *mac_addr)
{
	struct interface *inter;
	struct template *newtmpl;
	struct addr addr;
	extern int need_dhcp;
	extern int need_arp;

	if (mac_addr == NULL && tmpl->ethernet_addr == NULL) {
		yyerror("Need an ethernet address for DHCP.");
		return;
	}

	/* Find the right interface */
	if ((inter = interface_find(interface)) == NULL) {
		yyerror("Interface \"%s\" does not exist.", interface);
		return;
	}
	if (inter->if_ent.intf_link_addr.addr_type != ADDR_TYPE_ETH) {
		yyerror("Interface \"%s\" does not support ARP.", interface);
		return;
	}

	/* Need to find a temporary IP address */
	if (template_get_dhcp_address(&addr) == -1) {
		yyerror("Failed to obtain temporary IP address.");
		return;
	}

	newtmpl = template_clone(addr_ntoa(&addr), tmpl, inter, 1);
	if (newtmpl == NULL) {
		yyerror("Binding to %s failed", addr_ntoa(&addr));
		return;
	}

	if (mac_addr != NULL) {
		/*
		 * This is more complicated than it should be.
		 * 1. Remove existing ARP table entries.
		 * 2. Set new ethernet MAC address
		 * 3. Assign interface to template
		 * 4. Post new ARP table entry.
		 */
		template_remove_arp(newtmpl);

		newtmpl->ethernet_addr = ethernetcode_make_address(mac_addr);
		if (newtmpl->ethernet_addr == NULL) {
			yyerror("Unknown ethernet vendor \"%s\"", mac_addr);
		}

		newtmpl->inter = inter;

		/* We need to update the ARP binding */
		template_post_arp(newtmpl, &addr);
	}

	/* We can ignore the rest if we just verify the configuration */
	if (honeyd_verify_config)
		return;

	/* Wow - now we can assign the DHCP object to it */
	if (dhcp_getconf(newtmpl) == -1) {
		yyerror("Failed to start DHCP on %s",
		    inter->if_ent.intf_name);
		return;
	}

	need_arp = need_dhcp = 1;
}

int
yyerror(char *fmt, ...)
{
	va_list ap;
	errors = 1;

	va_start(ap, fmt);
	if (buffer == NULL) {
		fprintf(stderr, "%s:%d: ", filename, lineno);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	} else {
		char *data;
		if (vasprintf(&data, fmt, ap) == -1)
			err(1, "%s: vasprintf", __func__);
		evbuffer_add_printf(buffer, "%s: %s\n", filename, data);
		free(data);
	}
	va_end(ap);
	return (0);
}

int
yywarn(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (buffer == NULL) {
		fprintf(stderr, "%s:%d: ", filename, lineno);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	} else {
		char *data;
		if (vasprintf(&data, fmt, ap) == -1)
			err(1, "%s: vasprintf", __func__);
		evbuffer_add_printf(buffer, "%s: %s\n", filename, data);
		free(data);
	}
	va_end(ap);
	return (0);
}

int
yyprintf(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (buffer == NULL) {
		vfprintf(stdout, fmt, ap);
	} else {
		char *data;
		if (vasprintf(&data, fmt, ap) == -1)
			err(1, "%s: vasprintf", __func__);
		evbuffer_add_printf(buffer, "%s", data);
		free(data);
	}
	va_end(ap);
	return (0);
}

int
parse_configuration(FILE *input, char *name)
{
	extern FILE *yyin;

	buffer = NULL;
	errors = 0;
	lineno = 1;
	filename = name;
	yyin = input;
	yyparse();
	return (errors ? -1 : 0);
}

/*
 * Parse from memory.  Error output is buffered
 */

int
parse_line(struct evbuffer *output, char *line)
{
	void *yybuf;

	buffer = output;
	errors = 0;
	lineno = 1;
	filename = "<stdin>";
	yybuf = yy_scan_string(line);
	yyparse();
	yy_delete_buffer(yybuf);
	return (errors ? -1 : 0);
}
