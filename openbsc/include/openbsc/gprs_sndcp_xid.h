#ifndef _GPRS_SNDCP_XID_H
#define _GPRS_SNDCP_XID_H


#include <stdint.h>
#include <openbsc/gprs_sgsn.h>

#define CURRENT_SNDCP_VERSION 1	/* See TS 144 065, clause 8 */

/* According to: TS 144 065 6.5.1.1 Format of the protocol control information compression field (Figure 7) 
                 TS 144 065 6.6.1.1 Format of the data compression field (Figure 9) */
struct gprs_sndcp_comp_field {
	struct llist_head list;

	int p;			/* Propose bit (P), see also: 6.5.1.1.2 and 6.6.1.1.2 */
	int entity;		/* Entity number, see also: 6.5.1.1.3 and 6.6.1.1.3 */
	int algo;		/* gorithm identifier, see also: 6.5.1.1.4 and 6.6.1.1.4 */
	int comp[16];		/* PCOMP / DCOMP values, see also: 6.5.1.1.5 and 6.6.1.1.5 */
	int comp_len;		/* Number of contained PCOMP / DCOMP values */

	/* Note: Only one of the following struct pointers may, 
                 be used unused pointers must be set to NULL! */
	struct gprs_sndcp_hdrcomp_rohc_params *rohc_params;		/* Parameters: ROHC Robust header compression */
	struct gprs_sndcp_hdrcomp_rfc1144_params *rfc1144_params;	/* Parameters: RFC1144 TCP/IP Header compression */
	struct gprs_sndcp_hdrcomp_rfc2507_params *rfc2507_params;	/* Parameters: RFC2507 TCP/IP and UDP/IP header compression */
};

/* According to: TS 144 065 6.5.1.1.4 Algorithm identifier */
enum gprs_sndcp_hdr_comp_algo {
	RFC_1144 = 0,		/* TCP/IP header compression, see also 6.5.2 */
	RFC_2507 = 1,		/* TCP/IP and UDP/IP header compression, see also: 6.5.3 */
	ROHC = 2,		/* Robust Header Compression, see also 6.5.4 */
};

/* According to: TS 144 065 8 SNDCP XID parameters */
enum gprs_sndcp_xid_param_types {
	SNDCP_XID_VERSION_NUMBER = 0,
	SNDCP_XID_DATA_COMPRESSION = 1,				/* See also: subclause 6.6.1 */
	SNDCP_XID_PROTOCOL_CONTROL_INFORMATION_COMPRESSION = 2, /* See also: subclause 6.5.1 */
};



/* According to: TS 144 065 6.5.2.1 Parameters (Table 5) */
struct gprs_sndcp_hdrcomp_rfc1144_params {
	int nsapi[11];		/* Applicable NSAPIs (default 0) */
	int nsapi_len;		/* Number of applicable NSAPIs (default 0) */
	uint8_t s01;		/* (default 15) */
};

/* According to: TS 144 065 6.5.2.2 Assignment of PCOMP values */
enum gprs_sndcp_hdrcomp_rfc1144_pcomp {
	RFC1144_PCOMP1 = 0, 	/* Uncompressed TCP */
	RFC1144_PCOMP2 = 1, 	/* Compressed TCP */
};



/* According to: TS 144 065 6.5.3.1 Parameters (Table 6) */
struct gprs_sndcp_hdrcomp_rfc2507_params {
	int nsapi[11];		/* Applicable NSAPIs (default 0) */
	int nsapi_len;		/* Number of applicable NSAPIs (default 0) */
	uint16_t f_max_period;	/* (default 256) */
	uint8_t f_max_time;	/* (default 5) */
	uint8_t max_header;	/* (default 168) */
	uint8_t tcp_space;	/* (default 15) */
	uint16_t non_tcp_space;	/* (default 15) */
};

/* According to: TS 144 065 6.5.3.2 Assignment of PCOMP values for RFC2507 */
enum gprs_sndcp_hdrcomp_rfc2507_pcomp {
	RFC2507_PCOMP1 = 0, 	/* Full Header */
	RFC2507_PCOMP2 = 1, 	/* Compressed TCP */
	RFC2507_PCOMP3 = 2, 	/* Compressed TCP non delta */
	RFC2507_PCOMP4 = 3, 	/* Compressed non TCP */
	RFC2507_PCOMP5 = 4, 	/* Context state */
};



/* According to: TS 144 065 6.5.4.1 Parameter (Table 10) */
struct gprs_sndcp_hdrcomp_rohc_params {
	int nsapi[11];		/* Applicable NSAPIs (default 0) */
	int nsapi_len;		/* Number of applicable NSAPIs (default 0) */
	int max_cid;		/* (default 15) */
	int max_hdr;		/* (default 168) */
	uint16_t profile[16];	/* Applicable ROHC profiles (default 0, ROHC uncompressed) */
	int profile_len;	/* Number of applicable ROHC profiles (default 1) */
};

/* According to: TS 144 065 6.5.4.2 Assignment of PCOMP values for ROHC */
enum gprs_sndcp_hdrcomp_rohc_pcomp {
	ROHC_PCOMP1 = 0, 	/* ROHC small CIDs */
	ROHC_PCOMP2 = 1,	/* ROHC large CIDs */
};

/* ROHC compression profiles, see also: http://www.iana.org/assignments/rohc-pro-ids/rohc-pro-ids.xhtml */
enum gprs_sndcp_xid_rohc_profiles {
	ROHC_UNCOMPRESSED = 0x0000, 	/* ROHC uncompressed 	[RFC5795] */
	ROHC_RTP = 0x0001, 		/* ROHC RTP		[RFC3095] */
	ROHCV2_RTP = 0x0101, 		/* ROHCv2 RTP		[RFC5225] */
	ROHC_UDP = 0x0002, 		/* ROHC UDP		[RFC3095] */
	ROHCv2_UDP = 0x0102, 		/* ROHCv2 UDP		[RFC5225] */
	ROHC_ESP = 0x0003, 		/* ROHC ESP		[RFC3095] */
	ROHCV2_ESP = 0x0103, 		/* ROHCv2 ESP		[RFC5225] */
	ROHC_IP = 0x0004, 		/* ROHC IP		[RFC3843] */
	ROHCV2_IP = 0x0104, 		/* ROHCv2 IP		[RFC5225] */
	ROHC_LLA = 0x0005, 		/* ROHC LLA		[RFC4362] */
	ROHC_LLA_WITH_R_MODE = 0x0105, 	/* ROHC LLA with R-mode	[RFC3408] */
	ROHC_TCP = 0x0006, 		/* ROHC TCP		[RFC6846] */
	ROHC_RTP_UDP_LITE = 0x0007, 	/* ROHC RTP/UDP-Lite 	[RFC4019] */
	ROHCV2_RTP_UDP_LITE = 0x0107, 	/* ROHCv2 RTP/UDP-Lite 	[RFC5225] */
	ROHC_UDP_LITE = 0x0008, 	/* ROHC UDP-Lite 	[RFC4019] */
	ROHCV2_UDP_LITE = 0x0108, 	/* ROHCv2 UDP-Lite 	[RFC5225] */
};



/* Transform a list with compression fields into an SNDCP-XID message (bytes) */
int gprs_sndcp_compile_xid(struct llist_head *comp_fields, uint8_t *bytes, int bytes_maxlen);

#endif
