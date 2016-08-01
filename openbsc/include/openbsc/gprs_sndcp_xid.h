#ifndef _GPRS_SNDCP_XID_H
#define _GPRS_SNDCP_XID_H

#include <stdint.h>
#include <osmocom/core/linuxlist.h>

#define CURRENT_SNDCP_VERSION 0	/* See TS 144 065, clause 8 */

/* According to: TS 144 065 6.5.1.1 Format of the protocol control information 
				    compression field (Figure 7) 

                 TS 144 065 6.6.1.1 Format of the data compression 
				    field (Figure 9) */

struct gprs_sndcp_comp_field {
	struct llist_head list;

	/* Propose bit (P), see also: 6.5.1.1.2 and 6.6.1.1.2 */
	unsigned int p;

	/* Entity number, see also: 6.5.1.1.3 and 6.6.1.1.3 */
	unsigned int entity;

	/* gorithm identifier, see also: 6.5.1.1.4 and 6.6.1.1.4 */
	unsigned int algo;

	/* Number of contained PCOMP / DCOMP values */
	unsigned int comp_len;

	/* PCOMP / DCOMP values, see also: 6.5.1.1.5 and 6.6.1.1.5 */
	unsigned int comp[16];

	/* Note: Only one of the following struct pointers may, 
	   be used unused pointers must be set to NULL! */
	struct gprs_sndcp_hdrcomp_rfc1144_params *rfc1144_params;
	struct gprs_sndcp_hdrcomp_rfc2507_params *rfc2507_params;
	struct gprs_sndcp_hdrcomp_rohc_params *rohc_params;
	struct gprs_sndcp_datacomp_v42bis_params *v42bis_params;
	struct gprs_sndcp_datacomp_v44_params *v44_params;
};

/* According to: TS 144 065 6.5.1.1.4 Algorithm identifier */
enum gprs_sndcp_hdr_comp_algo {
	RFC_1144 = 0,	/* TCP/IP header compression, see also 6.5.2 */
	RFC_2507 = 1,	/* TCP/UDP/IP header compression, see also: 6.5.3 */
	ROHC = 2,	/* Robust Header Compression, see also 6.5.4 */
};

/* According to: TS 144 065 6.5.1.1.4 Algorithm identifier */
enum gprs_sndcp_data_comp_algo {
	V42BIS = 0,		/* V42bis data compression, see also 6.6.2 */
	V44 = 1,		/* V44 data compression, see also: 6.6.3 */
};

/* According to: TS 144 065 8 SNDCP XID parameters */
enum gprs_sndcp_xid_param_types {
	SNDCP_XID_VERSION_NUMBER = 0,
	SNDCP_XID_DATA_COMPRESSION = 1,		/* See also: subclause 6.6.1 */
	SNDCP_XID_PROTOCOL_COMPRESSION = 2,	/* See also: subclause 6.5.1 */
};

/* When the propose bit in an SNDCP-XID compression field is set to zero,
   the algorithm identifier is stripped. The algoritm parameters are specific
   for each algorithms. The following struct is used to pass the information
   about the referenced algorithm to the parser. */
struct gprs_sndcp_hdrcomp_entity_algo_table {
	unsigned int entity;	/* see also: 6.5.1.1.3 and 6.6.1.1.3 */
	unsigned int algo;	/* see also: 6.5.1.1.4 and 6.6.1.1.4 */
	unsigned int compclass;	/* Can be either SNDCP_XID_DATA_COMPRESSION or
				   SNDCP_XID_PROTOCOL_COMPRESSION */
};



/* According to: TS 144 065 6.5.2.1 Parameters (Table 5) */
struct gprs_sndcp_hdrcomp_rfc1144_params {
	unsigned int nsapi_len;	/* Number of applicable NSAPIs (default 0) */
	unsigned int nsapi[11];	/* Applicable NSAPIs (default 0) */
	unsigned int s01;	/* (default 15) */
};

/* According to: TS 144 065 6.5.2.2 Assignment of PCOMP values */
enum gprs_sndcp_hdrcomp_rfc1144_pcomp {
	RFC1144_PCOMP1 = 0,	/* Uncompressed TCP */
	RFC1144_PCOMP2 = 1,	/* Compressed TCP */
	RFC1144_PCOMP_LEN = 2
};



/* According to: TS 144 065 6.5.3.1 Parameters (Table 6) */
struct gprs_sndcp_hdrcomp_rfc2507_params {
	unsigned int nsapi_len;	/* Number of applicable NSAPIs (default 0) */
	unsigned int nsapi[11];	/* Applicable NSAPIs (default 0) */
	unsigned int f_max_period;	/* (default 256) */
	unsigned int f_max_time;	/* (default 5) */
	unsigned int max_header;	/* (default 168) */
	unsigned int tcp_space;	/* (default 15) */
	unsigned int non_tcp_space;	/* (default 15) */
};

/* According to: TS 144 065 6.5.3.2 Assignment of PCOMP values for RFC2507 */
enum gprs_sndcp_hdrcomp_rfc2507_pcomp {
	RFC2507_PCOMP1 = 0,	/* Full Header */
	RFC2507_PCOMP2 = 1,	/* Compressed TCP */
	RFC2507_PCOMP3 = 2,	/* Compressed TCP non delta */
	RFC2507_PCOMP4 = 3,	/* Compressed non TCP */
	RFC2507_PCOMP5 = 4,	/* Context state */
	RFC2507_PCOMP_LEN = 5
};



/* According to: TS 144 065 6.5.4.1 Parameter (Table 10) */
struct gprs_sndcp_hdrcomp_rohc_params {
	unsigned int nsapi_len;	/* Number of applicable NSAPIs (default 0) */
	unsigned int nsapi[11];		/* Applicable NSAPIs (default 0) */
	unsigned int max_cid;		/* (default 15) */
	unsigned int max_header;	/* (default 168) */
	unsigned int profile_len;	/* (default 1) */
	uint16_t profile[16];		/* (default 0, ROHC uncompressed) */
};

/* According to: TS 144 065 6.5.4.2 Assignment of PCOMP values for ROHC */
enum gprs_sndcp_hdrcomp_rohc_pcomp {
	ROHC_PCOMP1 = 0,	/* ROHC small CIDs */
	ROHC_PCOMP2 = 1,	/* ROHC large CIDs */
	ROHC_PCOMP_LEN = 2
};

/* ROHC compression profiles, see also: 
   http://www.iana.org/assignments/rohc-pro-ids/rohc-pro-ids.xhtml */
enum gprs_sndcp_xid_rohc_profiles {
	ROHC_UNCOMPRESSED = 0x0000,	/* ROHC uncompressed    [RFC5795] */
	ROHC_RTP = 0x0001,		/* ROHC RTP             [RFC3095] */
	ROHCV2_RTP = 0x0101,		/* ROHCv2 RTP           [RFC5225] */
	ROHC_UDP = 0x0002,		/* ROHC UDP             [RFC3095] */
	ROHCv2_UDP = 0x0102,		/* ROHCv2 UDP           [RFC5225] */
	ROHC_ESP = 0x0003,		/* ROHC ESP             [RFC3095] */
	ROHCV2_ESP = 0x0103,		/* ROHCv2 ESP           [RFC5225] */
	ROHC_IP = 0x0004,		/* ROHC IP              [RFC3843] */
	ROHCV2_IP = 0x0104,		/* ROHCv2 IP            [RFC5225] */
	ROHC_LLA = 0x0005,		/* ROHC LLA             [RFC4362] */
	ROHC_LLA_WITH_R_MODE = 0x0105,	/* ROHC LLA with R-mode [RFC3408] */
	ROHC_TCP = 0x0006,		/* ROHC TCP             [RFC6846] */
	ROHC_RTP_UDP_LITE = 0x0007,	/* ROHC RTP/UDP-Lite    [RFC4019] */
	ROHCV2_RTP_UDP_LITE = 0x0107,	/* ROHCv2 RTP/UDP-Lite  [RFC5225] */
	ROHC_UDP_LITE = 0x0008,		/* ROHC UDP-Lite        [RFC4019] */
	ROHCV2_UDP_LITE = 0x0108,	/* ROHCv2 UDP-Lite      [RFC5225] */
};



/* According to: TS 144 065 6.6.2.1 Parameters (Table 7a) */
struct gprs_sndcp_datacomp_v42bis_params {
	unsigned int nsapi_len;	/* Number of applicable NSAPIs (default 0) */
	unsigned int nsapi[11];	/* Applicable NSAPIs (default 0) */
	unsigned int p0;	/* (default 3) */
	unsigned int p1;	/* (default 2048) */
	unsigned int p2;	/* (default 20) */

};

/* According to: ETSI TS 144 065 6.6.2.2 Assignment of DCOMP values */
enum gprs_sndcp_datacomp_v42bis_dcomp {
	V42BIS_DCOMP1 = 0,	/* V42bis enabled */
	V42BIS_DCOMP_LEN = 1
};



/* According to: TS 144 065 6.6.3.1 Parameters (Table 7c) */
struct gprs_sndcp_datacomp_v44_params {
	unsigned int nsapi_len;	/* Number of applicable NSAPIs (default 0) */
	unsigned int nsapi[11];	/* Applicable NSAPIs (default 0) */
	unsigned int c0;	/* (default 10000000) */
	unsigned int p0;	/* (default 3) */
	unsigned int p1t;	/* Refer to subclause 6.6.3.1.4 */
	unsigned int p1r;	/* Refer to subclause 6.6.3.1.5 */
	unsigned int p3t;	/* (default 3 x p1t) */
	unsigned int p3r;	/* (default 3 x p1r) */
};

/* According to: ETSI TS 144 065 6.6.3.2 Assignment of DCOMP values */
enum gprs_sndcp_datacomp_v44_dcomp {
	V44_DCOMP1 = 0,		/* Packet method compressed */
	V44_DCOMP2 = 1,		/* Multi packet method compressed */
	V44_DCOMP_LEN = 2
};

/* Transform a list with compression fields into an SNDCP-XID message (bytes) */
int gprs_sndcp_compile_xid(struct llist_head *comp_fields, uint8_t * bytes,
			   unsigned int bytes_maxlen);

/* Transform an SNDCP-XID message (bytes) into a list of SNDCP-XID fields */
int gprs_sndcp_parse_xid(struct llist_head *comp_fields, uint8_t * bytes,
			 unsigned int bytes_len,
			 struct gprs_sndcp_hdrcomp_entity_algo_table *lt,
			 unsigned int lt_len);

/* Free a list with SNDCP-XID fields */
void gprs_sndcp_free_comp_fields(struct llist_head *comp_fields);

/* Find out to which compression class the specified comp-field belongs
   (header compression or data compression?) */
int gprs_sndcp_get_compression_class(struct gprs_sndcp_comp_field
				     *comp_field);

/* Dump a list with SNDCP-XID fields (Debug) */
void gprs_sndcp_dump_comp_fields(struct llist_head *comp_fields);


#endif
