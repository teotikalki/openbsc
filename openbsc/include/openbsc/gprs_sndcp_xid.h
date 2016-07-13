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
	struct gprs_sndcp_hdrcomp_rohc_params *rohc_params;	/* Parameters: Robust header compression (set to NULL, if unused!) */
};

/* According to: TS 144 065 6.5.1.1.4 Algorithm identifier */
enum gprs_sndcp_hdr_comp_algo {
	RFC_1144 = 0,		/* TCP/IP header compression, see also 6.5.2 */
	RFC_2507 = 1,		/* TCP/IP and UDP/IP header compression, see also: 6.5.3 */
	ROHC = 2,		/* Robust Header Compression, see also 6.5.4 */
};

/* According to: TS 144 065 6.5.4.2 Assignment of PCOMP values for ROHC */
enum gprs_sndcp_hdrcomp_rohc_pcomp {
	ROHC_PCOMP1 = 0, 	/* ROHC small CIDs */
	ROHC_PCOMP2 = 1,	/* ROHC large CIDs */
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

/* According to: TS 144 065 8 SNDCP XID parameters */
enum gprs_sndcp_xid_param_types {
	SNDCP_XID_VERSION_NUMBER = 0,
	SNDCP_XID_DATA_COMPRESSION = 1,				/* See also: subclause 6.6.1 */
	SNDCP_XID_PROTOCOL_CONTROL_INFORMATION_COMPRESSION = 2, /* See also: subclause 6.5.1 */
};

/* Transform a list with compression fields into an SNDCP-XID message (bytes) */
int gprs_sndcp_compile_xid(struct llist_head *comp_fields, uint8_t *bytes, int bytes_maxlen);

#endif
