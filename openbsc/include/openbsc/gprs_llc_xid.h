#ifndef _GPRS_LLC_XID_H
#define _GPRS_LLC_XID_H


#include <stdint.h>
#include <openbsc/gprs_sgsn.h>

/* TS 101 351 6.4.1.6 Exchange Identification (XID) command/response parameter field */
struct gprs_llc_xid_field {
	struct llist_head list;

	uint8_t type;		/* See also Table 6: LLC layer parameter negotiation */
	uint8_t *data;		/* Payload data (octets) */
	uint8_t data_len;	/* Payload length */
};


/* Transform a list with XID fields into a XID message (bytes) */
int gprs_llc_compile_xid(struct llist_head *xid_fields, uint8_t *bytes, int bytes_maxlen);

/* Transform a XID message (bytes) into a list of XID fields */
int gprs_llc_parse_xid(struct llist_head *xid_fields, uint8_t *bytes, int bytes_len);


#endif
