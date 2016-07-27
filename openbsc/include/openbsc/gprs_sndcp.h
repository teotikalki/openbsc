#ifndef _INT_SNDCP_H
#define _INT_SNDCP_H

#include <stdint.h>
#include <osmocom/core/linuxlist.h>

/* A fragment queue header, maintaining list of fragments for one N-PDU */
struct defrag_state {
	/* PDU number for which the defragmentation state applies */
	uint16_t npdu;
	/* highest segment number we have received so far */
	uint8_t highest_seg;
	/* bitmask of the segments we already have */
	uint32_t seg_have;
	/* do we still expect more segments? */
	unsigned int no_more;
	/* total length of all segments together */
	unsigned int tot_len;

	/* linked list of defrag_queue_entry: one for each fragment  */
	struct llist_head frag_list;

	struct osmo_timer_list timer;
};

/* See 6.7.1.2 Reassembly */
enum sndcp_rx_state {
	SNDCP_RX_S_FIRST,
	SNDCP_RX_S_SUBSEQ,
	SNDCP_RX_S_DISCARD,
};

struct gprs_sndcp_entity {
	struct llist_head list;

	/* FIXME: move this RA_ID up to the LLME or even higher */
	struct gprs_ra_id ra_id;
	/* reference to the LLC Entity below this SNDCP entity */
	struct gprs_llc_lle *lle;
	/* The NSAPI we shall use on top of LLC */
	uint8_t nsapi;

	/* NPDU number for the GTP->SNDCP side */
	uint16_t tx_npdu_nr;
	/* SNDCP eeceiver state */
	enum sndcp_rx_state rx_state;
	/* The defragmentation queue */
	struct defrag_state defrag;

	/* Specifies which compression is used once the packet is re-assembled */
	int pcomp;
};

extern struct llist_head gprs_sndcp_entities;


/* Entry point for the SNSM-ACTIVATE.indication */
int sndcp_sm_activate_ind(struct gprs_llc_lle *lle, uint8_t nsapi);

/* Entry point for the SNSM-DEACTIVATE.indication */
int sndcp_sm_deactivate_ind(struct gprs_llc_lle *lle, uint8_t nsapi);

/* Request transmission of a SN-PDU over specified LLC Entity + SAPI */
int sndcp_unitdata_req(struct msgb *msg, struct gprs_llc_lle *lle, uint8_t nsapi,
			void *mmcontext);

/* Section 5.1.2.17 LL-UNITDATA.ind */
int sndcp_llunitdata_ind(struct msgb *msg, struct gprs_llc_lle *lle,
			 uint8_t *hdr, uint16_t len);

/* Set of SNDCP-XID negotiation (See also: TS 144 065, Section 6.8 XID parameter negotiation) */
int sndcp_sn_xid_req(struct gprs_llc_lle *lle, uint8_t nsapi);



#endif	/* INT_SNDCP_H */
