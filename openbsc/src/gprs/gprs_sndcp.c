/* GPRS SNDCP protocol implementation as per 3GPP TS 04.65 */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <errno.h>
#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gprs/gprs_bssgp.h>

#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_llc.h>
#include <openbsc/sgsn.h>

#include <openbsc/gprs_sndcp.h>
#include <openbsc/gprs_llc_xid.h>
#include <openbsc/gprs_sndcp_xid.h>
#include <openbsc/gprs_sndcp_hdrcomp.h>
#include <openbsc/gprs_sndcp_comp_entity.h>

/* FIXME: Remove this debug code when done */
static void showPacketDetails(uint8_t *data, int len, int direction, char *info)
{
	uint8_t tcp_flags;


	printf("===============> %s\n",info);

	if(direction)
		printf("===============> PHONE => NETWORK: %s\n",osmo_hexdump_nospc(data, len));
	else
		printf("===============> PHONE <= NETWORK: %s\n",osmo_hexdump_nospc(data, len));

	printf("===============> LENGTH: %i\n",len);
	if(data[9]==0x06)
	{
		printf("===============> PRTOCOL TYPE TCP!\n");
		tcp_flags = data[33];
		
		printf("===============> FLAGS: ");
		if(tcp_flags & 1)
			printf("FIN ");
		if(tcp_flags & 2)
			printf("SYN ");		
		if(tcp_flags & 4)
			printf("RST ");		
		if(tcp_flags & 8)
			printf("PSH ");		
		if(tcp_flags & 16)
			printf("ACK ");		
		if(tcp_flags & 32)
			printf("URG ");		
		printf("\n");
	}
	else if(data[9]==0x11)
	{
		printf("===============> PRTOCOL TYPE UDP!\n");
	}
	else 
	{
		printf("===============> PRTOCOL TYPE UNKNOWN (%02x)!\n",data[9]);
	}

}

/* Chapter 7.2: SN-PDU Formats */
struct sndcp_common_hdr {
	/* octet 1 */
	uint8_t nsapi:4;
	uint8_t more:1;
	uint8_t type:1;
	uint8_t first:1;
	uint8_t spare:1;
} __attribute__((packed));

/* PCOMP / DCOMP only exist in first fragment */
struct sndcp_comp_hdr {
	/* octet 2 */
	uint8_t pcomp:4;
	uint8_t dcomp:4;
} __attribute__((packed));

struct sndcp_udata_hdr {
	/* octet 3 */
	uint8_t npdu_high:4;
	uint8_t seg_nr:4;
	/* octet 4 */
	uint8_t npdu_low;
} __attribute__((packed));


static void *tall_sndcp_ctx;

/* A fragment queue entry, containing one framgent of a N-PDU */
struct defrag_queue_entry {
	struct llist_head list;
	/* segment number of this fragment */
	uint32_t seg_nr;
	/* length of the data area of this fragment */
	uint32_t data_len;
	/* pointer to the data of this fragment */
	uint8_t *data;
};

LLIST_HEAD(gprs_sndcp_entities);

/* Enqueue a fragment into the defragment queue */
static int defrag_enqueue(struct gprs_sndcp_entity *sne, uint8_t seg_nr,
			  uint8_t *data, uint32_t data_len)
{
	struct defrag_queue_entry *dqe;

	dqe = talloc_zero(tall_sndcp_ctx, struct defrag_queue_entry);
	if (!dqe)
		return -ENOMEM;
	dqe->data = talloc_zero_size(dqe, data_len);
	if (!dqe->data) {
		talloc_free(dqe);
		return -ENOMEM;
	}
	dqe->seg_nr = seg_nr;
	dqe->data_len = data_len;

	llist_add(&dqe->list, &sne->defrag.frag_list);

	if (seg_nr > sne->defrag.highest_seg)
		sne->defrag.highest_seg = seg_nr;

	sne->defrag.seg_have |= (1 << seg_nr);
	sne->defrag.tot_len += data_len;

	memcpy(dqe->data, data, data_len);

	return 0;
}

/* return if we have all segments of this N-PDU */
static int defrag_have_all_segments(struct gprs_sndcp_entity *sne)
{
	uint32_t seg_needed = 0;
	unsigned int i;

	/* create a bitmask of needed segments */
	for (i = 0; i <= sne->defrag.highest_seg; i++)
		seg_needed |= (1 << i);

	if (seg_needed == sne->defrag.seg_have)
		return 1;

	return 0;
}

static struct defrag_queue_entry *defrag_get_seg(struct gprs_sndcp_entity *sne,
						 uint32_t seg_nr)
{
	struct defrag_queue_entry *dqe;

	llist_for_each_entry(dqe, &sne->defrag.frag_list, list) {
		if (dqe->seg_nr == seg_nr) {
			llist_del(&dqe->list);
			return dqe;
		}
	}
	return NULL;
}

/* Perform actual defragmentation and create an output packet */
static int defrag_segments(struct gprs_sndcp_entity *sne, struct llist_head *comp_entities)
{
	struct msgb *msg;
	unsigned int seg_nr;
	uint8_t *npdu;
	int rc;

	LOGP(DSNDCP, LOGL_DEBUG, "TLLI=0x%08x NSAPI=%u: Defragment output PDU %u "
		"num_seg=%u tot_len=%u\n", sne->lle->llme->tlli, sne->nsapi,
		sne->defrag.npdu, sne->defrag.highest_seg, sne->defrag.tot_len);
	msg = msgb_alloc_headroom(sne->defrag.tot_len+256, 128, "SNDCP Defrag");
	if (!msg)
		return -ENOMEM;

	/* FIXME: message headers + identifiers */

	npdu = msg->data;

	for (seg_nr = 0; seg_nr <= sne->defrag.highest_seg; seg_nr++) {
		struct defrag_queue_entry *dqe;
		uint8_t *data;

		dqe = defrag_get_seg(sne, seg_nr);
		if (!dqe) {
			LOGP(DSNDCP, LOGL_ERROR, "Segment %u missing\n", seg_nr);
			msgb_free(msg);
			return -EIO;
		}
		/* actually append the segment to the N-PDU */
		data = msgb_put(msg, dqe->data_len);
		memcpy(data, dqe->data, dqe->data_len);

		/* release memory for the fragment queue entry */
		talloc_free(dqe);
	}

	/* FIXME: cancel timer */

	/* actually send the N-PDU to the SGSN core code, which then
	 * hands it off to the correcshowPacketDetailst GTP tunnel + GGSN via gtp_data_req() */
	printf("\n\n\n////////////////////////////////////////////////////////////////////////////////////////////////////////////////\n");
	showPacketDetails(msg->data, msg->len,1,"defrag_segments()");
	rc = gprs_sndcp_hdrcomp_expand(msg->data, msg->len, sne->pcomp, comp_entities);
	sne->pcomp = 0;
	if (rc < 0)
		return -EIO;
	else
		msg->len = rc;

	showPacketDetails(msg->data, msg->len,1,"defrag_segments()");
	printf("////////////////////////////////////////////////////////////////////////////////////////////////////////////////\n\n\n");

	return sgsn_rx_sndcp_ud_ind(&sne->ra_id, sne->lle->llme->tlli,sne->nsapi, msg, sne->defrag.tot_len, npdu);
}

static int defrag_input(struct gprs_sndcp_entity *sne, struct msgb *msg, uint8_t *hdr,
			unsigned int len, struct llist_head *comp_entities)
{
	struct sndcp_common_hdr *sch;
	struct sndcp_udata_hdr *suh;
	uint16_t npdu_num;
	uint8_t *data;
	int rc;

	sch = (struct sndcp_common_hdr *) hdr;
	if (sch->first) {
		suh = (struct sndcp_udata_hdr *) (hdr + 1 + sizeof(struct sndcp_common_hdr));
	} else
		suh = (struct sndcp_udata_hdr *) (hdr + sizeof(struct sndcp_common_hdr));

	data = (uint8_t *)suh + sizeof(struct sndcp_udata_hdr);

	npdu_num = (suh->npdu_high << 8) | suh->npdu_low;

	LOGP(DSNDCP, LOGL_DEBUG, "TLLI=0x%08x NSAPI=%u: Input PDU %u Segment %u "
		"Length %u %s %s\n", sne->lle->llme->tlli, sne->nsapi, npdu_num,
		suh->seg_nr, len, sch->first ? "F " : "", sch->more ? "M" : "");

	if (sch->first) {
		/* first segment of a new packet.  Discard all leftover fragments of
		 * previous packet */
		if (!llist_empty(&sne->defrag.frag_list)) {
			struct defrag_queue_entry *dqe, *dqe2;
			LOGP(DSNDCP, LOGL_INFO, "TLLI=0x%08x NSAPI=%u: Dropping "
			     "SN-PDU %u due to insufficient segments (%04x)\n",
			     sne->lle->llme->tlli, sne->nsapi, sne->defrag.npdu,
			     sne->defrag.seg_have);
			llist_for_each_entry_safe(dqe, dqe2, &sne->defrag.frag_list, list) {
				llist_del(&dqe->list);
				talloc_free(dqe);
			}
		}
		/* store the currently de-fragmented PDU number */
		sne->defrag.npdu = npdu_num;

		/* Re-set fragmentation state */
		sne->defrag.no_more = sne->defrag.highest_seg = sne->defrag.seg_have = 0;
		sne->defrag.tot_len = 0;
		/* FIXME: (re)start timer */
	}

	if (sne->defrag.npdu != npdu_num) {
		LOGP(DSNDCP, LOGL_INFO, "Segment for different SN-PDU "
			"(%u != %u)\n", npdu_num, sne->defrag.npdu);
		/* FIXME */
	}

	/* FIXME: check if seg_nr already exists */
	/* make sure to subtract length of SNDCP header from 'len' */
	rc = defrag_enqueue(sne, suh->seg_nr, data, len - (data - hdr));
	if (rc < 0)
		return rc;

	if (!sch->more) {
		/* this is suppsed to be the last segment of the N-PDU, but it
		 * might well be not the last to arrive */
		sne->defrag.no_more = 1;
	}

	if (sne->defrag.no_more) {
		/* we have already received the last segment before, let's check
		 * if all the previous segments exist */
		if (defrag_have_all_segments(sne))
			return defrag_segments(sne,comp_entities);
	}

	return 0;
}

static struct gprs_sndcp_entity *gprs_sndcp_entity_by_lle(const struct gprs_llc_lle *lle,
						uint8_t nsapi)
{
	struct gprs_sndcp_entity *sne;

	llist_for_each_entry(sne, &gprs_sndcp_entities, list) {
		if (sne->lle == lle && sne->nsapi == nsapi)
			return sne;
	}
	return NULL;
}

static struct gprs_sndcp_entity *gprs_sndcp_entity_alloc(struct gprs_llc_lle *lle,
						uint8_t nsapi)
{
	struct gprs_sndcp_entity *sne;

	sne = talloc_zero(tall_sndcp_ctx, struct gprs_sndcp_entity);
	if (!sne)
		return NULL;

	sne->lle = lle;
	sne->nsapi = nsapi;
	sne->defrag.timer.data = sne;
	//sne->fqueue.timer.cb = FIXME;
	sne->rx_state = SNDCP_RX_S_FIRST;
	INIT_LLIST_HEAD(&sne->defrag.frag_list);

	llist_add(&sne->list, &gprs_sndcp_entities);

	return sne;
}

/* Entry point for the SNSM-ACTIVATE.indication */
int sndcp_sm_activate_ind(struct gprs_llc_lle *lle, uint8_t nsapi)
{
	LOGP(DSNDCP, LOGL_INFO, "SNSM-ACTIVATE.ind (lle=%p TLLI=%08x, "
	     "SAPI=%u, NSAPI=%u)\n", lle, lle->llme->tlli, lle->sapi, nsapi);

	if (gprs_sndcp_entity_by_lle(lle, nsapi)) {
		LOGP(DSNDCP, LOGL_ERROR, "Trying to ACTIVATE "
			"already-existing entity (TLLI=%08x, NSAPI=%u)\n",
			lle->llme->tlli, nsapi);
		return -EEXIST;
	}

	if (!gprs_sndcp_entity_alloc(lle, nsapi)) {
		LOGP(DSNDCP, LOGL_ERROR, "Out of memory during ACTIVATE\n");
		return -ENOMEM;
	}

	return 0;
}

/* Entry point for the SNSM-DEACTIVATE.indication */
int sndcp_sm_deactivate_ind(struct gprs_llc_lle *lle, uint8_t nsapi)
{
	struct gprs_sndcp_entity *sne;

	LOGP(DSNDCP, LOGL_INFO, "SNSM-DEACTIVATE.ind (lle=%p, TLLI=%08x, "
	     "SAPI=%u, NSAPI=%u)\n", lle, lle->llme->tlli, lle->sapi, nsapi);

	sne = gprs_sndcp_entity_by_lle(lle, nsapi);
	if (!sne) {
		LOGP(DSNDCP, LOGL_ERROR, "SNSM-DEACTIVATE.ind for non-"
		     "existing TLLI=%08x SAPI=%u NSAPI=%u\n", lle->llme->tlli,
		     lle->sapi, nsapi);
		return -ENOENT;
	}
	llist_del(&sne->list);
	/* frag queue entries are hierarchically allocated, so no need to
	 * free them explicitly here */
	talloc_free(sne);

	return 0;
}

/* Fragmenter state */
struct sndcp_frag_state {
	uint8_t frag_nr;
	struct msgb *msg;	/* original message */
	uint8_t *next_byte;	/* first byte of next fragment */

	struct gprs_sndcp_entity *sne;
	void *mmcontext;
};

/* returns '1' if there are more fragments to send, '0' if none */
static int sndcp_send_ud_frag(struct sndcp_frag_state *fs, int pcomp, int dcomp)
{
	struct gprs_sndcp_entity *sne = fs->sne;
	struct gprs_llc_lle *lle = sne->lle;
	struct sndcp_common_hdr *sch;
	struct sndcp_comp_hdr *scomph;
	struct sndcp_udata_hdr *suh;
	struct msgb *fmsg;
	unsigned int max_payload_len;
	unsigned int len;
	uint8_t *data;
	int rc, more;

	fmsg = msgb_alloc_headroom(fs->sne->lle->params.n201_u+256, 128,
				   "SNDCP Frag");
	if (!fmsg) {
		msgb_free(fs->msg);
		return -ENOMEM;
	}

	/* make sure lower layers route the fragment like the original */
	msgb_tlli(fmsg) = msgb_tlli(fs->msg);
	msgb_bvci(fmsg) = msgb_bvci(fs->msg);
	msgb_nsei(fmsg) = msgb_nsei(fs->msg);

	/* prepend common SNDCP header */
	sch = (struct sndcp_common_hdr *) msgb_put(fmsg, sizeof(*sch));
	sch->nsapi = sne->nsapi;
	/* Set FIRST bit if we are the first fragment in a series */
	if (fs->frag_nr == 0)
		sch->first = 1;
	sch->type = 1;

	/* append the compression header for first fragment */
	if (sch->first) {
		scomph = (struct sndcp_comp_hdr *)
				msgb_put(fmsg, sizeof(*scomph));
		scomph->pcomp = pcomp;
		scomph->dcomp = dcomp;
	}

	/* append the user-data header */
	suh = (struct sndcp_udata_hdr *) msgb_put(fmsg, sizeof(*suh));
	suh->npdu_low = sne->tx_npdu_nr & 0xff;
	suh->npdu_high = (sne->tx_npdu_nr >> 8) & 0xf;
	suh->seg_nr = fs->frag_nr % 0xf;

	/* calculate remaining length to be sent */
	len = (fs->msg->data + fs->msg->len) - fs->next_byte;
	/* how much payload can we actually send via LLC? */
	max_payload_len = lle->params.n201_u - (sizeof(*sch) + sizeof(*suh));
	if (sch->first)
		max_payload_len -= sizeof(*scomph);
	/* check if we're exceeding the max */
	if (len > max_payload_len)
		len = max_payload_len;

	/* copy the actual fragment data into our fmsg */
	data = msgb_put(fmsg, len);
	memcpy(data, fs->next_byte, len);

	/* Increment fragment number and data pointer to next fragment */
	fs->frag_nr++;
	fs->next_byte += len;

	/* determine if we have more fragemnts to send */
	if ((fs->msg->data + fs->msg->len) <= fs->next_byte)
		more = 0;
	else
		more = 1;

	/* set the MORE bit of the SNDCP header accordingly */
	sch->more = more;

	rc = gprs_llc_tx_ui(fmsg, lle->sapi, 0, fs->mmcontext, true);
	/* abort in case of error, do not advance frag_nr / next_byte */
	if (rc < 0) {
		msgb_free(fs->msg);
		return rc;
	}

	if (!more) {
		/* we've sent all fragments */
		msgb_free(fs->msg);
		memset(fs, 0, sizeof(*fs));
		/* increment NPDU number for next frame */
		sne->tx_npdu_nr = (sne->tx_npdu_nr + 1) % 0xfff;
		return 0;
	}

	/* default: more fragments to send */
	return 1;
}

/* Request transmission of a SN-PDU over specified LLC Entity + SAPI */
int sndcp_unitdata_req(struct msgb *msg, struct gprs_llc_lle *lle, uint8_t nsapi,
			void *mmcontext)
{
	/* NOTE Traffic from the network to the mobile passes along here */


	struct gprs_sndcp_entity *sne;
	struct sndcp_common_hdr *sch;
	struct sndcp_comp_hdr *scomph;
	struct sndcp_udata_hdr *suh;
	struct sndcp_frag_state fs;
	int pcomp = 0;
	int dcomp = 0;
	int rc;

	/* Identifiers from UP: (TLLI, SAPI) + (BVCI, NSEI) */

	printf("\n\n\n////////////////////////////////////////////////////////////////////////////////////////////////////////////////\n");
	showPacketDetails(msg->data, msg->len,0,"sndcp_initdata_req()");
	rc = gprs_sndcp_hdrcomp_compress(msg->data, msg->len,&pcomp, &lle->llme->comp.proto, nsapi);
	if (rc < 0)
		return -EIO;
	else
		msg->len = rc;
	showPacketDetails(msg->data, msg->len,0,"sndcp_initdata_req()");
	printf("////////////////////////////////////////////////////////////////////////////////////////////////////////////////\n\n\n");


	sne = gprs_sndcp_entity_by_lle(lle, nsapi);
	if (!sne) {
		LOGP(DSNDCP, LOGL_ERROR, "Cannot find SNDCP Entity\n");
		msgb_free(msg);
		return -EIO;
	}

	/* Check if we need to fragment this N-PDU into multiple SN-PDUs */
	if (msg->len > lle->params.n201_u - 
			(sizeof(*sch) + sizeof(*suh) + sizeof(*scomph))) {
		/* initialize the fragmenter state */
		fs.msg = msg;
		fs.frag_nr = 0;
		fs.next_byte = msg->data;
		fs.sne = sne;
		fs.mmcontext = mmcontext;

		/* call function to generate and send fragments until all
		 * of the N-PDU has been sent */
		while (1) {
			int rc = sndcp_send_ud_frag(&fs,pcomp,dcomp);
			if (rc == 0)
				return 0;
			if (rc < 0)
				return rc;
		}
		/* not reached */
		return 0;
	}

	/* this is the non-fragmenting case where we only build 1 SN-PDU */

	/* prepend the user-data header */
	suh = (struct sndcp_udata_hdr *) msgb_push(msg, sizeof(*suh));
	suh->npdu_low = sne->tx_npdu_nr & 0xff;
	suh->npdu_high = (sne->tx_npdu_nr >> 8) & 0xf;
	suh->seg_nr = 0;
	sne->tx_npdu_nr = (sne->tx_npdu_nr + 1) % 0xfff;

	scomph = (struct sndcp_comp_hdr *) msgb_push(msg, sizeof(*scomph));
	scomph->pcomp = pcomp;
	scomph->dcomp = dcomp;

	/* prepend common SNDCP header */
	sch = (struct sndcp_common_hdr *) msgb_push(msg, sizeof(*sch));
	sch->first = 1;
	sch->type = 1;
	sch->nsapi = nsapi;

	return gprs_llc_tx_ui(msg, lle->sapi, 0, mmcontext, true);
}

/* Section 5.1.2.17 LL-UNITDATA.ind */
int sndcp_llunitdata_ind(struct msgb *msg, struct gprs_llc_lle *lle,
			 uint8_t *hdr, uint16_t len)
{
	struct gprs_sndcp_entity *sne;
	struct sndcp_common_hdr *sch = (struct sndcp_common_hdr *)hdr;
	struct sndcp_comp_hdr *scomph = NULL;
	struct sndcp_udata_hdr *suh;
	uint8_t *npdu;
	uint16_t npdu_num __attribute__((unused));
	int npdu_len;
	int rc;

	sch = (struct sndcp_common_hdr *) hdr;
	if (sch->first) {
		scomph = (struct sndcp_comp_hdr *) (hdr + 1);
		suh = (struct sndcp_udata_hdr *) (hdr + 1 + sizeof(struct sndcp_common_hdr));
	} else
		suh = (struct sndcp_udata_hdr *) (hdr + sizeof(struct sndcp_common_hdr));

	if (sch->type == 0) {
		LOGP(DSNDCP, LOGL_ERROR, "SN-DATA PDU at unitdata_ind() function\n");
		return -EINVAL;
	}

	if (len < sizeof(*sch) + sizeof(*suh)) {
		LOGP(DSNDCP, LOGL_ERROR, "SN-UNITDATA PDU too short (%u)\n", len);
		return -EIO;
	}

	sne = gprs_sndcp_entity_by_lle(lle, sch->nsapi);
	if (!sne) {
		LOGP(DSNDCP, LOGL_ERROR, "Message for non-existing SNDCP Entity "
			"(lle=%p, TLLI=%08x, SAPI=%u, NSAPI=%u)\n", lle,
			lle->llme->tlli, lle->sapi, sch->nsapi);
		return -EIO;
	}
	/* FIXME: move this RA_ID up to the LLME or even higher */
	bssgp_parse_cell_id(&sne->ra_id, msgb_bcid(msg));

	if(scomph)
	{
		sne->pcomp = scomph->pcomp;
		sne->dcomp = scomph->dcomp;
	}

	/* any non-first segment is by definition something to defragment
	 * as is any segment that tells us there are more segments */
	if (!sch->first || sch->more)
		return defrag_input(sne, msg, hdr, len, &lle->llme->comp.proto);

	npdu_num = (suh->npdu_high << 8) | suh->npdu_low;
	npdu = (uint8_t *)suh + sizeof(*suh);
	npdu_len = (msg->data + msg->len) - npdu - 3; /* -3 'removes' the FCS from SNDCP */

	if (npdu_len <= 0) {
		LOGP(DSNDCP, LOGL_ERROR, "Short SNDCP N-PDU: %d\n", npdu_len);
		return -EIO;
	}
	/* actually send the N-PDU to the SGSN core code, which then
	 * hands it off to the correct GTP tunnel + GGSN via gtp_data_req() */


	printf("\n\n\n////////////////////////////////////////////////////////////////////////////////////////////////////////////////\n");
	showPacketDetails(npdu, npdu_len,1,"sndcp_llunitdata_ind()");
	rc = gprs_sndcp_hdrcomp_expand(npdu, npdu_len, sne->pcomp, &lle->llme->comp.proto);
	if (rc < 0)
		return -EIO;
	else
		npdu_len = rc;
	sne->pcomp = 0;
	showPacketDetails(npdu, npdu_len,1,"sndcp_llunitdata_ind()");
	printf("////////////////////////////////////////////////////////////////////////////////////////////////////////////////\n\n\n");


	return sgsn_rx_sndcp_ud_ind(&sne->ra_id, lle->llme->tlli, sne->nsapi, msg, npdu_len, npdu);
}

#if 0
/* Section 5.1.2.1 LL-RESET.ind */
static int sndcp_ll_reset_ind(struct gprs_sndcp_entity *se)
{
	/* treat all outstanding SNDCP-LLC request type primitives as not sent */
	/* reset all SNDCP XID parameters to default values */
	LOGP(DSNDCP, LOGL_NOTICE, "not implemented.\n");
	return 0;
}

static int sndcp_ll_status_ind()
{
	/* inform the SM sub-layer by means of SNSM-STATUS.req */
	LOGP(DSNDCP, LOGL_NOTICE, "not implemented.\n");
	return 0;
}

static struct sndcp_state_list {{
	uint32_t	states;
	unsigned int	type;
	int		(*rout)(struct gprs_sndcp_entity *se, struct msgb *msg);
} sndcp_state_list[] = {
	{ ALL_STATES,
	  LL_RESET_IND, sndcp_ll_reset_ind },
	{ ALL_STATES,
	  LL_ESTABLISH_IND, sndcp_ll_est_ind },
	{ SBIT(SNDCP_S_EST_RQD),
	  LL_ESTABLISH_RESP, sndcp_ll_est_ind },
	{ SBIT(SNDCP_S_EST_RQD),
	  LL_ESTABLISH_CONF, sndcp_ll_est_conf },
	{ SBIT(SNDCP_S_
};

static int sndcp_rx_llc_prim()
{
	case LL_ESTABLISH_REQ:
	case LL_RELEASE_REQ:
	case LL_XID_REQ:
	case LL_DATA_REQ:
	LL_UNITDATA_REQ,	/* TLLI, SN-PDU, Ref, QoS, Radio Prio, Ciph */

	switch (prim) {
	case LL_RESET_IND:
	case LL_ESTABLISH_IND:
	case LL_ESTABLISH_RESP:
	case LL_ESTABLISH_CONF:
	case LL_RELEASE_IND:
	case LL_RELEASE_CONF:
	case LL_XID_IND:
	case LL_XID_RESP:
	case LL_XID_CONF:
	case LL_DATA_IND:
	case LL_DATA_CONF:
	case LL_UNITDATA_IND:
	case LL_STATUS_IND:
}
#endif


/* Generate SNDCP-XID message */
static int gprs_llc_generate_sndcp_xid(uint8_t *bytes, int bytes_len, uint8_t nsapi)
{
	LLIST_HEAD(comp_fields);
	struct gprs_sndcp_hdrcomp_rfc1144_params rfc1144_params;
	struct gprs_sndcp_comp_field rfc1144_comp_field;

	struct gprs_sndcp_hdrcomp_rfc2507_params rfc2507_params;
	struct gprs_sndcp_comp_field rfc2507_comp_field;

	struct gprs_sndcp_hdrcomp_rohc_params rohc_params;
	struct gprs_sndcp_comp_field rohc_comp_field;

	memset(&rfc1144_comp_field,0,sizeof(struct gprs_sndcp_comp_field));
	memset(&rfc2507_comp_field,0,sizeof(struct gprs_sndcp_comp_field));
	memset(&rohc_comp_field,0,sizeof(struct gprs_sndcp_comp_field));



	/* Setup which NSAPIs shall make use of rfc1144 */
	rfc1144_params.nsapi[0] = nsapi;
	rfc1144_params.nsapi_len = 1;

	/* Setup rfc1144 operating parameters */
	rfc1144_params.s01 = 3;

	/* Setup rfc1144 compression field */
	rfc1144_comp_field.p = 1;
	rfc1144_comp_field.entity = 0;
	rfc1144_comp_field.algo = RFC_1144;
	rfc1144_comp_field.comp[RFC1144_PCOMP1] = 1;
	rfc1144_comp_field.comp[RFC1144_PCOMP2] = 2;
	rfc1144_comp_field.comp_len = RFC1144_PCOMP_LEN;
	rfc1144_comp_field.rfc1144_params = &rfc1144_params;



	/* Setup which NSAPIs shall make use of rfc1144 */
	rfc2507_params.nsapi[0] = nsapi;
	rfc2507_params.nsapi_len = 1;

	/* Setup rfc2507 operating parameters */
	rfc2507_params.f_max_period = 256;
	rfc2507_params.f_max_time = 5;
	rfc2507_params.max_header = 168;
	rfc2507_params.tcp_space = 15;
	rfc2507_params.non_tcp_space = 15;

	/* Setup rfc2507 compression field */
	rfc2507_comp_field.p = 1;
	rfc2507_comp_field.entity = 1;
	rfc2507_comp_field.algo = RFC_2507;
	rfc2507_comp_field.comp[RFC2507_PCOMP1] = 3;
	rfc2507_comp_field.comp[RFC2507_PCOMP2] = 4;
	rfc2507_comp_field.comp[RFC2507_PCOMP3] = 5;
	rfc2507_comp_field.comp[RFC2507_PCOMP4] = 6;
	rfc2507_comp_field.comp[RFC2507_PCOMP5] = 7;
	rfc2507_comp_field.comp_len = RFC2507_PCOMP_LEN;
	rfc2507_comp_field.rfc2507_params = &rfc2507_params;



	/* Setup which NSAPIs shall make use of ROHC */
	rohc_params.nsapi[0] = 5;
	rohc_params.nsapi[1] = 6;
	rohc_params.nsapi[2] = 7;
	rohc_params.nsapi[3] = 8;
	rohc_params.nsapi[4] = 9;
	rohc_params.nsapi[5] = 10;
	rohc_params.nsapi[6] = 11;
	rohc_params.nsapi[7] = 12;
	rohc_params.nsapi[8] = 13;
	rohc_params.nsapi[9] = 14;
	rohc_params.nsapi[10] = 15;
	rohc_params.nsapi_len = 11;

	/* Setup ROHC operating parameters */
	rohc_params.max_cid = 15; /* default */
	rohc_params.max_header = 168; /* default */
	rohc_params.profile[0] = ROHC_UNCOMPRESSED;
	rohc_params.profile[1] = ROHC_RTP;
	rohc_params.profile[2] = ROHCV2_RTP;
	rohc_params.profile[3] = ROHC_UDP;
	rohc_params.profile[4] = ROHCv2_UDP;
	rohc_params.profile[5] = ROHC_ESP;
	rohc_params.profile[6] = ROHCV2_ESP;
	rohc_params.profile[7] = ROHC_IP;
	rohc_params.profile[8] = ROHCV2_IP;
	rohc_params.profile[9] = ROHC_LLA;
	rohc_params.profile[10] = ROHC_LLA_WITH_R_MODE;
	rohc_params.profile[11] = ROHC_TCP;
	rohc_params.profile[12] = ROHC_RTP_UDP_LITE;
	rohc_params.profile[13] = ROHCV2_RTP_UDP_LITE;
	rohc_params.profile[14] = ROHC_UDP_LITE;
	rohc_params.profile[15] = ROHCV2_UDP_LITE;
	rohc_params.profile_len = 16;

	/* Setup ROHC compression field */
	rohc_comp_field.p = 1;
	rohc_comp_field.entity = 2;
	rohc_comp_field.algo = ROHC;
	rohc_comp_field.comp[ROHC_PCOMP1] = 8;
	rohc_comp_field.comp[ROHC_PCOMP2] = 9;
	rohc_comp_field.comp_len = ROHC_PCOMP_LEN;
	rohc_comp_field.rohc_params = &rohc_params;



	/* Add compression field(s) to list */
	llist_add(&rfc1144_comp_field.list, &comp_fields);
	llist_add(&rfc2507_comp_field.list, &comp_fields);
	llist_add(&rohc_comp_field.list, &comp_fields);

	/* Comile bytestream */
	return gprs_sndcp_compile_xid(&comp_fields, bytes, bytes_len);
}


/* Set of SNDCP-XID bnegotiation (See also: TS 144 065, Section 6.8 XID parameter negotiation) */
int sndcp_sn_xid_req(struct gprs_llc_lle *lle, uint8_t nsapi)
{
	uint8_t l3params_bytes[1024];
	int sndcp_xid_bytes_len;
	struct gprs_llc_xid_field xid_field_request;

	/* Generate compression parameter bytestream */
	sndcp_xid_bytes_len = gprs_llc_generate_sndcp_xid(l3params_bytes, sizeof(l3params_bytes), nsapi);


	/* Proceed with sending the XID with the SNDCP-XID bytetsream included */
	if(sndcp_xid_bytes_len > 0)
	{
		xid_field_request.type = GPRS_LLC_XID_T_L3_PAR;
		xid_field_request.data = l3params_bytes;
		xid_field_request.data_len = sndcp_xid_bytes_len;
		return gprs_ll_xid_req(lle,&xid_field_request);
	}

	/* When bytestream can not be generated, silently proceed without SNDCP-XID */
	else
	{
		LOGP(DLLC, LOGL_ERROR, "SNDCP-XID-Message generation failed, SNDCP-XID not sent!\n");
		return gprs_ll_xid_req(lle,NULL);
	}
}

/* Process SNDCP-XID indication (See also: TS 144 065, Section 6.8 XID parameter negotiation) */
int sndcp_sn_xid_ind(struct gprs_llc_xid_field *xid_field_indication, struct gprs_llc_xid_field *xid_field_response, struct gprs_llc_lle *lle)
{
	/* Note: This function computes the SNDCP-XID response that is sent 
                 back to the phone when an phone originated XID is received */

	int rc;
	LLIST_HEAD(comp_fields);
	struct gprs_sndcp_comp_field *comp_field;


	/* Parse SNDCP-CID XID-Field */
	rc = gprs_sndcp_parse_xid(&comp_fields, xid_field_indication->data, xid_field_indication->data_len, NULL, 0);

	if(rc >= 0)
	{
		LOGP(DSNDCP, LOGL_DEBUG, "Unmodified SNDCP-XID as received:\n");
		gprs_sndcp_dump_comp_fields(&comp_fields);


		llist_for_each_entry(comp_field, &comp_fields, list) 
		{
			/* Delete propose bit */
			comp_field->p = 0;
			
			/* Process proposed parameters */
			switch(comp_field->algo)
			{
				case RFC_1144:
#if GPRS_SNDCP_HDRCOMP_BYPASS == 1
					/* RFC 1144 is not yet supported, so we set applicable nsapis to zero */
					comp_field->rfc1144_params->nsapi_len = 0;
					LOGP(DSNDCP, LOGL_DEBUG, "Rejecting RFC1144 header conpression...\n");
					gprs_sndcp_comp_entities_delete(&lle->llme->comp.proto, comp_field->entity);
#else
					LOGP(DSNDCP, LOGL_DEBUG, "Accepting RFC1144 header conpression...\n");
					gprs_sndcp_comp_entities_add(&lle->llme->comp.proto, comp_field);
#endif
				break;
				case RFC_2507:
					/* RFC 2507 is not yet supported, so we set applicable nsapis to zero */
					LOGP(DSNDCP, LOGL_DEBUG, "Rejecting RFC2507 header conpression...\n");
					comp_field->rfc2507_params->nsapi_len = 0;
					gprs_sndcp_comp_entities_delete(&lle->llme->comp.proto, comp_field->entity);
				break;
				case ROHC:
					/* ROHC is not yet supported, so we set applicable nsapis to zero */
					LOGP(DSNDCP, LOGL_DEBUG, "Rejecting ROHC header conpression...\n");
					comp_field->rohc_params->nsapi_len = 0;
					gprs_sndcp_comp_entities_delete(&lle->llme->comp.proto, comp_field->entity);
				break;
			}
		}

		LOGP(DSNDCP, LOGL_DEBUG, "Modified version of received SNDCP-XID to be sent back:\n");
		gprs_sndcp_dump_comp_fields(&comp_fields);


		/* Reserve some memory to store the modified SNDCP-XID bytes */
		xid_field_response->data = talloc_zero_size(NULL, xid_field_indication->data_len);

		/* Set Type flag for response */
		xid_field_response->type=GPRS_LLC_XID_T_L3_PAR;

		/* Compile modified SNDCP-XID bytes */
		rc = gprs_sndcp_compile_xid(&comp_fields, xid_field_response->data, xid_field_indication->data_len);

		if(rc > 0)
			xid_field_response->data_len = rc;
		else
		{
			talloc_free(xid_field_response->data);
			xid_field_response->data = NULL;
			xid_field_response->data_len = 0;
			return -EINVAL;
		}
	}

	gprs_sndcp_free_comp_fields(&comp_fields);

	return 0;
}

