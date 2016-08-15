/* GPRS SNDCP header compression handler */

/* (C) 2016 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Philipp Maier
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

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <errno.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gsm/tlv.h>

#include <openbsc/gprs_llc.h>
#include <openbsc/sgsn.h>
#include <openbsc/gprs_sndcp_xid.h>
#include <openbsc/slhc.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_sndcp_comp.h>
#include <openbsc/gprs_sndcp_pcomp.h>

#define DEBUG_RFC1144 1

/* Show details of the RFC1144 compressed packet header */
static void debug_rfc1144_header(uint8_t *header)
{
#if DEBUG_RFC1144 == 1

	int t,c,i,p,s,a,w,u = 0;
	t = (header[0] >> 7) & 1;
	c = (header[0] >> 6) & 1;
	i = (header[0] >> 5) & 1;
	p = (header[0] >> 4) & 1;
	s = (header[0] >> 3) & 1;
	a = (header[0] >> 2) & 1;
	w = (header[0] >> 1) & 1;
	u = header[0] & 1;

	DEBUGP(DSNDCP,"rfc1144 header:\n");
	DEBUGP(DSNDCP," Tag bit = %d\n",t);
	DEBUGP(DSNDCP," C = %d\n",c);
	DEBUGP(DSNDCP," I = %d\n",i);
	DEBUGP(DSNDCP," P = %d\n",p);
	DEBUGP(DSNDCP," S = %d\n",s);
	DEBUGP(DSNDCP," A = %d\n",a);
	DEBUGP(DSNDCP," W = %d\n",w);
	DEBUGP(DSNDCP," U = %d\n",u);

	header++;
	if(c) {
		DEBUGP(DSNDCP," Connection number (C) = %d\n",*header);
		header++;
	}

	DEBUGP(DSNDCP," TCP Checksum = %02x%02x\n",header[0],header[1]);
	header+=2;

	if(s && w && u)	{
		DEBUGP(DSNDCP," Special case I (SPECIAL_I) => short header\n");
		return;
	} else if(s && a && w && u) {
		DEBUGP(DSNDCP," Special case D (SPECIAL_D) => short header\n");
		return;
	}

	if(u) {
		DEBUGP(DSNDCP," Urgent Pointer (U) = %02x\n",*header);
		header++;
	}
	if(w) {
		DEBUGP(DSNDCP," Delta Window (W) = %02x\n",*header);
		header++;
	}
	if(a) {
		DEBUGP(DSNDCP," Delta Ack (A) = %02x\n",*header);
		header++;
	}
	if(s) {
		DEBUGP(DSNDCP," Delta Sequence (S) = %02x\n",*header);
		header++;
	}
	if(i) {
		DEBUGP(DSNDCP," Delta IP ID (I) = %02x\n",*header);
		header++;
	}

	/* FIXME: Header values will be usually fit in 8 bits, implement
	 * implement variable length decoding for values larger then 8 bit */
#endif
}


/* Initalize header compression */
int gprs_sndcp_pcomp_init(const void *ctx, struct gprs_sndcp_comp *comp_entity,
			  const struct gprs_sndcp_comp_field *comp_field)
{
	/* Note: This function is automatically called from
	 * gprs_sndcp_comp.c when a new header compression
	 * entity is created by gprs_sndcp.c */

	if (comp_entity->compclass == SNDCP_XID_PROTOCOL_COMPRESSION
	    && comp_entity->algo == RFC_1144) {
		comp_entity->state =
		    slhc_init(ctx, comp_field->rfc1144_params->s01 + 1,
			      comp_field->rfc1144_params->s01 + 1);
		LOGP(DSNDCP, LOGL_INFO,
		     "RFC1144 header compression initalized.\n");
		return 0;
	}

	/* Just in case someone tries to initalize an unknown or unsupported
	 * header compresson. Since everything is checked during the SNDCP
	 * negotiation process, this should never happen! */
	OSMO_ASSERT(false);
}

/* Terminate header compression */
void gprs_sndcp_pcomp_term(struct gprs_sndcp_comp *comp_entity)
{
	/* Note: This function is automatically called from
	 * gprs_sndcp_comp.c when a header compression
	 * entity is deleted by gprs_sndcp.c */

	if (comp_entity->compclass == SNDCP_XID_PROTOCOL_COMPRESSION
	    && comp_entity->algo == RFC_1144) {
		if (comp_entity->state) {
			slhc_free((struct slcompress *)comp_entity->state);
			comp_entity->state = NULL;
		}
		LOGP(DSNDCP, LOGL_INFO,
		     "RFC1144 header compression terminated.\n");
		return;
	}

	/* Just in case someone tries to initalize an unknown or unsupported
	 * header compresson. Since everything is checked during the SNDCP
	 * negotiation process, this should never happen! */
	OSMO_ASSERT(false);
}

/* Compress a packet using Van Jacobson RFC1144 header compression */
static int gprs_sndcp_pcomp_rfc1144_compress(int *pcomp_index, uint8_t *data_o,
					     uint8_t *data_i, int len,
					     struct slcompress *comp)
{
	uint8_t *comp_ptr;	/* Not used */
	int compr_len;

	/* Create a working copy of the incoming data */
	memcpy(data_o, data_i, len);

	/* Run compressor */
	compr_len = slhc_compress(comp, data_i, len, data_o, &comp_ptr, 0);

	/* Generate pcomp_index */
	if (data_o[0] & SL_TYPE_COMPRESSED_TCP) {
		*pcomp_index = 2;
		data_o[0] &= ~SL_TYPE_COMPRESSED_TCP;
		debug_rfc1144_header(data_o);
	} else if ((data_o[0] & SL_TYPE_UNCOMPRESSED_TCP) ==
		   SL_TYPE_UNCOMPRESSED_TCP) {
		*pcomp_index = 1;
		data_o[0] &= 0x4F;
	} else
		*pcomp_index = 0;

	return compr_len;
}

/* Expand a packet using Van Jacobson RFC1144 header compression */
static int gprs_sndcp_pcomp_rfc1144_expand(uint8_t *data_o, uint8_t *data_i,
					   int len, int pcomp_index,
					   struct slcompress *comp)
{
	int data_decompressed_len;
	int type = -1;

	/* Note: this function should never be called with pcomp_index=0,
	 * since this condition is already filtered
	 * out by gprs_sndcp_pcomp_expand() */

	/* Determine the data type by the PCOMP index */
	switch (pcomp_index) {
	case 1:
		type = SL_TYPE_UNCOMPRESSED_TCP;
		break;
	case 2:
		type = SL_TYPE_COMPRESSED_TCP;
		break;
	}

	/* Create a working copy of the incoming data */
	memcpy(data_o, data_i, len);

	/* Restore the original version nibble on
	 * marked uncompressed packets */
	if (type == SL_TYPE_UNCOMPRESSED_TCP) {

		/* Just in case the phone tags uncompressed tcp-datas
		 * (normally this is handled by pcomp so there is
		 * no need for tagging the datas) */
		data_o[0] &= 0x4F;
		data_decompressed_len = slhc_remember(comp, data_o, len);
		return data_decompressed_len;
	}

	/* Uncompress compressed packets */
	else if (type == SL_TYPE_COMPRESSED_TCP) {
		data_decompressed_len = slhc_uncompress(comp, data_o, len);
		return data_decompressed_len;
	}

	/* Regular or unknown packets will not be touched */
	return len;
}

/* Expand packet header */
int gprs_sndcp_pcomp_expand(uint8_t *data_o, uint8_t *data_i, int len,
			    int pcomp, const struct llist_head *comp_entities)
{
	int rc;
	int pcomp_index = 0;
	struct gprs_sndcp_comp *comp_entity;

	OSMO_ASSERT(data_o);
	OSMO_ASSERT(data_i);
	OSMO_ASSERT(comp_entities);

	/* Skip on pcomp=0 */
	if (pcomp == 0) {
		memcpy(data_o,data_i,len);
		return len;
	}

	/* Find out which compression entity handles the data */
	comp_entity = gprs_sndcp_comp_by_comp(comp_entities, pcomp);

	/* Skip compression if no suitable compression entity can be found */
	if (comp_entity == NULL) {
		memcpy(data_o,data_i,len);
		return len;
	}

	/* Note: Only protocol compression entities may appear in
	 * protocol compression context */
	OSMO_ASSERT(comp_entity->compclass == SNDCP_XID_PROTOCOL_COMPRESSION);

	/* Note: Currently RFC1144 is the only compression method we
	 * support, so the only allowed algorithm is RFC1144 */
	OSMO_ASSERT(comp_entity->algo == RFC_1144);

	/* Find pcomp_index */
	pcomp_index = gprs_sndcp_comp_get_idx(comp_entity, pcomp);

	/* Run decompression algo */
	rc = gprs_sndcp_pcomp_rfc1144_expand(data_o, data_i, len, pcomp_index,
					     comp_entity->state);
	slhc_i_status(comp_entity->state);
	slhc_o_status(comp_entity->state);

	LOGP(DSNDCP, LOGL_DEBUG,
	     "Header expansion done, old length=%i, new length=%i\n",
	     len, rc);

	return rc;
}

/* Compress packet header */
int gprs_sndcp_pcomp_compress(uint8_t *data_o, uint8_t *data_i, int len,
			      int *pcomp,
			      const struct llist_head *comp_entities, int nsapi)
{
	int rc;
	int pcomp_index = 0;
	struct gprs_sndcp_comp *comp_entity;

	OSMO_ASSERT(data_o);
	OSMO_ASSERT(data_i);
	OSMO_ASSERT(pcomp);
	OSMO_ASSERT(comp_entities);

	/* Find out which compression entity handles the data */
	comp_entity = gprs_sndcp_comp_by_nsapi(comp_entities, nsapi);

	/* Skip compression if no suitable compression entity can be found */
	if (!comp_entity) {
		*pcomp = 0;
		memcpy(data_o,data_i,len);
		return len;
	}

	/* Note: Only protocol compression entities may appear in
	 * protocol compression context */
	OSMO_ASSERT(comp_entity->compclass == SNDCP_XID_PROTOCOL_COMPRESSION);

	/* Note: Currently RFC1144 is the only compression method we
	 * support, so the only allowed algorithm is RFC1144 */
	OSMO_ASSERT(comp_entity->algo == RFC_1144);

	/* Run compression algo */
	rc = gprs_sndcp_pcomp_rfc1144_compress(&pcomp_index, data_o, data_i,
					       len, comp_entity->state);
	slhc_i_status(comp_entity->state);
	slhc_o_status(comp_entity->state);

	/* Find pcomp value */
	*pcomp = gprs_sndcp_comp_get_comp(comp_entity, pcomp_index);

	LOGP(DSNDCP, LOGL_DEBUG,
	     "Header compression done, old length=%i, new length=%i\n",
	     len, rc);
	return rc;
}
