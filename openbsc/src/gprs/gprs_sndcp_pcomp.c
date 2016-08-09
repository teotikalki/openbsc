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
			slhc_free((struct slcompress *) comp_entity->
				  state);
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


/* Display compressor status */
static void gprs_sndcp_pcomp_rfc1144_stat(struct slcompress *comp)
{
	slhc_i_status(comp);
	slhc_o_status(comp);
}


/* Compress a packet using Van Jacobson RFC1144 header compression */
static int gprs_sndcp_pcomp_rfc1144_compress(struct slcompress *comp,
					       uint8_t * packet,
					       int packet_len,
					       int *pcomp_index)
{
	uint8_t *packet_compressed;
	uint8_t *packet_compressed_ptr;	/* Not used */
	int packet_compressed_len;

	/* Reserve some space for to store the compression result */
	packet_compressed = talloc_zero_size(NULL, packet_len);

	/* Run compressor */
	memcpy(packet_compressed, packet, packet_len);
	packet_compressed_len =
	    slhc_compress(comp, packet, packet_len,
			  (uint8_t *) packet_compressed,
			  &packet_compressed_ptr, 0);

	/* Copy back compression result */
	memcpy(packet, packet_compressed, packet_len);
	talloc_free(packet_compressed);

	/* Generate pcomp_index */
	if ((packet[0] & SL_TYPE_COMPRESSED_TCP) == SL_TYPE_COMPRESSED_TCP) {
		*pcomp_index = 2;
	} else if ((packet[0] & SL_TYPE_UNCOMPRESSED_TCP) ==
		   SL_TYPE_UNCOMPRESSED_TCP) {
		*pcomp_index = 1;

		/* Remove tag for uncompressed TCP, because the
		 * packet type is already define by pcomp */
		packet[0] &= 0x4F;	
	} else
		*pcomp_index = 0;

	return packet_compressed_len;
}

/* Expand a packet using Van Jacobson RFC1144 header compression */
static int gprs_sndcp_pcomp_rfc1144_expand(struct slcompress *comp,
					     uint8_t * packet,
					     int packet_len,
					     int pcomp_index)
{
	int packet_decompressed_len;
	int type = -1;

	/* Note: this function should never be called with pcomp_index=0,
	 * since this condition is already filtered
	 * out by gprs_sndcp_pcomp_expand() */

	/* Determine the packet type by the PCOMP index */
	switch (pcomp_index) {
	case 1:
		type = SL_TYPE_UNCOMPRESSED_TCP;
		break;
	case 2:
		type = SL_TYPE_COMPRESSED_TCP;
		break;
	}

	/* Restore the original version nibble on
	 * marked uncompressed packets */
	if (type == SL_TYPE_UNCOMPRESSED_TCP) {
		LOGP(DSNDCP, LOGL_INFO,
		     "Uncompressed rfc1144 packet received...\n");


		/* Just in case the phone tags uncompressed tcp-packets
		 * (normally this is handled by pcomp so there is
		 * no need for tagging the packets) */
		packet[0] &= 0x4F;
		packet_decompressed_len =
		    slhc_remember(comp, packet, packet_len);
		return packet_decompressed_len;
	}

	/* Uncompress compressed packets */
	else if (type == SL_TYPE_COMPRESSED_TCP) {
		LOGP(DSNDCP, LOGL_INFO,
		     "Compressed rfc1144 packet received...\n");
		packet_decompressed_len =
		    slhc_uncompress(comp, packet, packet_len);
		return packet_decompressed_len;
	}


	/* Regular or unknown packets will not be touched */
	return packet_len;
}


/* Expand header compressed packet */
int gprs_sndcp_pcomp_expand(uint8_t * packet, int packet_len, int pcomp,
			      const struct llist_head *comp_entities)
{
	int rc;
	int pcomp_index = 0;
	struct gprs_sndcp_comp *comp_entity;

	/* Skip on pcomp=0 */
	if (pcomp == 0) {
		LOGP(DSNDCP, LOGL_INFO,
		     "Uncompressed packet received (pcomp=0), skipping compression...\n");
		return packet_len;
	}

	/* Find out which compression entity handles the packet */
	comp_entity =
	    gprs_sndcp_comp_by_comp(comp_entities, pcomp);

	/* Skip compression if no suitable compression entity can be found! */
	if (comp_entity == NULL) {
		LOGP(DSNDCP, LOGL_ERROR,
		     "Compressed packet received (pcomp=%i) but no suitable compression entity found, skipping compression...\n",
		     pcomp);
		return packet_len;
	}


	/* Note: Only protocol compression entities may appear in 
	 * protocol compression context */
	OSMO_ASSERT(comp_entity->compclass == SNDCP_XID_PROTOCOL_COMPRESSION)

	/* Note: Currently RFC1144 is the only compression method we
	 * support, so the only allowed algorithm is RFC1144 */
	OSMO_ASSERT(comp_entity->algo == RFC_1144)


	/* Find pcomp_index */
	pcomp_index = gprs_sndcp_comp_get_idx(comp_entity, pcomp);

	/* Run decompression algo */	
	rc = gprs_sndcp_pcomp_rfc1144_expand((struct slcompress *)
					       comp_entity->state, packet,
					       packet_len, pcomp_index);
	gprs_sndcp_pcomp_rfc1144_stat((struct slcompress *) comp_entity->
					state);


	LOGP(DSNDCP, LOGL_DEBUG,
	     "Header expansion done, old length=%i, new length=%i, pcomp=%i, pcomp_index=%i\n",
	     packet_len, rc, pcomp, pcomp_index);

	return rc;
}


/* Expand header compressed packet */
int gprs_sndcp_pcomp_compress(uint8_t * packet, int packet_len,
				int *pcomp,
				const struct llist_head *comp_entities,
				int nsapi)
{
	int rc;
	int pcomp_index = 0;
	struct gprs_sndcp_comp *comp_entity;

	/* Find out which compression entity handles the packet */
	comp_entity = gprs_sndcp_comp_by_nsapi(comp_entities, nsapi);

	/* Skip compression if no suitable compression entity can be found! */
	if (comp_entity == NULL) {
		LOGP(DSNDCP, LOGL_INFO,
		     "No suitable compression entity found for nsapi %i, skipping compression...\n",
		     nsapi);
		*pcomp = 0;
		return packet_len;
	}


	/* Note: Only protocol compression entities may appear in 
	 * protocol compression context */
	OSMO_ASSERT(comp_entity->compclass == SNDCP_XID_PROTOCOL_COMPRESSION)

	/* Note: Currently RFC1144 is the only compression method we
	 * support, so the only allowed algorithm is RFC1144 */
	OSMO_ASSERT(comp_entity->algo == RFC_1144)


	/* Run compression algo */	
	rc = gprs_sndcp_pcomp_rfc1144_compress((struct slcompress *)
						 comp_entity->state,
						 packet, packet_len,
						 &pcomp_index);
	gprs_sndcp_pcomp_rfc1144_stat((struct slcompress *) comp_entity-> state);

	/* Find pcomp value */
	*pcomp = gprs_sndcp_comp_get_comp(comp_entity, pcomp_index);

	LOGP(DSNDCP, LOGL_DEBUG,
	     "Header compression done, old length=%i, new length=%i, pcomp=%i, pcomp_index=%i\n",
	     packet_len, rc, *pcomp, pcomp_index);
	return rc;
}


