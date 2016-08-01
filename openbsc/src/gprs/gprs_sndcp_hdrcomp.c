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
#include <openbsc/gprs_sndcp_comp_entity.h>
#include <openbsc/gprs_sndcp_hdrcomp.h>

/* Enable private debug messages */
#define GPRS_SNDCP_HDRCOMP_DEBUG 1

/* Test RFC1144 implementation 
   (Caution: GPRS_SNDCP_HDRCOMP_BYPASS in .h file has to be set to 1!) */
#define GPRS_SNDCP_HDRCOMP_RFC1144_TEST 0

/* Exit immediately in case of RFC1144 test failure */
#define GPRS_SNDCP_HDRCOMP_RFC1144_TEST_EXITONERR 1

/* For debug/test only! */
#if GPRS_SNDCP_HDRCOMP_RFC1144_TEST == 1
static struct slcompress *test_compression_state_tx = NULL;
static struct slcompress *test_compression_state_rx = NULL;
static int test_errors = 0;
static int gprs_sndcp_hdrcomp_test_ind(uint8_t * packet, int packet_len);
static int gprs_sndcp_hdrcomp_test_req(uint8_t * packet, int packet_len);
#endif


/* Initalize header compression */
int gprs_sndcp_hdrcomp_init(struct gprs_sndcp_comp_entity *comp_entity,
			    struct gprs_sndcp_comp_field *comp_field)
{
	/* Note: This function is automatically called from
		 gprs_sndcp_comp_entity.c when a new header compression
		 entity is created by gprs_sndcp.c */

	if ((comp_entity->compclass == SNDCP_XID_PROTOCOL_COMPRESSION)
	    && (comp_entity->algo == RFC_1144)) {
		comp_entity->status =
		    slhc_init(comp_field->rfc1144_params->s01 + 1,
			      comp_field->rfc1144_params->s01 + 1);
		LOGP(DSNDCP, LOGL_INFO,
		     "RFC1144 header compression initalized.\n");
		return 0;
	}

	/* Just in case someone tries to initalize an unknown or unsupported
	   header compresson. Since everything is checked during the SNDCP
	   negotiation process, this should never happen! */
	LOGP(DSNDCP, LOGL_ERROR,
	     "Unknown or unsupported header compression type requested for initalization, could not initalize...\n");
	return -EINVAL;

}


/* Terminate header compression */
void gprs_sndcp_hdrcomp_term(struct gprs_sndcp_comp_entity *comp_entity)
{
	/* Note: This function is automatically called from
	   gprs_sndcp_comp_entity.c when a header compression
	   entity is deleted by gprs_sndcp.c */

	if ((comp_entity->compclass == SNDCP_XID_PROTOCOL_COMPRESSION)
	    && (comp_entity->algo == RFC_1144)) {
		if (comp_entity->status) {
			slhc_free((struct slcompress *) comp_entity->
				  status);
			comp_entity->status = NULL;
		}
		LOGP(DSNDCP, LOGL_INFO,
		     "RFC1144 header compression terminated.\n");
		return;
	}

	/* Just in case someone tries to initalize an unknown or unsupported
	   header compresson. Since everything is checked during the SNDCP
	   negotiation process, this should never happen! */
	LOGP(DSNDCP, LOGL_ERROR,
	     "Unknown or unsupported header compression type requested for termiation, could not initalize...\n");
}


/* Display compressor status */
static void gprs_sndcp_hdrcomp_rfc1144_stat(struct slcompress *comp)
{
	slhc_i_status(comp);
	slhc_o_status(comp);
}


/* Compress a packet using Van Jacobson RFC1144 header compression */
static int gprs_sndcp_hdrcomp_rfc1144_compress(struct slcompress *comp,
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
		/* Remove tag for compressed TCP, because the packet
		   type is already define by pcomp */
		//      packet[0] &= 0x7F;      
	} else if ((packet[0] & SL_TYPE_UNCOMPRESSED_TCP) ==
		   SL_TYPE_UNCOMPRESSED_TCP) {
		*pcomp_index = 1;

		/* Remove tag for uncompressed TCP, because the
		   packet type is already define by pcomp */
		packet[0] &= 0x4F;	
	} else
		*pcomp_index = 0;

	return packet_compressed_len;
}

/* Expand a packet using Van Jacobson RFC1144 header compression */
static int gprs_sndcp_hdrcomp_rfc1144_expand(struct slcompress *comp,
					     uint8_t * packet,
					     int packet_len,
					     int pcomp_index)
{
	int packet_decompressed_len;
	int type = -1;

	/* Note: this function should never be called with pcomp_index=0,
	   since this condition is already filtered
	   out by gprs_sndcp_hdrcomp_expand() */

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
	   marked uncompressed packets */
	if (type == SL_TYPE_UNCOMPRESSED_TCP) {
		LOGP(DSNDCP, LOGL_INFO,
		     "Uncompressed rfc1144 packet received...\n");


		/* Just in case the phone tags uncompressed tcp-packets
		   (normally this is handled by pcomp so there is
		   no need for tagging the packets) */
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
int gprs_sndcp_hdrcomp_expand(uint8_t * packet, int packet_len, int pcomp,
			      struct llist_head *comp_entities)
{
	int rc;
	int pcomp_index = 0;
	struct gprs_sndcp_comp_entity *comp_entity;

	/* Skip on pcomp=0 */
	if (pcomp == 0) {
		LOGP(DSNDCP, LOGL_INFO,
		     "Uncompressed packet received (pcomp=0), skipping compression...\n");
		return packet_len;
	}

	/* Find out which compression entity handles the packet */
	comp_entity =
	    gprs_sndcp_comp_entity_find_by_comp(comp_entities, pcomp);

	/* Skip compression if no suitable compression entity can be found! */
	if (comp_entity == NULL) {
		LOGP(DSNDCP, LOGL_ERROR,
		     "Compressed packet received (pcomp=%i) but no suitable compression entity found, skipping compression...\n",
		     pcomp);
		return packet_len;
	}

	/* Find pcomp_index */
	pcomp_index =
	    gprs_sndcp_comp_entity_find_comp_index_by_comp(comp_entity,
							   pcomp);

#if GPRS_SNDCP_HDRCOMP_RFC1144_TEST == 1
	/* Test mode */
	LOGP(DSNDCP, LOGL_INFO,
	     "gprs_sndcp_hdrcomp_expand(): testing compression...!\n");
	rc = gprs_sndcp_hdrcomp_test_ind(packet, packet_len);
#else
	/* Normal operation: */
	rc = gprs_sndcp_hdrcomp_rfc1144_expand((struct slcompress *)
					       comp_entity->status, packet,
					       packet_len, pcomp_index);
	gprs_sndcp_hdrcomp_rfc1144_stat((struct slcompress *) comp_entity->
					status);
#endif

	LOGP(DSNDCP, LOGL_DEBUG,
	     "Header expansion done, old length=%i, new length=%i, pcomp=%i, pcomp_index=%i\n",
	     packet_len, rc, pcomp, pcomp_index);
	return rc;
}


/* Expand header compressed packet */
int gprs_sndcp_hdrcomp_compress(uint8_t * packet, int packet_len,
				int *pcomp,
				struct llist_head *comp_entities,
				int nsapi)
{
	int rc;
	int pcomp_index = 0;
	struct gprs_sndcp_comp_entity *comp_entity;

	/* Find out which compression entity handles the packet */
	comp_entity =
	    gprs_sndcp_comp_entity_find_by_nsapi(comp_entities, nsapi);

	/* Skip compression if no suitable compression entity can be found! */
	if (comp_entity == NULL) {
		LOGP(DSNDCP, LOGL_INFO,
		     "No suitable compression entity found for nsapi %i, skipping compression...\n",
		     nsapi);
		*pcomp = 0;
		return packet_len;
	}
#if GPRS_SNDCP_HDRCOMP_RFC1144_TEST == 1
	LOGP(DSNDCP, LOGL_INFO,
	     "gprs_sndcp_hdrcomp_expand(): testing compression...!\n");
	rc = gprs_sndcp_hdrcomp_test_req(packet, packet_len);
	*pcomp = 0;
	return rc;
#else
	/* Normal operation: */
	rc = gprs_sndcp_hdrcomp_rfc1144_compress((struct slcompress *)
						 comp_entity->status,
						 packet, packet_len,
						 &pcomp_index);
	gprs_sndcp_hdrcomp_rfc1144_stat((struct slcompress *) comp_entity->
					status);
#endif

	/* Find pcomp value */
	*pcomp =
	    gprs_sndcp_comp_entity_find_comp_by_comp_index(comp_entity,
							   pcomp_index);

	LOGP(DSNDCP, LOGL_DEBUG,
	     "Header compression done, old length=%i, new length=%i, pcomp=%i, pcomp_index=%i\n",
	     packet_len, rc, *pcomp, pcomp_index);
	return rc;
}







#if GPRS_SNDCP_HDRCOMP_RFC1144_TEST == 1

/* 
 * This is a test implementation to make sure the rfc1144 compression
 * implementation works as expected. All data is first compressed and
 * decompressed on both directions. 
 */

/* FIXME: FOR EXPERIMENTATION ONLY! REMOVE AS SOON AS POSSIBLE */
static uint16_t header_checksum(uint8_t * iph, unsigned int ihl)
{
	int i;
	uint16_t temp;
	uint32_t accumulator = 0xFFFF;

	for (i = 0; i < ihl * 2; i++) {
		temp = ((*iph) << 8) & 0xFF00;
		iph++;
		temp |= (*iph) & 0xFF;
		iph++;

		accumulator += temp;
		if (accumulator > 0xFFFF) {
			accumulator++;
			accumulator &= 0xFFFF;
		}
	}

	return (uint16_t) (htons(~accumulator) & 0xFFFF);
}

/* Check packet integrity */
static int gprs_sndcp_hdrcomp_test_check_packet(uint8_t * packet,
						uint8_t * packet_backup,
						int packet_len,
						int
						packet_len_uncompressed)
{
	uint16_t checksum;

	if (packet_len != packet_len_uncompressed) {
		LOGP(DSNDCP, LOGL_INFO,
		     "prs_sndcp_hdrcomp_test_check_packet(): Error: Packet length mismatch!\n");
#if GPRS_SNDCP_HDRCOMP_RFC1144_TEST_EXITONERR == 1
		exit(1);
#endif
		return -1;
	}

	/* Check packet integrety */
	if (memcmp(packet, packet_backup, packet_len)) {
		LOGP(DSNDCP, LOGL_INFO,
		     "prs_sndcp_hdrcomp_test_check_packet(): Warning: Packet content!\n");
		LOGP(DSNDCP, LOGL_INFO,
		     "prs_sndcp_hdrcomp_test_check_packet(): %s\n",
		     osmo_hexdump_nospc(packet_backup, 80));
		LOGP(DSNDCP, LOGL_INFO,
		     "prs_sndcp_hdrcomp_test_check_packet(): %s\n",
		     osmo_hexdump_nospc(packet, 80));

		checksum = header_checksum(packet, 5);
		LOGP(DSNDCP, LOGL_INFO,
		     "prs_sndcp_hdrcomp_test_check_packet():  %04x\n",
		     checksum);

		if (checksum == 0x0000) {
			LOGP(DSNDCP, LOGL_INFO,
			     "prs_sndcp_hdrcomp_test_check_packet(): Checksum looks good!\n");

			if (memcmp
			    (packet + 20, packet_backup + 20,
			     packet_len - 20))
				test_errors++;
			else
				LOGP(DSNDCP, LOGL_INFO,
				     "prs_sndcp_hdrcomp_test_check_packet(): Packet looks also good!\n");
		} else {
			test_errors++;
#if GPRS_SNDCP_HDRCOMP_RFC1144_TEST_EXITONERR == 1
			exit(1);
#endif
			return -1;
		}
	}

	return 0;
}

/* FIXME: FOR EXPERIMENTATION ONLY! REMOVE AS SOON AS POSSIBLE */
static int gprs_sndcp_hdrcomp_test_ind(uint8_t * packet, int packet_len)
{
	int packet_len_compressed;
	int packet_len_uncompressed;
	int pcomp;
	uint8_t *packet_backup;

	if (test_compression_state_tx == NULL)
		test_compression_state_tx = slhc_init(8, 8);
	if (test_compression_state_rx == NULL)
		test_compression_state_rx = slhc_init(8, 8);

	LOGP(DSNDCP, LOGL_INFO,
	     "gprs_sndcp_hdrcomp_test_ind(): packet_len=%i\n", packet_len);
	packet_backup = talloc_zero_size(NULL, packet_len);
	memcpy(packet_backup, packet, packet_len);

	LOGP(DSNDCP, LOGL_INFO,
	     "gprs_sndcp_hdrcomp_test_ind(): IND:          %s\n",
	     osmo_hexdump_nospc(packet, packet_len));
	packet_len_compressed =
	    gprs_sndcp_hdrcomp_rfc1144_compress(test_compression_state_rx,
						packet, packet_len,
						&pcomp);
	LOGP(DSNDCP, LOGL_INFO,
	     "gprs_sndcp_hdrcomp_test_ind(): IND (COMP):   %s\n",
	     osmo_hexdump_nospc(packet, packet_len_compressed));
	packet_len_uncompressed =
	    gprs_sndcp_hdrcomp_rfc1144_expand(test_compression_state_tx,
					      packet,
					      packet_len_compressed,
					      pcomp);
	LOGP(DSNDCP, LOGL_INFO,
	     "gprs_sndcp_hdrcomp_test_ind(): IND (DECOMP): %s\n",
	     osmo_hexdump_nospc(packet, packet_len_uncompressed));
	LOGP(DSNDCP, LOGL_INFO,
	     "gprs_sndcp_hdrcomp_test_ind(): packet_len=%i   packet_len_compressed=%i   packet_len_uncompressed=%i\n",
	     packet_len, packet_len_compressed, packet_len_uncompressed);

	gprs_sndcp_hdrcomp_test_check_packet(packet, packet_backup,
					     packet_len,
					     packet_len_uncompressed);
	talloc_free(packet_backup);
	gprs_sndcp_hdrcomp_rfc1144_stat(test_compression_state_rx);
	gprs_sndcp_hdrcomp_rfc1144_stat(test_compression_state_tx);
	LOGP(DSNDCP, LOGL_INFO,
	     "gprs_sndcp_hdrcomp_test_ind(): Test errors: %i\n",
	     test_errors);
	return packet_len;
}

/* FIXME: FOR EXPERIMENTATION ONLY! REMOVE AS SOON AS POSSIBLE */
static int gprs_sndcp_hdrcomp_test_req(uint8_t * packet, int packet_len)
{
	int packet_len_compressed;
	int packet_len_uncompressed;
	int pcomp;
	uint8_t *packet_backup;

	if (test_compression_state_tx == NULL)
		test_compression_state_tx = slhc_init(8, 8);
	if (test_compression_state_rx == NULL)
		test_compression_state_rx = slhc_init(8, 8);

	LOGP(DSNDCP, LOGL_INFO,
	     "gprs_sndcp_hdrcomp_test_req(): packet_len=%i\n", packet_len);
	packet_backup = talloc_zero_size(NULL, packet_len);
	memcpy(packet_backup, packet, packet_len);

	LOGP(DSNDCP, LOGL_INFO,
	     "gprs_sndcp_hdrcomp_test_req(): REQ:          %s\n",
	     osmo_hexdump_nospc(packet, packet_len));
	packet_len_compressed =
	    gprs_sndcp_hdrcomp_rfc1144_compress(test_compression_state_tx,
						packet, packet_len,
						&pcomp);
	LOGP(DSNDCP, LOGL_INFO,
	     "gprs_sndcp_hdrcomp_test_req(): REQ (COMP):   %s\n",
	     osmo_hexdump_nospc(packet, packet_len_compressed));
	packet_len_uncompressed =
	    gprs_sndcp_hdrcomp_rfc1144_expand(test_compression_state_rx,
					      packet,
					      packet_len_compressed,
					      pcomp);
	LOGP(DSNDCP, LOGL_INFO,
	     "gprs_sndcp_hdrcomp_test_req(): REQ (DECOMP): %s\n",
	     osmo_hexdump_nospc(packet, packet_len_uncompressed));
	LOGP(DSNDCP, LOGL_INFO,
	     "gprs_sndcp_hdrcomp_test_req(): packet_len=%i   packet_len_compressed=%i   packet_len_uncompressed=%i\n",
	     packet_len, packet_len_compressed, packet_len_uncompressed);

	gprs_sndcp_hdrcomp_test_check_packet(packet, packet_backup,
					     packet_len,
					     packet_len_uncompressed);
	talloc_free(packet_backup);
	gprs_sndcp_hdrcomp_rfc1144_stat(test_compression_state_rx);
	gprs_sndcp_hdrcomp_rfc1144_stat(test_compression_state_tx);
	LOGP(DSNDCP, LOGL_INFO,
	     "gprs_sndcp_hdrcomp_test_ind(): Test errors: %i\n",
	     test_errors);
	return packet_len;
}

#endif
