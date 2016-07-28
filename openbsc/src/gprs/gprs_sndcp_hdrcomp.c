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
#include <openbsc/gprs_sndcp_hdrcomp.h>

/* Debug options */
#define GPRS_SNDCP_HDRCOMP_DEBUG 1			/* Enable private debug messages */
#define GPRS_SNDCP_HDRCOMP_HOLDDOWN_RFC1144 0		/* Artificically hold down RFC1144 compression by only transmitting TYPE_IP packets */
#define GPRS_SNDCP_HDRCOMP_RFC1144_TEST 0		/* Test RFC1144 implementation (Caution: GPRS_SNDCP_HDRCOMP_BYPASS in .h file has to be set to 0!) */
#define GPRS_SNDCP_HDRCOMP_RFC1144_TEST_EXITONERR 1	/* Exit immediately in case of RFC1144 test failure */

static struct slcompress *compression_state;	/* FIXME: We need private compression states! */

#if GPRS_SNDCP_HDRCOMP_RFC1144_TEST == 1
static struct slcompress *test_compression_state_tx;	/* For debug/test only! */
static struct slcompress *test_compression_state_rx;	/* For debug/test only! */
static int test_errors; /* For debug/test only! */
static int gprs_sndcp_hdrcomp_test_ind(uint8_t *packet, int packet_len);
static int gprs_sndcp_hdrcomp_test_req(uint8_t *packet, int packet_len);
#endif

/* Initalize header compression */
void gprs_sndcp_hdrcomp_init(void)
{
	printf("gprs_sndcp_hdrcomp_init()\n");
	compression_state = slhc_init(8, 8);
#if GPRS_SNDCP_HDRCOMP_RFC1144_TEST == 1
	test_compression_state_tx = slhc_init(8, 8);
	test_compression_state_rx = slhc_init(8, 8);
	test_errors = 0;
#endif
}

/* Display compressor status */
static void gprs_sndcp_hdrcomp_stat(struct slcompress *comp)
{
#if GPRS_SNDCP_HDRCOMP_DEBUG == 1
	printf("gprs_sndcp_hdrcomp_stat(): ");
	printf("Inbound:  ");
	slhc_i_status(comp);
	printf("\n");
	printf("gprs_sndcp_hdrcomp_stat(): ");
	printf("Outbound: ");
	slhc_o_status(comp);
	printf("\n");
#endif
}

/* Compress a packet using Van Jacobson RFC1144 header compression */
static int gprs_sndcp_hdrcomp_rfc1144_compress(struct slcompress *comp, uint8_t *packet, int packet_len, int *pcomp_index)
{
	uint8_t *packet_compressed;
	uint8_t *packet_compressed_ptr;	/* Not used */
	int packet_compressed_len;

#if GPRS_SNDCP_HDRCOMP_DEBUG == 1
		printf("gprs_sndcp_hdrcomp_rfc1144_compress(): packet_len=%i\n",packet_len);
#endif

#if GPRS_SNDCP_HDRCOMP_HOLDDOWN_RFC1144 == 1
	/* For debugging purpose only: Never emit compressed or otherwise modified packets,
           this will cause the compression scheme to stay in its initial state where only 
           TYPE_IP or UNCOMPRESSESSED_TCP packets can be transmitted */
	printf("gprs_sndcp_hdrcomp_rfc1144_compress(): holding down compression - packet not touched!\n");
	*pcomp_index = 0;
	return packet_len;
#endif

	/* Reserve some space for to store the compression result */
	packet_compressed = talloc_zero_size(NULL,packet_len);

	/* Run compressor */
	memcpy(packet_compressed,packet,packet_len);
	packet_compressed_len = slhc_compress(comp, packet, packet_len, (uint8_t*)packet_compressed, &packet_compressed_ptr, 0);

	/* Copy back compression result */	
	memcpy(packet,packet_compressed,packet_len);
	talloc_free(packet_compressed);

	/* Generate pcomp_index */
	if((packet[0] & SL_TYPE_COMPRESSED_TCP) == SL_TYPE_COMPRESSED_TCP)
	{
		*pcomp_index = 2;
	//	packet[0] &= 0x7F;
	}
	else if((packet[0] & SL_TYPE_UNCOMPRESSED_TCP) == SL_TYPE_UNCOMPRESSED_TCP)
	{
		*pcomp_index = 1;
		packet[0] &= 0x4F;	/* Remove tag for uncompressed TCP, because we never saw this in the wild */
	}
	else
		*pcomp_index = 0;



#if GPRS_SNDCP_HDRCOMP_DEBUG == 1
		printf("gprs_sndcp_hdrcomp_rfc1144_compress(): packet_compressed_len=%i\n",packet_compressed_len);
		printf("gprs_sndcp_hdrcomp_rfc1144_compress(): pcomp_index=%i\n",*pcomp_index);
#endif

	return packet_compressed_len;
}

/* Expand a packet using Van Jacobson RFC1144 header compression */
static int gprs_sndcp_hdrcomp_rfc1144_expand(struct slcompress *comp, uint8_t *packet, int packet_len, int pcomp_index)
{
	int packet_decompressed_len;
	int type = -1;

	/* Determine the packet type by the PCOMP index */
	switch(pcomp_index)
	{
		case 0: type = SL_TYPE_IP;
		break;
		case 1: type = SL_TYPE_UNCOMPRESSED_TCP;
		break;
		case 2: type = SL_TYPE_COMPRESSED_TCP;
		break;
	}

#if GPRS_SNDCP_HDRCOMP_DEBUG == 1
		printf("gprs_sndcp_hdrcomp_rfc1144_expand(): pcomp_index=%i\n",pcomp_index);
#endif

	/* Restore the original version nibble on marked uncompressed packets */
	if(type == SL_TYPE_UNCOMPRESSED_TCP)
	{
#if GPRS_SNDCP_HDRCOMP_DEBUG == 1
		printf("gprs_sndcp_hdrcomp_rfc1144_expand(): Received unconmpressed packet\n");
#endif
		packet[0] &= 0x4F;
		packet_decompressed_len = slhc_remember(comp, packet, packet_len);
		return packet_decompressed_len;
	}

	/* Uncompress compressed packets */
	else if(type == SL_TYPE_COMPRESSED_TCP)
	{
#if GPRS_SNDCP_HDRCOMP_DEBUG == 1
		printf("gprs_sndcp_hdrcomp_rfc1144_expand(): Received compressed packet\n");
#endif
		packet_decompressed_len = slhc_uncompress(comp, packet, packet_len);
		return  packet_decompressed_len;
	}

	/* Regular or unknown packets will not be touched */
	else
	{
#if GPRS_SNDCP_HDRCOMP_DEBUG == 1
		printf("gprs_sndcp_hdrcomp_rfc1144_expand(): Received transparent packet\n");
#endif
		return packet_len;
	}


}


/* Expand header compressed packet */
int gprs_sndcp_hdrcomp_expand(uint8_t *packet, int packet_len, int pcomp)
{
	int rc;
	/* FIXME: The pcomp value can be anything from 1-15, it has to 
                  be dispatched correctly, for testing we just pass it to
                  the decompressor because we choose matching pcomp
                  values */

#if GPRS_SNDCP_HDRCOMP_RFC1144_TEST == 1
	printf("gprs_sndcp_hdrcomp_expand(): testing compression...!\n");
	rc = gprs_sndcp_hdrcomp_test_ind(packet, packet_len);

#elif GPRS_SNDCP_HDRCOMP_BYPASS == 1
	/* Compression bypass */
	printf("gprs_sndcp_hdrcomp_expand(): bypassing compression - packet not touched!\n");
	rc = packet_len;
#else
	/* Normal operation: */
	rc = gprs_sndcp_hdrcomp_rfc1144_expand(compression_state, packet, packet_len, pcomp);
	printf("gprs_sndcp_hdrcomp_expand(): pcomp=%i\n",pcomp);
	printf("gprs_sndcp_hdrcomp_expand(): rc=%i\n",rc);
	gprs_sndcp_hdrcomp_stat(compression_state);
#endif

	return rc;
}

/* Expand header compressed packet */
int gprs_sndcp_hdrcomp_compress(uint8_t *packet, int packet_len, int *pcomp)
{
	int rc;
	/* FIXME: The pcomp value can be anything from 1-15, it has to 
                  be dispatched correctly, for testing we just pass it to
                  the decompressor because we choose matching pcomp
                  values */

#if GPRS_SNDCP_HDRCOMP_RFC1144_TEST == 1
	printf("gprs_sndcp_hdrcomp_expand(): testing compression...!\n");
	rc = gprs_sndcp_hdrcomp_test_req(packet, packet_len);
	*pcomp=0;
	return rc;

#elif GPRS_SNDCP_HDRCOMP_BYPASS == 1
	/* Compression bypass */
	printf("gprs_sndcp_hdrcomp_compress(): bypassing compression - packet not touched!\n");
	*pcomp = 0;
	rc = packet_len;
#else
	/* Normal operation: */
	rc = gprs_sndcp_hdrcomp_rfc1144_compress(compression_state, packet, packet_len, pcomp);
	printf("gprs_sndcp_hdrcomp_compress(): pcomp=%i\n",*pcomp);
	printf("gprs_sndcp_hdrcomp_compress(): rc=%i\n",rc);
	gprs_sndcp_hdrcomp_stat(compression_state);
#endif

	return rc;
}

























































#if GPRS_SNDCP_HDRCOMP_RFC1144_TEST == 1

/* 
 * This is a test implementation to make sure the rfc1144 compression implementation works
 * as expected. All data is first compressed and decompressed on both directions. 
 */

/* FIXME: FOR EXPERIMENTATION ONLY! REMOVE AS SOON AS POSSIBLE */
static uint16_t header_checksum(uint8_t *iph, unsigned int ihl)
{
	int i;
	uint16_t temp;
	uint32_t accumulator = 0xFFFF;

	for(i=0;i<ihl*2;i++)
	{
		temp = ((*iph) << 8)&0xFF00;
		iph++;
		temp |= (*iph)&0xFF;
		iph++;

		accumulator+=temp;
		if(accumulator>0xFFFF)
		{
			accumulator++;
			accumulator&=0xFFFF;
		}
	}

    return (uint16_t)(htons(~accumulator)&0xFFFF);
}

/* Check packet integrity */
static int gprs_sndcp_hdrcomp_test_check_packet(uint8_t *packet, uint8_t *packet_backup, int packet_len, int packet_len_uncompressed)
{
	uint16_t checksum;

	if(packet_len != packet_len_uncompressed)
	{
		printf("prs_sndcp_hdrcomp_test_check_packet(): Error: Packet length mismatch!\n");
#if GPRS_SNDCP_HDRCOMP_RFC1144_TEST_EXITONERR == 1
		exit(1);
#endif
		return -1;
	}

	/* Check packet integrety */
	if(memcmp(packet,packet_backup,packet_len))
	{
		printf("prs_sndcp_hdrcomp_test_check_packet(): Warning: Packet content!\n");
		printf("prs_sndcp_hdrcomp_test_check_packet(): %s\n",osmo_hexdump_nospc(packet_backup,80));
		printf("prs_sndcp_hdrcomp_test_check_packet(): %s\n",osmo_hexdump_nospc(packet,80));

		checksum = header_checksum(packet,5);
		printf("prs_sndcp_hdrcomp_test_check_packet():  %04x\n",checksum);

		if(checksum == 0x0000)
		{
			printf("prs_sndcp_hdrcomp_test_check_packet(): Checksum looks good!\n");
			
			if(memcmp(packet+20,packet_backup+20,packet_len-20))
				test_errors++;
			else
				printf("prs_sndcp_hdrcomp_test_check_packet(): Packet looks also good!\n");
		}	
		else
		{
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
static int gprs_sndcp_hdrcomp_test_ind(uint8_t *packet, int packet_len)
{
	int packet_len_compressed;
	int packet_len_uncompressed;
	int pcomp;
	uint8_t *packet_backup;

	printf("gprs_sndcp_hdrcomp_test_ind(): packet_len=%i\n",packet_len);
	packet_backup = talloc_zero_size(NULL,packet_len);
	memcpy(packet_backup,packet,packet_len);

	printf("gprs_sndcp_hdrcomp_test_ind(): IND:          %s\n",osmo_hexdump_nospc(packet,packet_len));
	packet_len_compressed = gprs_sndcp_hdrcomp_rfc1144_compress(test_compression_state_rx, packet, packet_len, &pcomp);
	printf("gprs_sndcp_hdrcomp_test_ind(): IND (COMP):   %s\n",osmo_hexdump_nospc(packet,packet_len_compressed));
	packet_len_uncompressed = gprs_sndcp_hdrcomp_rfc1144_expand(test_compression_state_tx, packet, packet_len_compressed, pcomp);
	printf("gprs_sndcp_hdrcomp_test_ind(): IND (DECOMP): %s\n",osmo_hexdump_nospc(packet,packet_len_uncompressed));
	printf("gprs_sndcp_hdrcomp_test_ind(): packet_len=%i   packet_len_compressed=%i   packet_len_uncompressed=%i\n",packet_len, packet_len_compressed,packet_len_uncompressed);

	gprs_sndcp_hdrcomp_test_check_packet(packet,packet_backup,packet_len,packet_len_uncompressed);
	talloc_free(packet_backup);
	gprs_sndcp_hdrcomp_stat(test_compression_state_rx);
	gprs_sndcp_hdrcomp_stat(test_compression_state_tx);
	printf("gprs_sndcp_hdrcomp_test_ind(): Test errors: %i\n",test_errors);
	return packet_len;
}

/* FIXME: FOR EXPERIMENTATION ONLY! REMOVE AS SOON AS POSSIBLE */
static int gprs_sndcp_hdrcomp_test_req(uint8_t *packet, int packet_len)
{
	int packet_len_compressed;
	int packet_len_uncompressed;
	int pcomp;
	uint8_t *packet_backup;

	printf("gprs_sndcp_hdrcomp_test_req(): packet_len=%i\n",packet_len);
	packet_backup = talloc_zero_size(NULL,packet_len);
	memcpy(packet_backup,packet,packet_len);

	printf("gprs_sndcp_hdrcomp_test_req(): REQ:          %s\n",osmo_hexdump_nospc(packet,packet_len));
	packet_len_compressed = gprs_sndcp_hdrcomp_rfc1144_compress(test_compression_state_tx, packet, packet_len,&pcomp);
	printf("gprs_sndcp_hdrcomp_test_req(): REQ (COMP):   %s\n",osmo_hexdump_nospc(packet,packet_len_compressed));
	packet_len_uncompressed = gprs_sndcp_hdrcomp_rfc1144_expand(test_compression_state_rx, packet, packet_len_compressed,pcomp);
	printf("gprs_sndcp_hdrcomp_test_req(): REQ (DECOMP): %s\n",osmo_hexdump_nospc(packet,packet_len_uncompressed));
	printf("gprs_sndcp_hdrcomp_test_req(): packet_len=%i   packet_len_compressed=%i   packet_len_uncompressed=%i\n",packet_len, packet_len_compressed,packet_len_uncompressed);

	gprs_sndcp_hdrcomp_test_check_packet(packet,packet_backup,packet_len,packet_len_uncompressed);
	talloc_free(packet_backup);
	gprs_sndcp_hdrcomp_stat(test_compression_state_rx);
	gprs_sndcp_hdrcomp_stat(test_compression_state_tx);
	printf("gprs_sndcp_hdrcomp_test_ind(): Test errors: %i\n",test_errors);
	return packet_len;
}

#endif







