/* GPRS SNDCP XID field encoding/decoding as per 3GPP TS 144 065 */

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

#include <openbsc/debug.h>
#include <openbsc/gprs_llc.h>
#include <openbsc/sgsn.h>
#include <openbsc/gprs_sndcp_xid.h>


/* 
 * FUNCTIONS RELATED TO SNDCP-XID ENCODING
 */

/* Encode applicable sapis (works the same in all three compression schemes) */
static int encode_hdrcomp_applicable_sapis(uint8_t *dst,
					   unsigned int *nsapis,
					   unsigned int nsapis_len)
{
	/* 
	 * NOTE: Buffer *dst needs offer at 2 bytes
	 * of space to store the generation results
	 */

	uint16_t blob;
	unsigned int nsapi;
	int i;

	/* Encode applicable SAPIs */
	blob = 0;
	for (i = 0; i < nsapis_len; i++) {
		nsapi = nsapis[i];
		/* 
		 * Only NSAPI 5 to 15 are applicable for user traffic (PDP-
		 * contexts). Only for these NSAPIs SNDCP-XID parameters
		 * can apply. See also ETSI TS 144 065 5.1 Service primitives
		 */
		if ((nsapi < 5) || (nsapi > 15))
			return -EINVAL;
		blob |= (1 << nsapi);
	}

	/* Store result */
	*dst = (blob >> 8) & 0xFF;
	dst++;
	*dst = blob & 0xFF;

	return 2;
}


/* 
 * Encode rfc1144 parameter field 
 * (see also: ETSI TS 144 065 6.5.2.1, Table 5) 
 */
static int encode_hdrcomp_rfc1144_params(uint8_t *dst,
					 unsigned int dst_maxlen,
					 struct
					 gprs_sndcp_hdrcomp_rfc1144_params
					 *params)
{
	/* 
	 * NOTE: Buffer *dst should offer at least 3 bytes
	 * of space to store the generation results
	 */

	int dst_counter = 0;
	int rc;

	/* Exit immediately if no source struct is available */
	if (!params)
		return -EINVAL;

	/* Exit immediately if no sufficient memory space is supplied */
	if ((dst_maxlen < 3) || !dst)
		return -EINVAL;

	/*
	 * Exit if number of possible nsapis exceeds valid range
	 * (Only 11 nsapis possible for PDP-Contexts) 
	 */
	if ((params->nsapi_len < 0) || (params->nsapi_len > 11))
		return -EINVAL;

	/* Zero out buffer */
	memset(dst, 0, dst_maxlen);

	/* Encode applicable SAPIs */
	rc = encode_hdrcomp_applicable_sapis(dst, params->nsapi,
					     params->nsapi_len);
	dst += rc;
	dst_counter += rc;

	/* Encode s01 (see also: ETSI TS 144 065 6.5.2.1, Table 5) */
	*dst = params->s01;
	dst++;
	dst_counter++;

	/* Return generated length */
	return dst_counter;
}


/* 
 * Encode rfc2507 parameter field 
 * (see also: ETSI TS 144 065 6.5.3.1, Table 6)
 */
static int encode_hdrcomp_rfc2507_params(uint8_t *dst,
					 unsigned int dst_maxlen,
					 struct
					 gprs_sndcp_hdrcomp_rfc2507_params
					 *params)
{
	/* 
	 * NOTE: Buffer *dst should offer at least 3 bytes
	 * of space to store the generation results
	 */

	int dst_counter = 0;
	int rc;

	/* Exit immediately if no source struct is available */
	if (!params)
		return -EINVAL;

	/* Exit immediately if no sufficient memory space is supplied */
	if ((dst_maxlen < 9) || !dst)
		return -EINVAL;

	/*
	 * Exit if number of possible nsapis exceeds valid range
	 * (Only 11 nsapis possible for PDP-Contexts) 
	 */
	if ((params->nsapi_len < 0) || (params->nsapi_len > 11))
		return -EINVAL;

	/* Zero out buffer */
	memset(dst, 0, dst_maxlen);

	/* Encode applicable SAPIs */
	rc = encode_hdrcomp_applicable_sapis(dst, params->nsapi,
					     params->nsapi_len);
	dst += rc;
	dst_counter += rc;

	/* Encode F_MAX_PERIOD (see also: ETSI TS 144 065 6.5.3.1, Table 6) */
	if ((params->f_max_period < 1) || (params->f_max_period > 65535))
		return -EINVAL;
	*dst = (params->f_max_period >> 8) & 0xFF;
	dst++;
	dst_counter++;
	*dst = (params->f_max_period) & 0xFF;
	dst++;
	dst_counter++;

	/* Encode F_MAX_TIME (see also: ETSI TS 144 065 6.5.3.1, Table 6) */
	if ((params->f_max_time < 1) || (params->f_max_time > 255))
		return -EINVAL;
	*dst = params->f_max_time;
	dst++;
	dst_counter++;

	/* Encode MAX_HEADER (see also: ETSI TS 144 065 6.5.3.1, Table 6) */
	if ((params->max_header < 60) || (params->max_header > 255))
		return -EINVAL;
	*dst = params->max_header;
	dst++;
	dst_counter++;

	/* Encode TCP_SPACE (see also: ETSI TS 144 065 6.5.3.1, Table 6) */
	if ((params->tcp_space < 3) || (params->tcp_space > 255))
		return -EINVAL;
	*dst = params->tcp_space;
	dst++;
	dst_counter++;

	/* Encode NON_TCP_SPACE (see also: ETSI TS 144 065 6.5.3.1, Table 6) */
	if ((params->non_tcp_space < 3) || (params->tcp_space > 65535))
		return -EINVAL;
	*dst = (params->non_tcp_space >> 8) & 0xFF;
	dst++;
	dst_counter++;
	*dst = (params->non_tcp_space) & 0xFF;
	dst++;
	dst_counter++;

	/* Return generated length */
	return dst_counter;
}


/* 
 * Encode ROHC parameter field 
 * (see also: ETSI TS 144 065 6.5.4.1, Table 10)
 */
static int encode_hdrcomp_rohc_params(uint8_t *dst,
				      unsigned int dst_maxlen,
				      struct gprs_sndcp_hdrcomp_rohc_params
				      *params)
{
	/* 
	 * NOTE: Buffer *dst should offer at least 36 
	 * (2 * 16 Profiles + 2 * 3 Parameter) bytes
	 * of memory space to store generation results
	 */

	int i;
	int dst_counter = 0;
	int rc;

	/* Exit immediately if no source struct is available */
	if (!params)
		return -EINVAL;

	/* Exit immediately if no sufficient memory space is supplied */
	if ((dst_maxlen < 38) || !dst)
		return -EINVAL;

	/*
	 * Exit if number of possible nsapis exceeds valid range
	 * (Only 11 nsapis possible for PDP-Contexts) 
	 */
	if ((params->nsapi_len < 0) || (params->nsapi_len > 11))
		return -EINVAL;

	/* 
	 * Exit if number of ROHC profiles exceeds limit 
	 * (ROHC supports only a maximum of 16 different profiles)
	 */
	if ((params->profile_len < 0) || (params->profile_len > 16))
		return -EINVAL;

	/* Zero out buffer */
	memset(dst, 0, dst_maxlen);

	/* Encode applicable SAPIs */
	rc = encode_hdrcomp_applicable_sapis(dst, params->nsapi,
					     params->nsapi_len);
	dst += rc;
	dst_counter += rc;

	/* Encode MAX_CID (see also: ETSI TS 144 065 6.5.4.1, Table 10) */
	if (params->max_cid > 16383)
		return -EINVAL;
	*dst = (params->max_cid >> 8) & 0xFF;
	dst++;
	*dst = params->max_cid & 0xFF;
	dst++;
	dst_counter += 2;

	/* Encode MAX_HEADER (see also: ETSI TS 144 065 6.5.4.1, Table 10) */
	if ((params->max_header < 60) || (params->max_header > 255))
		return -EINVAL;
	*dst = (params->max_header >> 8) & 0xFF;
	dst++;
	*dst = params->max_header & 0xFF;
	dst++;
	dst_counter += 2;

	/* Encode ROHC Profiles (see also: ETSI TS 144 065 6.5.4.1, Table 10) */
	for (i = 0; i < params->profile_len; i++) {
		*dst = (params->profile[i] >> 8) & 0xFF;
		dst++;
		*dst = params->profile[i] & 0xFF;
		dst++;
		dst_counter += 2;
	}

	/* Return generated length */
	return dst_counter;
}


/* 
 * Encode V42bis parameter field 
 * (see also: ETSI TS 144 065 6.6.2.1, Table 7a)
 */
static int encode_datacomp_v42bis_params(uint8_t *dst,
					 unsigned int dst_maxlen,
					 struct
					 gprs_sndcp_datacomp_v42bis_params
					 *params)
{
	/* 
	 * NOTE: Buffer *dst should offer at least 6 bytes
	 * of space to store the generation results
	 */

	int dst_counter = 0;
	int rc;

	/* Exit immediately if no source struct is available */
	if (!params)
		return -EINVAL;

	/* Exit immediately if no sufficient memory space is supplied */
	if ((dst_maxlen < 6) || !dst)
		return -EINVAL;

	/*
	 * Exit if number of possible nsapis exceeds valid range
	 * (Only 11 nsapis possible for PDP-Contexts) 
	 */
	if ((params->nsapi_len < 0) || (params->nsapi_len > 11))
		return -EINVAL;

	/* Zero out buffer */
	memset(dst, 0, dst_maxlen);

	/* Encode applicable SAPIs */
	rc = encode_hdrcomp_applicable_sapis(dst, params->nsapi,
					     params->nsapi_len);
	dst += rc;
	dst_counter += rc;

	/* Encode P0 (see also: ETSI TS 144 065 6.6.2.1, Table 7a) */
	if (params->p0 > 3)
		return -EINVAL;
	*dst = params->p0 & 0x03;
	dst++;
	dst_counter++;

	/* Encode P1 (see also: ETSI TS 144 065 6.6.2.1, Table 7a) */
	if ((params->p1 < 512) || (params->p1 > 65535))
		return -EINVAL;
	*dst = (params->p1 >> 8) & 0xFF;
	dst++;
	*dst = params->p1 & 0xFF;
	dst++;
	dst_counter += 2;

	/* Encode P2 (see also: ETSI TS 144 065 6.6.2.1, Table 7a) */
	if ((params->p2 < 6) || (params->p2 > 250))
		return -EINVAL;
	*dst = params->p2;
	dst++;
	dst_counter++;

	/* Return generated length */
	return dst_counter;
}


/* 
 * Encode V44 parameter field 
 * (see also: ETSI TS 144 065 6.6.3.1, Table 7c)
 */
static int encode_datacomp_v44_params(uint8_t *dst,
				      unsigned int dst_maxlen,
				      struct gprs_sndcp_datacomp_v44_params
				      *params)
{
	/* 
	 * NOTE: Buffer *dst should offer at least 12 bytes
	 * of space to store the generation results
	 */

	int dst_counter = 0;
	int rc;

	/* Exit immediately if no source struct is available */
	if (!params)
		return -EINVAL;

	/* Exit immediately if no sufficient memory space is supplied */
	if ((dst_maxlen < 12) || !dst)
		return -EINVAL;

	/*
	 * Exit if number of possible nsapis exceeds valid range
	 * (Only 11 nsapis possible for PDP-Contexts) 
	 */
	if ((params->nsapi_len < 0) || (params->nsapi_len > 11))
		return -EINVAL;

	/* Zero out buffer */
	memset(dst, 0, dst_maxlen);

	/* Encode applicable SAPIs */
	rc = encode_hdrcomp_applicable_sapis(dst, params->nsapi,
					     params->nsapi_len);
	dst += rc;
	dst_counter += rc;

	/* Encode C0 (see also: ETSI TS 144 065 6.6.3.1, Table 7c) */
	if ((params->c0 == 0x80) || (params->c0 == 0xC0)) {
		*dst = params->c0 & 0xC0;
		dst++;
		dst_counter++;
	} else
		return -EINVAL;

	/* Encode P0 (see also: ETSI TS 144 065 6.6.3.1, Table 7c) */
	if (params->p0 > 3)
		return -EINVAL;
	*dst = params->p0 & 0x03;
	dst++;
	dst_counter++;

	/* Encode P1T (see also: ETSI TS 144 065 6.6.3.1, Table 7c) */
	if ((params->p1t < 256) || (params->p1t > 65535))
		return -EINVAL;
	*dst = (params->p1t >> 8) & 0xFF;
	dst++;
	*dst = params->p1t & 0xFF;
	dst++;
	dst_counter += 2;

	/* Encode P1R (see also: ETSI TS 144 065 6.6.3.1, Table 7c) */
	if ((params->p1r < 256) || (params->p1r > 65535))
		return -EINVAL;
	*dst = (params->p1r >> 8) & 0xFF;
	dst++;
	*dst = params->p1r & 0xFF;
	dst++;
	dst_counter += 2;

	/* Encode P3T (see also: ETSI TS 144 065 6.6.3.1, Table 7c) */
	if (params->p3t > 65535)
		return -EINVAL;
	if (params->p3t < 2 * params->p1t)
		return -EINVAL;
	*dst = (params->p3t >> 8) & 0xFF;
	dst++;
	*dst = params->p3t & 0xFF;
	dst++;
	dst_counter += 2;

	/* Encode P3R (see also: ETSI TS 144 065 6.6.3.1, Table 7c) */
	if (params->p3r > 65535)
		return -EINVAL;
	if (params->p3r < 2 * params->p1r)
		return -EINVAL;
	*dst = (params->p3r >> 8) & 0xFF;
	dst++;
	*dst = params->p3r & 0xFF;
	dst++;
	dst_counter += 2;

	/* Return generated length */
	return dst_counter;
}


/* 
 * Encode data or protocol control information compression field 
 * (see also: ETSI TS 144 065 6.6.1.1, Figure 9 and 
 *            ETSI TS 144 065 6.5.1.1, Figure 7)
 */
static int encode_comp_field(uint8_t *dst, unsigned int dst_maxlen,
			     struct gprs_sndcp_comp_field *comp_field)
{
	int dst_counter = 0;
	int len;
	int expected_length;
	int i;

	uint8_t payload_bytes[256];
	int payload_bytes_len = -1;

	/* If possible, try do encode payload bytes first */
	if (comp_field->rfc1144_params)
		payload_bytes_len =
		    encode_hdrcomp_rfc1144_params(payload_bytes,
						  sizeof(payload_bytes),
						  comp_field->
						  rfc1144_params);
	else if (comp_field->rfc2507_params)
		payload_bytes_len =
		    encode_hdrcomp_rfc2507_params(payload_bytes,
						  sizeof(payload_bytes),
						  comp_field->
						  rfc2507_params);
	else if (comp_field->rohc_params)
		payload_bytes_len =
		    encode_hdrcomp_rohc_params(payload_bytes,
					       sizeof(payload_bytes),
					       comp_field->rohc_params);
	else if (comp_field->v42bis_params)
		payload_bytes_len =
		    encode_datacomp_v42bis_params(payload_bytes,
						  sizeof(payload_bytes),
						  comp_field->
						  v42bis_params);
	else if (comp_field->v44_params)
		payload_bytes_len =
		    encode_datacomp_v44_params(payload_bytes,
					       sizeof(payload_bytes),
					       comp_field->v44_params);
	else
		return -EINVAL;

	/* Exit immediately if payload byte generation failed */
	if (payload_bytes_len < 0)
		return -EINVAL;

	/* Exit immediately if no source struct is available */
	if (!comp_field)
		return -EINVAL;

	/* Check if comp_len is within bounds */
	if ((comp_field->comp_len < 0) || (comp_field->comp_len > 16))
		return -EINVAL;

	/* Calculate length field of the data block */
	if (comp_field->p) {
		len =
		    payload_bytes_len +
		    ceil((double) (comp_field->comp_len) / 2.0);
		expected_length = len + 3;
	} else {
		len = payload_bytes_len;
		expected_length = len + 2;
	}

	/* Exit immediately if no sufficient memory space is supplied */
	if ((dst_maxlen < expected_length) || !dst)
		return -EINVAL;

	/* Check if the entity number is within bounds */
	if ((comp_field->entity < 0) || (comp_field->entity > 0x1f))
		return -EINVAL;

	/* Check if the algorithm number is within bounds */
	if ((comp_field->algo < 0) || (comp_field->algo > 0x1f))
		return -EINVAL;

	/* Zero out buffer */
	memset(dst, 0, dst_maxlen);

	/* Encode Propose bit */
	if (comp_field->p)
		*dst |= (1 << 7);

	/* Encode entity number */
	*dst |= comp_field->entity & 0x1F;
	dst++;
	dst_counter++;

	/* Encode algorithm number */
	if (comp_field->p) {
		*dst |= comp_field->algo & 0x1F;
		dst++;
		dst_counter++;
	}

	/* Encode length field */
	*dst |= len & 0xFF;
	dst++;
	dst_counter++;

	/* Encode PCOMP/DCOMP values */
	if (comp_field->p) {
		for (i = 0; i < comp_field->comp_len; i++) {
			/* Check if submitted PCOMP/DCOMP 
			   values are within bounds */
			if ((comp_field->comp[i] < 0)
			    || (comp_field->comp[i] > 0x0F))
				return -EINVAL;

			if (i & 1) {
				*dst |= comp_field->comp[i] & 0x0F;
				dst++;
				dst_counter++;
			} else
				*dst |=
				    (comp_field->comp[i] << 4) & 0xF0;
		}

		if (i & 1) {
			dst++;
			dst_counter++;
		}
	}

	/* Append payload bytes */
	memcpy(dst, payload_bytes, payload_bytes_len);
	dst_counter += payload_bytes_len;

	/* Return generated length */
	return dst_counter;
}


/* Find out to which compression class the specified comp-field belongs 
   (header compression or data compression?) */
int gprs_sndcp_get_compression_class(struct gprs_sndcp_comp_field
				     *comp_field)
{
	if (comp_field->rfc1144_params)
		return SNDCP_XID_PROTOCOL_COMPRESSION;
	else if (comp_field->rfc2507_params)
		return SNDCP_XID_PROTOCOL_COMPRESSION;
	else if (comp_field->rohc_params)
		return SNDCP_XID_PROTOCOL_COMPRESSION;
	else if (comp_field->v42bis_params)
		return SNDCP_XID_DATA_COMPRESSION;
	else if (comp_field->v44_params)
		return SNDCP_XID_DATA_COMPRESSION;
	else
		return -EINVAL;
}


/* Convert all compression fields to bytstreams */
static int gprs_sndcp_pack_fields(struct llist_head *comp_fields,
				  uint8_t *dst,
				  unsigned int dst_maxlen, int class)
{
	struct gprs_sndcp_comp_field *comp_field;
	int byte_counter = 0;
	int rc;

	llist_for_each_entry(comp_field, comp_fields, list) {
		if (class == gprs_sndcp_get_compression_class(comp_field)) {
			rc = encode_comp_field(dst + byte_counter,
					       dst_maxlen - byte_counter,
					       comp_field);

			/* Immediately stop on error */
			if (rc < 0)
				return rc;

			byte_counter += rc;
		}
	}

	/* Return generated length */
	return byte_counter;
}


/* Transform a list with compression fields into an SNDCP-XID message (dst) */
int gprs_sndcp_compile_xid(struct llist_head *comp_fields, uint8_t *dst,
			   unsigned int dst_maxlen)
{
	int rc;
	int byte_counter = 0;
	uint8_t comp_bytes[512];
	uint8_t xid_version_number[1] = { CURRENT_SNDCP_VERSION };

	/* Exit immediately if no sufficient memory space is supplied */
	if ((dst_maxlen < 2 + sizeof(xid_version_number)) || !dst)
		return -EINVAL;

	/* Zero out buffer (just to be sure) */
	memset(dst, 0, dst_maxlen);

	/* Prepend header */
	dst =
	    tlv_put(dst, SNDCP_XID_VERSION_NUMBER,
		    sizeof(xid_version_number), xid_version_number);
	byte_counter += (sizeof(xid_version_number) + 2);

	/* Add data compression fields */
	rc = gprs_sndcp_pack_fields(comp_fields, comp_bytes,
				    sizeof(comp_bytes),
				    SNDCP_XID_DATA_COMPRESSION);
	if (rc < 0)
		return rc;
	else if (rc > 0) {
		dst =
		    tlv_put(dst, SNDCP_XID_DATA_COMPRESSION, rc,
			    comp_bytes);
		byte_counter += rc + 2;
	}

	/* Add header compression fields */
	rc = gprs_sndcp_pack_fields(comp_fields, comp_bytes,
				    sizeof(comp_bytes),
				    SNDCP_XID_PROTOCOL_COMPRESSION);
	if (rc < 0)
		return rc;
	else if (rc > 0) {
		dst =
		    tlv_put(dst, SNDCP_XID_PROTOCOL_COMPRESSION, rc,
			    comp_bytes);
		byte_counter += rc + 2;
	}

	/* Return generated length */
	return byte_counter;
}










/* 
 * FUNCTIONS RELATED TO SNDCP-XID DECODING
 */

/* Decode applicable sapis (works the same in all three compression schemes) */
static int decode_hdrcomp_applicable_sapis(const uint8_t *src,
					   unsigned int src_len,
					   unsigned int *nsapis,
					   unsigned int *nsapis_len)
{
	uint16_t blob;
	int i;
	int nsapi_len = 0;

	/* Exit immediately if no result can be stored */
	if (!nsapis)
		return -EINVAL;

	/* Exit immediately if not enough input data is available */
	if (src_len < 2)
		return -EINVAL;

	/* Read bitmask */
	blob = *src;
	blob = (blob << 8) & 0xFF00;
	src++;
	blob |= (*src) & 0xFF;
	blob = (blob >> 5);

	/* Decode applicable SAPIs */
	for (i = 0; i < 15; i++) {
		if ((blob >> i) & 1) {
			nsapis[nsapi_len] = i + 5;
			nsapi_len++;
		}
	}

	/* Return consumed length */
	*nsapis_len = nsapi_len;
	return 2;
}

/* Decode 16 bit field */
static int decode_hdrcomp_16_bit_field(const uint8_t *src,
				       unsigned int src_len,
				       int value_min, int value_max,
				       unsigned int *value_int,
				       uint16_t * value_uint16)
{
	uint16_t blob;

	/* Reset values to zero (just to be sure) */
	if (value_int)
		*value_int = 0;
	if (value_uint16)
		*value_uint16 = 0;

	/* Exit if not enough src are available */
	if (src_len < 2)
		return -EINVAL;

	/* Decode bit value */
	blob = *src;
	blob = (blob << 8) & 0xFF00;
	src++;
	blob |= *src;

	/* Check if parsed value is within bounds */
	if (blob < value_min)
		return -EINVAL;
	if (blob > value_max)
		return -EINVAL;

	/* Hand back results to the caller */
	if (value_int)
		*value_int = blob;
	if (value_uint16)
		*value_uint16 = blob;

	/* Return consumed length */
	return 2;
}

/* Decode 8 bit field */
static int decode_hdrcomp_8_bit_field(const uint8_t *src,
				      unsigned int src_len,
				      int value_min, int value_max,
				      unsigned int *value_int,
				      uint8_t * value_uint8)
{
	uint8_t blob;

	/* Reset values to zero (just to be sure) */
	if (value_int)
		*value_int = 0;
	if (value_uint8)
		*value_uint8 = 0;

	/* Exit if not enough src are available */
	if (src_len < 1)
		return -EINVAL;

	/* Decode bit value */
	blob = *src;

	/* Check if parsed value is within bounds */
	if (blob < value_min)
		return -EINVAL;
	if (blob > value_max)
		return -EINVAL;

	/* Hand back results to the caller */
	if (value_int)
		*value_int = blob;
	if (value_uint8)
		*value_uint8 = blob;

	/* Return consumed length */
	return 1;
}




/* Decode rfc1144 parameter field see also: ETSI TS 144 065 6.5.2.1, Table 5) */
static int decode_hdrcomp_rfc1144_params(const uint8_t * src,
					 unsigned int src_len,
					 struct
					 gprs_sndcp_hdrcomp_rfc1144_params
					 *params)
{
	int rc;
	int byte_counter = 0;

	/* Exit immediately if no result can be stored */
	if (!params)
		return -EINVAL;

	/* Decode applicable SAPIs */
	rc = decode_hdrcomp_applicable_sapis(src, src_len,
					     params->nsapi,
					     &params->nsapi_len);
	if (rc > 0) {
		byte_counter += rc;
		src += rc;
	} else
		return byte_counter;

	/* 
	 * Decode parameter S0 -1 
	 * (see also: ETSI TS 144 065 6.5.2.1, Table 5)
	 */
	rc = decode_hdrcomp_8_bit_field(src, src_len - byte_counter, 0,
					255, &params->s01, NULL);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Return consumed length */
	return byte_counter;
}

/* 
 * Decode rfc2507 parameter field 
 * (see also: ETSI TS 144 065 6.5.3.1, Table 6)
 */
static int decode_hdrcomp_rfc2507_params(const uint8_t *src,
					 unsigned int src_len,
					 struct
					 gprs_sndcp_hdrcomp_rfc2507_params
					 *params)
{
	int rc;
	int byte_counter = 0;

	/* Exit immediately if no result can be stored */
	if (!params)
		return -EINVAL;

	/* Decode applicable SAPIs */
	rc = decode_hdrcomp_applicable_sapis(src, src_len,
					     params->nsapi,
					     &params->nsapi_len);
	if (rc > 0) {
		byte_counter += rc;
		src += rc;
	} else
		return byte_counter;

	/* Decode F_MAX_PERIOD (see also: ETSI TS 144 065 6.5.3.1, Table 6) */
	rc = decode_hdrcomp_16_bit_field(src, src_len - byte_counter,
					 1, 65535, &params->f_max_period,
					 NULL);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode F_MAX_TIME (see also: ETSI TS 144 065 6.5.3.1, Table 6) */
	rc = decode_hdrcomp_8_bit_field(src, src_len - byte_counter, 1,
					255, &params->f_max_time, NULL);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode MAX_HEADER (see also: ETSI TS 144 065 6.5.3.1, Table 6) */
	rc = decode_hdrcomp_8_bit_field(src, src_len - byte_counter,
					60, 255, &params->max_header,
					NULL);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode TCP_SPACE (see also: ETSI TS 144 065 6.5.3.1, Table 6) */
	rc = decode_hdrcomp_8_bit_field(src, src_len - byte_counter, 3,
					255, &params->tcp_space, NULL);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode NON_TCP_SPACE (see also: ETSI TS 144 065 6.5.3.1, Table 6) */
	rc = decode_hdrcomp_16_bit_field(src, src_len - byte_counter,
					 3, 65535, &params->non_tcp_space,
					 NULL);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Return consumed length */
	return byte_counter;
}

/* Decode ROHC parameter field (see also: ETSI TS 144 065 6.5.4.1, Table 10) */
static int decode_hdrcomp_rohc_params(const uint8_t *src,
				      unsigned int src_len,
				      struct gprs_sndcp_hdrcomp_rohc_params
				      *params)
{
	int rc;
	int byte_counter = 0;
	int i;

	/* Exit immediately if no result can be stored */
	if (!params)
		return -EINVAL;

	/* Decode applicable SAPIs */
	rc = decode_hdrcomp_applicable_sapis(src, src_len,
					     params->nsapi,
					     &params->nsapi_len);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode MAX_CID (see also: ETSI TS 144 065 6.5.4.1, Table 10) */
	rc = decode_hdrcomp_16_bit_field(src, src_len - byte_counter,
					 0, 16383, &params->max_cid, NULL);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode MAX_HEADER (see also: ETSI TS 144 065 6.5.4.1, Table 10) */
	rc = decode_hdrcomp_16_bit_field(src, src_len - byte_counter,
					 60, 255, &params->max_header,
					 NULL);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode Profiles (see also: ETSI TS 144 065 6.5.4.1, Table 10) */
	for (i = 0; i < 16; i++) {
		params->profile_len = 0;
		rc = decode_hdrcomp_16_bit_field(src,
						 src_len - byte_counter,
						 0, 65535, NULL,
						 &params->profile[i]);
		if (rc <= 0)
			return byte_counter;
		byte_counter += rc;
		src += rc;
		params->profile_len = i + 1;
	}

	/* Return consumed length */
	return byte_counter;
}


/* 
 * Decode V42bis parameter field 
 * (see also: ETSI TS 144 065 6.6.2.1, Table 7a) 
 */
static int decode_datacomp_v42bis_params(const uint8_t *src,
					 unsigned int src_len,
					 struct
					 gprs_sndcp_datacomp_v42bis_params
					 *params)
{
	int rc;
	int byte_counter = 0;

	/* Exit immediately if no result can be stored */
	if (!params)
		return -EINVAL;

	/* Decode applicable SAPIs */
	rc = decode_hdrcomp_applicable_sapis(src, src_len,
					     params->nsapi,
					     &params->nsapi_len);
	if (rc > 0) {
		byte_counter += rc;
		src += rc;
	} else
		return byte_counter;

	/* Decode P0 (see also: ETSI TS 144 065 6.6.2.1, Table 7a) */
	rc = decode_hdrcomp_8_bit_field(src, src_len - byte_counter, 0,
					3, &params->p0, NULL);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode P1 (see also: ETSI TS 144 065 6.6.2.1, Table 7a) */
	rc = decode_hdrcomp_16_bit_field(src, src_len - byte_counter,
					 512, 65535, &params->p1, NULL);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode P2 (see also: ETSI TS 144 065 6.6.2.1, Table 7a) */
	rc = decode_hdrcomp_8_bit_field(src, src_len - byte_counter, 6,
					250, &params->p2, NULL);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Return consumed length */
	return byte_counter;
}


/* Decode V44 parameter field (see also: ETSI TS 144 065 6.6.3.1, Table 7c) */
static int decode_datacomp_v44_params(const uint8_t *src,
				      unsigned int src_len,
				      struct gprs_sndcp_datacomp_v44_params
				      *params)
{
	int rc;
	int byte_counter = 0;

	/* Exit immediately if no result can be stored */
	if (!params)
		return -EINVAL;

	/* Decode applicable SAPIs */
	rc = decode_hdrcomp_applicable_sapis(src, src_len,
					     params->nsapi,
					     &params->nsapi_len);
	if (rc > 0) {
		byte_counter += rc;
		src += rc;
	} else
		return byte_counter;

	/* Decode C0 (see also: ETSI TS 144 065 6.6.3.1, Table 7c) */
	rc = decode_hdrcomp_8_bit_field(src, src_len - byte_counter, 0,
					255, &params->c0, NULL);
	if (rc <= 0)
		return byte_counter;
	if ((params->c0 != 0x80) && (params->c0 != 0xC0))
		return -EINVAL;
	byte_counter += rc;
	src += rc;

	/* Decode P0 (see also: ETSI TS 144 065 6.6.3.1, Table 7c) */
	rc = decode_hdrcomp_8_bit_field(src, src_len - byte_counter, 0,
					3, &params->p0, NULL);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode P1T (see also: ETSI TS 144 065 6.6.3.1, Table 7c) */
	rc = decode_hdrcomp_16_bit_field(src, src_len - byte_counter,
					 265, 65535, &params->p1t, NULL);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode P1R (see also: ETSI TS 144 065 6.6.3.1, Table 7c) */
	rc = decode_hdrcomp_16_bit_field(src, src_len - byte_counter,
					 265, 65535, &params->p1r, NULL);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode P3T (see also: ETSI TS 144 065 6.6.3.1, Table 7c) */
	rc = decode_hdrcomp_16_bit_field(src, src_len - byte_counter,
					 265, 65535, &params->p3t, NULL);
	if (rc <= 0)
		return byte_counter;
	if (params->p3t < 2 * params->p1t)
		return -EINVAL;
	byte_counter += rc;
	src += rc;

	/* Decode P3R (see also: ETSI TS 144 065 6.6.3.1, Table 7c) */
	rc = decode_hdrcomp_16_bit_field(src, src_len - byte_counter,
					 265, 65535, &params->p3r, NULL);
	if (rc <= 0)
		return byte_counter;
	if (params->p3r < 2 * params->p1r)
		return -EINVAL;
	byte_counter += rc;
	src += rc;

	/* Return consumed length */
	return byte_counter;
}


/* Lookup algorithm identfier by entity ID */
static int lookup_algorithm_identifier(int entity,
				       struct
				       gprs_sndcp_hdrcomp_entity_algo_table
				       *lt, unsigned int lt_len,
				       int compclass)
{
	int i;
	if ((lt) && (lt_len > 0)) {
		for (i = 0; i < lt_len; i++) {
			if ((lt[i].entity == entity)
			    && (lt[i].compclass == compclass))
				return lt[i].algo;
		}
	}

	return -1;
}


/* 
 * Decode data or protocol control information compression field 
 * (see also: ETSI TS 144 065 6.6.1.1, Figure 9 and 
 *            ETSI TS 144 065 6.5.1.1, Figure 7)
 */
static int decode_comp_field(const uint8_t *src, unsigned int src_len,
			     struct gprs_sndcp_comp_field *comp_field,
			     struct
			     gprs_sndcp_hdrcomp_entity_algo_table
			     *lt, unsigned int lt_len, int compclass)
{
	int byte_counter = 0;
	unsigned int len;
	int i;
	int rc;

	/* Exit immediately if it is clear that no
	   parseable data is present */
	if ((src_len < 1) || !src)
		return -EINVAL;

	/* Exit immediately if no result can be stored */
	if (!comp_field)
		return -EINVAL;

	/* Zero out target struct */
	memset(comp_field, 0, sizeof(struct gprs_sndcp_comp_field));

	/* Decode Propose bit and Entity number */
	if ((*src) & 0x80)
		comp_field->p = 1;
	comp_field->entity = (*src) & 0x1F;
	byte_counter++;
	src++;

	/* Decode algorithm number (if present) */
	if (comp_field->p) {
		comp_field->algo = (*src) & 0x1F;
		byte_counter++;
		src++;
	}
	/* Alternatively take the information from the lookup table */
	else
		comp_field->algo =
		    lookup_algorithm_identifier(comp_field->entity, lt,
						lt_len, compclass);

	/* Decode length field */
	len = *src;
	byte_counter++;
	src++;


	/* Decode PCOMP/DCOMP values */
	if (comp_field->p) {
		/* Determine the number of expected PCOMP/DCOMP values */
		if (compclass == SNDCP_XID_PROTOCOL_COMPRESSION) {
			/* For protocol compression */
			switch (comp_field->algo) {
			case RFC_1144:
				comp_field->comp_len = RFC1144_PCOMP_LEN;
				break;
			case RFC_2507:
				comp_field->comp_len = RFC2507_PCOMP_LEN;
				break;
			case ROHC:
				comp_field->comp_len = ROHC_PCOMP_LEN;
				break;

				/* Exit if the algorithem type encodes
				   something unknown / unspecified */
			default:
				return -EINVAL;
			}
		} else {
			/* For data compression */
			switch (comp_field->algo) {
			case V42BIS:
				comp_field->comp_len = V42BIS_DCOMP_LEN;
				break;
			case V44:
				comp_field->comp_len = V44_DCOMP_LEN;
				break;

				/* Exit if the algorithem type encodes
				   something unknown / unspecified */
			default:
				return -EINVAL;
			}
		}

		for (i = 0; i < comp_field->comp_len; i++) {
			if (i & 1) {
				comp_field->comp[i] = (*src) & 0x0F;
				src++;
				byte_counter++;
				len--;
			} else
				comp_field->comp[i] =
				    ((*src) >> 4) & 0x0F;
		}

		if (i & 1) {
			src++;
			byte_counter++;
			len--;
		}
	}

	/* Decode algorithm specific payload data */
	if (compclass == SNDCP_XID_PROTOCOL_COMPRESSION) {
		/* For protocol compression */
		switch (comp_field->algo) {
		case RFC_1144:
			comp_field->rfc1144_params =
			    talloc_zero(NULL,
					struct
					gprs_sndcp_hdrcomp_rfc1144_params);
			rc = decode_hdrcomp_rfc1144_params(src, len,
							   comp_field->
							   rfc1144_params);
			break;
		case RFC_2507:
			comp_field->rfc2507_params =
			    talloc_zero(NULL,
					struct
					gprs_sndcp_hdrcomp_rfc2507_params);
			rc = decode_hdrcomp_rfc2507_params(src, len,
							   comp_field->
							   rfc2507_params);
			break;
		case ROHC:
			comp_field->rohc_params =
			    talloc_zero(NULL,
					struct
					gprs_sndcp_hdrcomp_rohc_params);
			rc = decode_hdrcomp_rohc_params(src, len,
							comp_field->
							rohc_params);
			break;

			/* If no suitable decoder is detected, 
			   leave the remaining bytes undecoded */
		default:
			rc = len;
		}
	} else {
		/* For data compression */
		switch (comp_field->algo) {
		case V42BIS:
			comp_field->v42bis_params =
			    talloc_zero(NULL,
					struct
					gprs_sndcp_datacomp_v42bis_params);
			rc = decode_datacomp_v42bis_params(src, len,
							   comp_field->
							   v42bis_params);
			break;
		case V44:
			comp_field->v44_params =
			    talloc_zero(NULL,
					struct
					gprs_sndcp_datacomp_v44_params);
			rc = decode_datacomp_v44_params(src, len,
							comp_field->
							v44_params);
			break;

		/* If no suitable decoder is detected, 
		   leave the remaining bytes undecoded */
		default:
			rc = len;
		}
	}

	if (rc >= 0)
		byte_counter += rc;
	else
		return -EINVAL;


	/* Return consumed length */
	return byte_counter;
}


/* Transform an SNDCP-XID message (src) into a list of SNDCP-XID fields */
int gprs_sndcp_parse_xid(struct llist_head *comp_fields, uint8_t *src,
			 unsigned int src_len,
			 struct gprs_sndcp_hdrcomp_entity_algo_table
			 *lt, unsigned int lt_len)
{
	int src_pos = 0;
	uint8_t tag;
	uint16_t tag_len;
	const uint8_t *val;
	struct gprs_sndcp_comp_field *comp_field;
	int rc;
	int byte_counter = 0;
	int comp_field_count = 0;

	/* Valid TLV-Tag and types */
	static const struct tlv_definition sndcp_xid_def = {
		.def = {
			[SNDCP_XID_VERSION_NUMBER] = {TLV_TYPE_TLV,},
			[SNDCP_XID_DATA_COMPRESSION] = {TLV_TYPE_TLV,},
			[SNDCP_XID_PROTOCOL_COMPRESSION] = {TLV_TYPE_TLV,},
			},
	};

	/* Parse TLV-Encoded SNDCP-XID message and defer payload 
	   to the apporpiate sub-parser functions */
	while (1) {
		src_pos +=
		    tlv_parse_one(&tag, &tag_len, &val, &sndcp_xid_def,
				  src + src_pos,
				  src_len - src_pos);

		/* Decode compression parameters */
		if ((tag == SNDCP_XID_PROTOCOL_COMPRESSION)
		    || (tag == SNDCP_XID_DATA_COMPRESSION)) {
			byte_counter = 0;
			do {
				/* Bail if more than the maximum number of
				   comp_fields is generated */
				if (comp_field_count > MAX_ENTITIES * 2) {
					gprs_sndcp_free_comp_fields(comp_fields);
					return -EINVAL;
				}

				/* Parse and add comp_field */
				comp_field =
				    talloc_zero(NULL,
						struct
						gprs_sndcp_comp_field);

				rc = decode_comp_field(val + byte_counter,
						       tag_len -
						       byte_counter,
						       comp_field, lt,
						       lt_len, tag);

				if (rc < 0) {
					talloc_free(comp_field);
					gprs_sndcp_free_comp_fields(comp_fields);
					return -EINVAL;
				} else {
					byte_counter += rc;
					llist_add(&comp_field->list,
						  comp_fields);
				}

				comp_field_count++;
			}
			while (tag_len - byte_counter > 0);
		}

		/* Stop when no further TLV elements can be expected */
		if (src_len - src_pos <= 2)
			break;
	}

	return 0;
}


/* Free a list with SNDCP-XID fields */
void gprs_sndcp_free_comp_fields(struct llist_head *comp_fields)
{
	struct gprs_sndcp_comp_field *comp_field;
	struct llist_head *lh, *lh2;

	/* Exit immediately if no list is present */
	if (!comp_fields)
		return;

	llist_for_each_entry(comp_field, comp_fields, list) {
		if (comp_field->rfc1144_params)
			talloc_free(comp_field->rfc1144_params);
		if (comp_field->rfc2507_params)
			talloc_free(comp_field->rfc2507_params);
		if (comp_field->rohc_params)
			talloc_free(comp_field->rohc_params);
		if (comp_field->v42bis_params)
			talloc_free(comp_field->v42bis_params);
		if (comp_field->v44_params)
			talloc_free(comp_field->v44_params);
	}

	llist_for_each_safe(lh, lh2, comp_fields) {
		llist_del(lh);
		talloc_free(lh);
	}
}


/* Fill up lookutable from a list with comression entitiy fields */
int gprs_sndcp_fill_table(struct gprs_sndcp_hdrcomp_entity_algo_table *lt,
			   unsigned int lt_len, struct llist_head *comp_fields)
{
	struct gprs_sndcp_comp_field *comp_field;
	int i = 0;

	if (!(comp_fields))
		return -EINVAL;
	if (!(lt))
		return -EINVAL;

	memset(lt,0,lt_len*sizeof(struct gprs_sndcp_hdrcomp_entity_algo_table));

	llist_for_each_entry(comp_field, comp_fields, list) {

		lt[i].entity = comp_field->entity;
		lt[i].algo = comp_field->algo;
		lt[i].compclass = gprs_sndcp_get_compression_class(comp_field);

		if(lt[i].compclass < 0)
		{
			memset(lt,0,lt_len*
			sizeof(struct gprs_sndcp_hdrcomp_entity_algo_table));
			return -EINVAL;
		}

		i++;
	}

	return i;
}


/* 
 * Helper for gprs_sndcp_dump_comp_fields(),
 * dumps protocol compression parameters 
 */
static void dump_pcomp_params(struct gprs_sndcp_comp_field *comp_field)
{
	int i;
			switch (comp_field->algo) {
			case RFC_1144:
				LOGP(DSNDCP, LOGL_DEBUG,
				     "   gprs_sndcp_hdrcomp_rfc1144_params {\n");
				LOGP(DSNDCP, LOGL_DEBUG,
				     "      nsapi_len=%i;\n",
				     comp_field->rfc1144_params->
				     nsapi_len);
				if (comp_field->rfc1144_params->
				    nsapi_len == 0)
					LOGP(DSNDCP, LOGL_DEBUG,
					     "      nsapi[] = NULL;\n");
				for (i = 0;
				     i <
				     comp_field->rfc1144_params->nsapi_len;
				     i++)
					LOGP(DSNDCP, LOGL_DEBUG,
					     "      nsapi[%i]=%i;\n", i,
					     comp_field->rfc1144_params->
					     nsapi[i]);
				DEBUGP(DSNDCP, "      s01=%i;\n",
				     comp_field->rfc1144_params->s01);
				DEBUGP(DSNDCP, "   }\n");
				break;
			case RFC_2507:
				LOGP(DSNDCP, LOGL_DEBUG,
				     "   gprs_sndcp_hdrcomp_rfc2507_params {\n");
				LOGP(DSNDCP, LOGL_DEBUG,
				     "      nsapi_len=%i;\n",
				     comp_field->rfc2507_params->
				     nsapi_len);
				if (comp_field->rfc2507_params->
				    nsapi_len == 0)
					LOGP(DSNDCP, LOGL_DEBUG,
					     "      nsapi[] = NULL;\n");
				for (i = 0;
				     i <
				     comp_field->rfc2507_params->nsapi_len;
				     i++)
					LOGP(DSNDCP, LOGL_DEBUG,
					     "      nsapi[%i]=%i;\n", i,
					     comp_field->rfc2507_params->
					     nsapi[i]);
				LOGP(DSNDCP, LOGL_DEBUG,
				     "      f_max_period=%i;\n",
				     comp_field->rfc2507_params->
				     f_max_period);
				LOGP(DSNDCP, LOGL_DEBUG,
				     "      f_max_time=%i;\n",
				     comp_field->rfc2507_params->
				     f_max_time);
				LOGP(DSNDCP, LOGL_DEBUG,
				     "      max_header=%i;\n",
				     comp_field->rfc2507_params->
				     max_header);
				LOGP(DSNDCP, LOGL_DEBUG,
				     "      tcp_space=%i;\n",
				     comp_field->rfc2507_params->
				     tcp_space);
				LOGP(DSNDCP, LOGL_DEBUG,
				     "      non_tcp_space=%i;\n",
				     comp_field->rfc2507_params->
				     non_tcp_space);
				DEBUGP(DSNDCP, "   }\n");
				break;
			case ROHC:
				LOGP(DSNDCP, LOGL_DEBUG,
				     "   gprs_sndcp_hdrcomp_rohc_params {\n");
				LOGP(DSNDCP, LOGL_DEBUG,
				     "      nsapi_len=%i;\n",
				     comp_field->rohc_params->nsapi_len);
				if (comp_field->rohc_params->nsapi_len ==
				    0)
					LOGP(DSNDCP, LOGL_DEBUG,
					     "      nsapi[] = NULL;\n");
				for (i = 0;
				     i <
				     comp_field->rohc_params->nsapi_len;
				     i++)
					LOGP(DSNDCP, LOGL_DEBUG,
					     "      nsapi[%i]=%i;\n", i,
					     comp_field->rohc_params->
					     nsapi[i]);
				LOGP(DSNDCP, LOGL_DEBUG,
				     "      max_cid=%i;\n",
				     comp_field->rohc_params->max_cid);
				LOGP(DSNDCP, LOGL_DEBUG,
				     "      max_header=%i;\n",
				     comp_field->rohc_params->max_header);
				if (comp_field->rohc_params->profile_len ==
				    0)
					LOGP(DSNDCP, LOGL_DEBUG,
					     "      profile[] = NULL;\n");
				for (i = 0;
				     i <
				     comp_field->rohc_params->profile_len;
				     i++)
					LOGP(DSNDCP, LOGL_DEBUG,
					     "      profile[%i]=%04x;\n",
					     i,
					     comp_field->rohc_params->
					     profile[i]);
				DEBUGP(DSNDCP, "   }\n");
				break;
			}


}


/* 
 * Helper for gprs_sndcp_dump_comp_fields(),
 * data protocol compression parameters 
 */
static void dump_dcomp_params(struct gprs_sndcp_comp_field *comp_field)
{
	int i;
			switch (comp_field->algo) {
			case V42BIS:
				LOGP(DSNDCP, LOGL_DEBUG,
				     "   gprs_sndcp_datacomp_v42bis_params {\n");
				LOGP(DSNDCP, LOGL_DEBUG,
				     "      nsapi_len=%i;\n",
				     comp_field->v42bis_params->nsapi_len);
				if (comp_field->v42bis_params->nsapi_len ==
				    0)
					LOGP(DSNDCP, LOGL_DEBUG,
					     "      nsapi[] = NULL;\n");
				for (i = 0;
				     i <
				     comp_field->v42bis_params->nsapi_len;
				     i++)
					LOGP(DSNDCP, LOGL_DEBUG,
					     "      nsapi[%i]=%i;\n", i,
					     comp_field->v42bis_params->
					     nsapi[i]);
				DEBUGP(DSNDCP, "      p0=%i;\n",
				     comp_field->v42bis_params->p0);
				DEBUGP(DSNDCP, "      p1=%i;\n",
				     comp_field->v42bis_params->p1);
				DEBUGP(DSNDCP, "      p2=%i;\n",
				     comp_field->v42bis_params->p2);
				DEBUGP(DSNDCP, "   }\n");
				break;
			case V44:
				LOGP(DSNDCP, LOGL_DEBUG,
				     "   gprs_sndcp_datacomp_v44_params {\n");
				LOGP(DSNDCP, LOGL_DEBUG,
				     "      nsapi_len=%i;\n",
				     comp_field->v44_params->nsapi_len);
				if (comp_field->v44_params->nsapi_len == 0)
					LOGP(DSNDCP, LOGL_DEBUG,
					     "      nsapi[] = NULL;\n");
				for (i = 0;
				     i < comp_field->v44_params->nsapi_len;
				     i++)
					LOGP(DSNDCP, LOGL_DEBUG,
					     "      nsapi[%i]=%i;\n", i,
					     comp_field->v44_params->
					     nsapi[i]);
				DEBUGP(DSNDCP, "      c0=%i;\n",
				     comp_field->v44_params->c0);
				DEBUGP(DSNDCP, "      p0=%i;\n",
				     comp_field->v44_params->p0);
				DEBUGP(DSNDCP, "      p1t=%i;\n",
				     comp_field->v44_params->p1t);
				DEBUGP(DSNDCP, "      p1r=%i;\n",
				     comp_field->v44_params->p1r);
				DEBUGP(DSNDCP, "      p3t=%i;\n",
				     comp_field->v44_params->p3t);
				DEBUGP(DSNDCP, "      p3r=%i;\n",
				     comp_field->v44_params->p3r);
				DEBUGP(DSNDCP, "   }\n");
				break;
			}
}


/* Dump a list with SNDCP-XID fields (Debug) */
void gprs_sndcp_dump_comp_fields(struct llist_head *comp_fields)
{
	struct gprs_sndcp_comp_field *comp_field;
	int i;
	int compclass;

	llist_for_each_entry(comp_field, comp_fields, list) {
		DEBUGP(DSNDCP, "SNDCP-XID:\n");
		LOGP(DSNDCP, LOGL_DEBUG,
		     "struct gprs_sndcp_comp_field {\n");
		DEBUGP(DSNDCP, "   entity=%i;\n",
		     comp_field->entity);
		DEBUGP(DSNDCP, "   algo=%i;\n",
		     comp_field->algo);
		DEBUGP(DSNDCP, "   comp_len=%i;\n",
		     comp_field->comp_len);
		if (comp_field->comp_len == 0)
			DEBUGP(DSNDCP, "   comp[] = NULL;\n");
		for (i = 0; i < comp_field->comp_len; i++)
			DEBUGP(DSNDCP, "   comp[%i]=%i;\n", i,
			     comp_field->comp[i]);

		compclass = gprs_sndcp_get_compression_class(comp_field);

		if (compclass == SNDCP_XID_PROTOCOL_COMPRESSION) {
			dump_pcomp_params(comp_field);
		} else if (compclass == SNDCP_XID_DATA_COMPRESSION) {
			dump_dcomp_params(comp_field);
		}

		DEBUGP(DSNDCP, "}\n");
		DEBUGP(DSNDCP, "\n");
	}

}
