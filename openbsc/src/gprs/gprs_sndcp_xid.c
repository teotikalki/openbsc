/* GPRS LLC XID field encoding/decoding as per 3GPP TS 04.64 */

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
#include <osmocom/core/utils.h>
#include <errno.h>
#include <openbsc/gprs_sndcp_xid.h>
#include <openbsc/gprs_llc.h>
#include <osmocom/core/msgb.h>
#include <openbsc/sgsn.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gsm/tlv.h>


/* Encode ROHC parameter field */
static int encode_hdrcomp_rohc_params(uint8_t *bytes, int bytes_maxlen, struct gprs_sndcp_hdrcomp_rohc_params *params)
{
	/* NOTE: Buffer *bytes should offer at least 36 (2 * 16 Profiles + 2 * 3 Parameter) 
                 bytes of memory space to store generation results */

	/* NOTE: Do not call manually, will be called by encode_hdrcomp_comp_field on purpose */

	int i;
	uint16_t blob;
	int nsapi;
	int bytes_counter = 0;

	/* Exit immediately if no source struct is available */
	if(!params)
		return -EINVAL;

	/* Exit immediately if no sufficient memory space is supplied */
	if((bytes_maxlen < 38)||(!(bytes)))
		return -EINVAL;

	/* Exit if number of possible nsapis exceeds valid range
	   (Only 11 nsapis possible for PDP-Contexts) */
	if((params->nsapi_len < 0)||(params->nsapi_len > 11))
		return -EINVAL;

	/* Exit if number of ROHC profiles exceeds limit 
	   (ROHC supports only a maximum of 16 different profiles) */
	if((params->profile_len < 0)||(params->profile_len > 16))
		return -EINVAL;

	/* Zero out buffer */
	memset(bytes,0,bytes_maxlen);

	/* Encode applicable SAPIs */
	blob=0;
	for(i=0;i<params->nsapi_len;i++)
	{
		nsapi = params->nsapi[i];
		if((nsapi < 5)||(nsapi > 15))
			return -EINVAL;
		blob |= (1 << (16-(nsapi-4)));
	}
	*bytes = (blob >> 8)&0xFF;
	bytes++;
	*bytes = blob&0xFF;
	bytes++;
	bytes_counter += 2;

	/* Encode MAX_CID */
	if((params->max_cid < 0)||(params->max_cid > 16383))
		return -EINVAL;
	*bytes = (params->max_cid >> 8)&0xFF;
	bytes++;
	*bytes = params->max_cid&0xFF;
	bytes++;
	bytes_counter += 2;

	/* Encode MAX_HEADER */
	if((params->max_hdr < 60)||(params->max_hdr > 255))
		return -EINVAL;
	*bytes = (params->max_hdr >> 8)&0xFF;
	bytes++;
	*bytes = params->max_hdr&0xFF;
	bytes++;
	bytes_counter += 2;	

	/* Encode ROHC Profiles */
	for(i=0;i<params->profile_len;i++)
	{
		*bytes = (params->profile[i] >> 8)&0xFF;
		bytes++;
		*bytes = params->profile[i]&0xFF;
		bytes++;	
		bytes_counter += 2;
	}

	/* Return generated length */
	return bytes_counter;
}


/* Encode data or protocol control information compression field */
static int encode_hdrcomp_comp_field(uint8_t *bytes, int bytes_maxlen, struct gprs_sndcp_comp_field *comp_field)
{
	int bytes_counter = 0;
	int len;
	int expected_length;
	int i;

	uint8_t payload_bytes[256];
	uint8_t payload_bytes_len = -1;

	/* If possible, try do encode payload bytes first */
	if(comp_field->rohc_params)
		payload_bytes_len = encode_hdrcomp_rohc_params(payload_bytes, sizeof(payload_bytes), comp_field->rohc_params);

	/* NOTE: New compression fields will be added here. If the pointer to the struct is NULL, the field will
                 be ignored. The first field that has a pointer different from NULL will be picked for encoding. */

	/* Exit immediately if payload byte generation failed */
	if(payload_bytes_len < 0)
		return -EINVAL;

	/* Exit immediately if no source struct is available */
	if(!comp_field)
		return -EINVAL;

	/* Check if comp_len is within bounds */
	if((comp_field->comp_len < 0)||(comp_field->comp_len > 16))
		return -EINVAL;

	/* Calculate length field of the data block */
	if(comp_field->p)
	{
		len = payload_bytes_len + ceil((double)(comp_field->comp_len)/2.0);
		expected_length = len + 3;
	}
	else
	{
		len = payload_bytes_len;
		expected_length = len + 2;
	}

	/* Exit immediately if no sufficient memory space is supplied */
	if((bytes_maxlen < expected_length)||(!(bytes)))
		return -EINVAL;

	/* Check if the entity number is within bounds */
	if((comp_field->entity < 0)||(comp_field->entity > 0x1f))
		return -EINVAL;

	/* Check if the algorithm number is within bounds */
	if((comp_field->algo < 0)||(comp_field->algo > 0x1f))
		return -EINVAL;

	/* Zero out buffer */
	memset(bytes,0,bytes_maxlen);

	/* Encode Propose bit */
	if(comp_field->p)
		*bytes |= (1 << 7);

	/* Encode entity number */
	*bytes |= comp_field->entity&0x1F;
	bytes++;
	bytes_counter++;

	/* Encode algorithm number */
	if(comp_field->p)
	{
		*bytes |= comp_field->algo&0x1F;
		bytes++;
		bytes_counter++;
	}

	/* Encode length field */
	*bytes |= len&0xFF;
	bytes++;
	bytes_counter++;

	/* Encode PCOMP/DCOMP values */
	if(comp_field->p)
	{
		for(i=0;i<comp_field->comp_len;i++)
		{
			/* Check if submitted PCOMP/DCOMP values are within bounds */
			if((comp_field->comp[i] < 0)||(comp_field->comp[i] > 0x0F))
				return -EINVAL;

			if(i&1)
			{
				*bytes |= comp_field->comp[i]&0x0F;
				bytes++;
				bytes_counter++;
			}
			else
				*bytes |= (comp_field->comp[i]<<4)&0xF0;
		}

		if(i&1)
		{
			bytes++;
			bytes_counter++;
		}
	}

	/* Append payload bytes */
	memcpy(bytes,payload_bytes,payload_bytes_len);
	bytes_counter+=payload_bytes_len;

	/* Return generated length */
	return bytes_counter;
}


/* Transform a list with compression fields into an SNDCP-XID message (bytes) */
int gprs_sndcp_compile_xid(struct llist_head *comp_fields, uint8_t *bytes, int bytes_maxlen)
{
	struct gprs_sndcp_comp_field *comp_field;
	int rc;
	int byte_counter = 0;

	uint8_t comp_bytes[512];
	uint8_t xid_version_number[1] = {CURRENT_SNDCP_VERSION};

	/* Exit immediately if no sufficient memory space is supplied */
	if((bytes_maxlen < 1+sizeof(xid_version_number))||(!(bytes)))
		return -EINVAL;

	/* Zero out buffer (just to be sure) */
	memset(bytes,0,bytes_maxlen);

	/* Prepend header */
	bytes = tlv_put(bytes,SNDCP_XID_VERSION_NUMBER,sizeof(xid_version_number),xid_version_number);
	byte_counter++;

	llist_for_each_entry(comp_field, comp_fields, list) 
	{
		/* Encode Compression Field */
		rc = encode_hdrcomp_comp_field(comp_bytes, sizeof(comp_bytes), comp_field);

		/* Immediately stop on error */
		if(rc < 0)
			return rc;

		/* Make sure we do not overflow the buffer */
		if(byte_counter < bytes_maxlen)
		{
			/* FIXME: Currently we are setting the type flag SNDCP_XID_PROTOCOL_CONTROL_INFORMATION_COMPRESSION
				  statically, this is fine as long as we do only header compression. If we want to do
				  data compression as welle we need to check in comp_field which compression parameter
				  we deal with */
			bytes = tlv_put(bytes,SNDCP_XID_PROTOCOL_CONTROL_INFORMATION_COMPRESSION,rc,comp_bytes);
			byte_counter+=rc;
		}
		else
			return -EINVAL;
	}

	/* Return generated length */
	return byte_counter;
}


