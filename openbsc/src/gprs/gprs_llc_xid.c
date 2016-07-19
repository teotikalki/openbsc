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
#include <errno.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>

#include <openbsc/gprs_llc.h>
#include <openbsc/sgsn.h>
#include <openbsc/gprs_llc_xid.h>


/* Parse XID parameter field */
static int decode_xid_field(uint8_t *bytes, uint8_t bytes_len, struct gprs_llc_xid_field *xid_field)
{
	uint8_t xl;
	uint8_t type;
	uint8_t len;
	int bytes_counter = 0;

	/* Exit immediately if it is clear that no
           parseable data is present */
	if((bytes_len < 1)||(!(bytes)))
		return -EINVAL;

	/* Exit immediately if no result can be stored */
	if(!xid_field)
		return -EINVAL;

	/* Extract header info */
	xl = (*bytes >> 7)&1;
	type = (*bytes >> 2)&0x1F;

	/* Extract length field */
	len = (*bytes) & 0x3;
	bytes++;
	bytes_counter++;
	if(xl)
	{
		if(bytes_len < 2)
			return -EINVAL;
		len = (len << 6) & 0xC0;
		len |= ((*bytes) >> 2) & 0x3F;
		bytes++;
		bytes_counter++;
	}

	/* Fill out struct */
	xid_field->type = type;
	xid_field->data_len = len;
	if(len > 0)
	{
		if(bytes_len < bytes_counter+len)
			return -EINVAL;	
		xid_field->data = bytes;
	}
	else
		xid_field->data = NULL;

	/* Return consumed length */
	return bytes_counter+len;
}


/* Encode XID parameter field */
static int encode_xid_field(uint8_t *bytes, int bytes_maxlen, struct gprs_llc_xid_field *xid_field)
{
	int xl = 0;

	/* Exit immediately if no source struct is available */
	if(!xid_field)
		return -EINVAL;

	/* When the length does not fit into 2 bits, we need extended length fields */
	if(xid_field->data_len > 3)
		xl = 1;

	/* Exit immediately if it is clear that no
           encoding result can be stored */
	if(bytes_maxlen < xid_field->data_len+1+xl)
		return -EINVAL;

	/* There are only 5 bits reserved for the type, exit on exceed */
	if(xid_field->type > 31)
		return -EINVAL;

	/* Encode header */
	memset(bytes,0,bytes_maxlen);
	if(xl)
		bytes[0] |= 0x80;
	bytes[0] |= (((xid_field->type)&0x1F) << 2);

	if(xl)
	{
		bytes[0] |= (((xid_field->data_len) >> 6) & 0x03);
		bytes[1] = ((xid_field->data_len) << 2) & 0xFC;
	}
	else
		bytes[0] |= ((xid_field->data_len) & 0x03);

	/* Append payload data */
	if((xid_field->data)&&(xid_field->data_len))
		memcpy(bytes+1+xl,xid_field->data,xid_field->data_len);

	/* Return generated length */
	return xid_field->data_len+1+xl;
}


/* Transform a list with XID fields into a XID message (bytes) */
int gprs_llc_compile_xid(struct llist_head *xid_fields, uint8_t *bytes, int bytes_maxlen)
{
	struct gprs_llc_xid_field *xid_field;
	int rc;
	int byte_counter = 0;

	memset(bytes,0,bytes_maxlen);

	llist_for_each_entry(xid_field, xid_fields, list) 
	{
		/* Encode XID-Field */
		rc = encode_xid_field(bytes, bytes_maxlen, xid_field);

		/* Immediately stop on error */
		if(rc < 0)
			return rc;

		/* Advance pointer and lower maxlen for the next encoding round */
		bytes+=rc;
		byte_counter+=rc;
		bytes_maxlen-=rc;
	}

	/* Return generated length */
	return byte_counter;
}


/* Transform a XID message (bytes) into a list of XID fields */
int gprs_llc_parse_xid(struct llist_head *xid_fields, uint8_t *bytes, int bytes_len)
{
	struct gprs_llc_xid_field *xid_field;
	int rc;

	while(1)
	{
		/* Decode XID field */
		xid_field = talloc_zero(NULL, struct gprs_llc_xid_field);
		rc = decode_xid_field(bytes, bytes_len, xid_field);

		/* Immediately stop on error */
		if(rc < 0)
			return rc;

		/* Add parsed XID field to list */
		llist_add(&xid_field->list, xid_fields);

		/* Advance pointer and lower bytes_len for the next decoding round */
		bytes+=rc;
		bytes_len-=rc;

		/* We are (scuccessfully) done when no further byes are left */
		if(bytes_len == 0)
			return 0;
	}
}


/* Free llist with xid fields */
void gprs_llc_free_xid(struct llist_head *xid_fields)
{
	struct gprs_llc_xid_field *xid_field;

	llist_for_each_entry(xid_field, xid_fields, list) 
	{
		talloc_free(xid_field);
	}

}

/* Create a duplicate of an XID-Field */
struct gprs_llc_xid_field *gprs_llc_duplicate_xid_field(struct gprs_llc_xid_field *xid_field)
{
	struct gprs_llc_xid_field *duplicate_of_xid_field;

	/* Create a copy of the XID field in memory */
	duplicate_of_xid_field = talloc_zero(NULL, struct gprs_llc_xid_field);
	memcpy(duplicate_of_xid_field, xid_field, sizeof(struct gprs_llc_xid_field));

	/* Wipeout all llist information in the duplicate (just to be sure) */
	memset(&duplicate_of_xid_field->list,0,sizeof(struct llist_head));

	return duplicate_of_xid_field;
}



