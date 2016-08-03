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
#include <osmocom/core/talloc.h>

#include <openbsc/debug.h>
#include <openbsc/gprs_llc.h>
#include <openbsc/sgsn.h>
#include <openbsc/gprs_llc_xid.h>


/* Parse XID parameter field */
static int
decode_xid_field(uint8_t *src, uint8_t src_len,
		 struct gprs_llc_xid_field *xid_field)
{
	uint8_t xl;
	uint8_t type;
	uint8_t len;
	int src_counter = 0;

	/* Exit immediately if it is clear that no
	   parseable data is present */
	if ((src_len < 1) || !src)
		return -EINVAL;

	/* Exit immediately if no result can be stored */
	if (!xid_field)
		return -EINVAL;

	/* Extract header info */
	xl = (*src >> 7) & 1;
	type = (*src >> 2) & 0x1F;

	/* Extract length field */
	len = (*src) & 0x3;
	src++;
	src_counter++;
	if (xl) {
		if (src_len < 2)
			return -EINVAL;
		len = (len << 6) & 0xC0;
		len |= ((*src) >> 2) & 0x3F;
		src++;
		src_counter++;
	}

	/* Fill out struct */
	xid_field->type = type;
	xid_field->data_len = len;
	if (len > 0) {
		if (src_len < src_counter + len)
			return -EINVAL;

		xid_field->data =
		    talloc_zero_size(NULL, xid_field->data_len);
		memcpy(xid_field->data, src, xid_field->data_len);
	} else
		xid_field->data = NULL;

	/* Return consumed length */
	return src_counter + len;
}


/* Encode XID parameter field */
static int
encode_xid_field(uint8_t *dst, int dst_maxlen,
		 struct gprs_llc_xid_field *xid_field)
{
	int xl = 0;

	/* Exit immediately if no source struct is available */
	if (!xid_field)
		return -EINVAL;

	/* When the length does not fit into 2 bits,
	   we need extended length fields */
	if (xid_field->data_len > 3)
		xl = 1;

	/* Exit immediately if it is clear that no
	   encoding result can be stored */
	if (dst_maxlen < xid_field->data_len + 1 + xl)
		return -EINVAL;

	/* There are only 5 bits reserved for the type, exit on exceed */
	if (xid_field->type > 31)
		return -EINVAL;

	/* Encode header */
	memset(dst, 0, dst_maxlen);
	if (xl)
		dst[0] |= 0x80;
	dst[0] |= (((xid_field->type) & 0x1F) << 2);

	if (xl) {
		dst[0] |= (((xid_field->data_len) >> 6) & 0x03);
		dst[1] = ((xid_field->data_len) << 2) & 0xFC;
	} else
		dst[0] |= ((xid_field->data_len) & 0x03);

	/* Append payload data */
	if ((xid_field->data) && (xid_field->data_len))
		memcpy(dst + 1 + xl, xid_field->data,
		       xid_field->data_len);

	/* Return generated length */
	return xid_field->data_len + 1 + xl;
}


/* Transform a list with XID fields into a XID message (dst) */
int
gprs_llc_compile_xid(struct llist_head *xid_fields, uint8_t *dst,
		     int dst_maxlen)
{
	struct gprs_llc_xid_field *xid_field;
	int rc;
	int byte_counter = 0;

	memset(dst, 0, dst_maxlen);

	llist_for_each_entry(xid_field, xid_fields, list) {
		/* Encode XID-Field */
		rc = encode_xid_field(dst, dst_maxlen, xid_field);

		/* Immediately stop on error */
		if (rc < 0)
			return rc;

		/* Advance pointer and lower maxlen for the
		   next encoding round */
		dst += rc;
		byte_counter += rc;
		dst_maxlen -= rc;
	}

	/* Return generated length */
	return byte_counter;
}


/* Transform a XID message (dst) into a list of XID fields */
int
gprs_llc_parse_xid(struct llist_head *xid_fields, uint8_t *dst,
		   int dst_len)
{
	struct gprs_llc_xid_field *xid_field;
	int rc;

	while (1) {
		/* Decode XID field */
		xid_field = talloc_zero(NULL, struct gprs_llc_xid_field);
		rc = decode_xid_field(dst, dst_len, xid_field);

		/* Immediately stop on error */
		if (rc < 0) {
			gprs_llc_free_xid(xid_fields);
			return -EINVAL;
		}

		/* Add parsed XID field to list */
		llist_add(&xid_field->list, xid_fields);

		/* Advance pointer and lower dst_len for the next
		   decoding round */
		dst += rc;
		dst_len -= rc;

		/* We are (scuccessfully) done when no further byes are left */
		if (dst_len == 0)
			return 0;
	}
}


/* Free llist with xid fields */
void gprs_llc_free_xid(struct llist_head *xid_fields)
{
	struct gprs_llc_xid_field *xid_field;
	struct llist_head *lh, *lh2;

	if (xid_fields) {
		llist_for_each_entry(xid_field, xid_fields, list) {
			if ((xid_field->data) && (xid_field->data_len))
				talloc_free(xid_field->data);
		}

		llist_for_each_safe(lh, lh2, xid_fields) {
			llist_del(lh);
			talloc_free(lh);
		}
	}
}


/* Create a duplicate of an XID-Field */
struct gprs_llc_xid_field *gprs_llc_duplicate_xid_field(struct
							gprs_llc_xid_field
							*xid_field)
{
	struct gprs_llc_xid_field *duplicate_of_xid_field;

	/* Create a copy of the XID field in memory */
	duplicate_of_xid_field =
	    talloc_zero(NULL, struct gprs_llc_xid_field);
	memcpy(duplicate_of_xid_field, xid_field,
	       sizeof(struct gprs_llc_xid_field));
	duplicate_of_xid_field->data =
	    talloc_zero_size(NULL, xid_field->data_len);
	memcpy(duplicate_of_xid_field->data, xid_field->data,
	       xid_field->data_len);

	/* Wipeout all llist information in the duplicate (just to be sure) */
	memset(&duplicate_of_xid_field->list, 0,
	       sizeof(struct llist_head));

	return duplicate_of_xid_field;
}

/* Copy an llist with xid fields */
void gprs_llc_copy_xid(struct llist_head *xid_fields_copy, 
		       struct llist_head *xid_fields_orig)
{
	struct gprs_llc_xid_field *xid_field;

	/* Make sure that the target list is empty */
	gprs_llc_free_xid(xid_fields_copy);

	/* Create duplicates and add them to the target list */
	llist_for_each_entry(xid_field, xid_fields_orig, list) {
		llist_add(&gprs_llc_duplicate_xid_field(xid_field)->list, xid_fields_copy);
	}
}

/* Dump a list with XID fields (Debug) */
void gprs_llc_dump_xid_fields(struct llist_head *xid_fields)
{
	struct gprs_llc_xid_field *xid_field;

	llist_for_each_entry(xid_field, xid_fields, list) {
		LOGP(DSNDCP, LOGL_DEBUG,
		     "XID: type=%i, data_len=%i, data=%s\n",
		     xid_field->type, xid_field->data_len,
		     osmo_hexdump_nospc(xid_field->data,
					xid_field->data_len));
	}
}
