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

#ifndef _GPRS_SNDCP_HDRCOMP_H
#define _GPRS_SNDCP_HDRCOMP_H

#include <stdint.h>
#include <osmocom/core/linuxlist.h>
#include <openbsc/gprs_sndcp_comp_entity.h>

/* 1=Bypass any header compression, 0=Normal */
#define GPRS_SNDCP_HDRCOMP_BYPASS 0	

/* Header compression entity */
struct gprs_sndcp_hdrcomp_compression_entity {

	/* Specifies to which NSAPIs the compression entity is assigned */
	int nsapi_len;		/* Number of applicable NSAPIs (default 0) */
	int nsapi[11];		/* Applicable NSAPIs (default 0) */

	/* Assigned pcomp values */
	int pcomp_len;		/* Number of contained PCOMP / DCOMP values */
	int pcomp[16];		/* see also: 6.5.1.1.5 and 6.6.1.1.5 */

	/* Algorithm parameters */
	int compclass;		/* 1=Header compression, 2=Data compression */
	int algo;		/* Algorithm type (see gprs_sndcp_xid.h) */
	void *status;		/* Algorithm status and parameters */
};


/* Initalize header compression */
int gprs_sndcp_hdrcomp_init(struct gprs_sndcp_comp_entity *comp_entity,
			    struct gprs_sndcp_comp_field *comp_field);

/* Terminate header compression */
void gprs_sndcp_hdrcomp_term(struct gprs_sndcp_comp_entity *comp_entity);

/* Expand header compressed packet */
int gprs_sndcp_hdrcomp_expand(uint8_t * packet, int packet_len, int pcomp,
			      struct llist_head *comp_entities);

/* Expand header compressed packet */
int gprs_sndcp_hdrcomp_compress(uint8_t * packet, int packet_len,
				int *pcomp,
				struct llist_head *comp_entities,
				int nsapi);

#endif
