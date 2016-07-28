/* GPRS SNDCP header compression entity management tools */

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

#ifndef _GPRS_SNDCP_COMP_ENTITY_H
#define _GPRS_SNDCP_COMP_ENTITY_H

#include <stdint.h>
#include <osmocom/core/linuxlist.h>

/* Header / Data compression entity */
struct gprs_sndcp_comp_entity {
	struct llist_head list;

	/* Serves as an identifier in case we want to delete this entity later */
	int entity;		/* Entity number, see also: 6.5.1.1.3 and 6.6.1.1.3 */

	/* Specifies to which NSAPIs the compression entity is assigned */
	int nsapi_len;		/* Number of applicable NSAPIs (default 0) */
	int nsapi[11];		/* Applicable NSAPIs (default 0) */

	/* Assigned pcomp values */
	int comp_len;		/* Number of contained PCOMP / DCOMP values */
	int comp[16];		/* PCOMP / DCOMP values, see also: 6.5.1.1.5 and 6.6.1.1.5 */

	/* Algorithm parameters */
	int algo;		/* Algorithm type (see gprs_sndcp_xid.h) */
	int compclass;		/* See gprs_sndcp_xid.h/c */
	void *status;		/* Algorithm status and parameters */
};

/* Free a list with compression entities */
void gprs_sndcp_comp_entities_free(struct llist_head *comp_entities);

/* Delete a compression entity */
void gprs_sndcp_comp_entities_delete(struct llist_head *comp_entities, int entity);

/* Create and Add a new compression entity (returns a pointer to the compression entity that has just been created) */
struct gprs_sndcp_comp_entity *gprs_sndcp_comp_entities_add(struct llist_head *comp_entities, struct gprs_sndcp_comp_field *comp_field);

/* Find compression entity by its entity number */
struct gprs_sndcp_comp_entity *gprs_sndcp_comp_entity_find_by_entity(struct llist_head *comp_entities, int entity);

/* Find which compression entity handles the specified pcomp/dcomp */
struct gprs_sndcp_comp_entity *gprs_sndcp_comp_entity_find_by_comp(struct llist_head *comp_entities, int comp);

/* Find which compression entity handles the specified pcomp/dcomp */
struct gprs_sndcp_comp_entity *gprs_sndcp_comp_entity_find_by_nsapi(struct llist_head *comp_entities, int nsapi);

/* Find a comp_index for a given pcomp/dcomp value */
int gprs_sndcp_comp_entity_find_comp_index_by_comp(struct gprs_sndcp_comp_entity *comp_entity, int comp);

/* Find a pcomp/dcomp value for a given comp_index */
int gprs_sndcp_comp_entity_find_comp_by_comp_index(struct gprs_sndcp_comp_entity *comp_entity, int comp_index);

#endif

