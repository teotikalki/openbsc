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

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <errno.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <openbsc/debug.h>
#include <openbsc/gprs_sndcp_xid.h>
#include <openbsc/gprs_sndcp_comp.h>
#include <openbsc/gprs_sndcp_pcomp.h>

/* Create a new compression entity from a XID-Field */
static struct gprs_sndcp_comp *gprs_sndcp_comp_create(const void
						      *ctx, const struct
						      gprs_sndcp_comp_field
						      *comp_field)
{
	OSMO_ASSERT(comp_field);

	struct gprs_sndcp_comp *comp_entity;
	comp_entity = talloc_zero(ctx, struct gprs_sndcp_comp);

	/* Copy relevant information from the SNDCP-XID field */
	comp_entity->entity = comp_field->entity;
	comp_entity->comp_len = comp_field->comp_len;
	memcpy(comp_entity->comp, comp_field->comp,
	       comp_field->comp_len * sizeof(int));

	if (comp_field->rfc1144_params) {
		comp_entity->nsapi_len = comp_field->rfc1144_params->nsapi_len;
		memcpy(comp_entity->nsapi,
		       comp_field->rfc1144_params->nsapi,
		       comp_entity->nsapi_len * sizeof(int));
	} else if (comp_field->rfc2507_params) {
		comp_entity->nsapi_len = comp_field->rfc2507_params->nsapi_len;
		memcpy(comp_entity->nsapi,
		       comp_field->rfc2507_params->nsapi,
		       comp_entity->nsapi_len * sizeof(int));
	} else if (comp_field->rohc_params) {
		comp_entity->nsapi_len = comp_field->rohc_params->nsapi_len;
		memcpy(comp_entity->nsapi, comp_field->rohc_params->nsapi,
		       comp_entity->nsapi_len * sizeof(int));
	} else if (comp_field->v42bis_params) {
		comp_entity->nsapi_len = comp_field->v42bis_params->nsapi_len;
		memcpy(comp_entity->nsapi,
		       comp_field->v42bis_params->nsapi,
		       comp_entity->nsapi_len * sizeof(int));
	} else if (comp_field->v44_params) {
		comp_entity->nsapi_len = comp_field->v42bis_params->nsapi_len;
		memcpy(comp_entity->nsapi,
		       comp_field->v42bis_params->nsapi,
		       comp_entity->nsapi_len * sizeof(int));
	} else {
		talloc_free(comp_entity);
		LOGP(DSNDCP, LOGL_ERROR,
		     "Comp field contained invalid parameters, compression entity not created!\n");
		return NULL;
	}

	comp_entity->algo = comp_field->algo;
	comp_entity->state = NULL;

	/* Determine of which class our compression entity will be
	 * (Protocol or Data compresson ?) */
	comp_entity->compclass = gprs_sndcp_get_compression_class(comp_field);

	if (comp_entity->compclass == SNDCP_XID_PROTOCOL_COMPRESSION) {
		if (gprs_sndcp_pcomp_init(ctx, comp_entity, comp_field) == 0)
			LOGP(DSNDCP, LOGL_INFO,
			     "New header compression entity (%i) created.\n",
			     comp_entity->entity);
		else {
			talloc_free(comp_entity);
			LOGP(DSNDCP, LOGL_ERROR,
			     "Header compression entity (%i) creation failed!\n",
			     comp_entity->entity);
			return NULL;
		}
	} else
		LOGP(DSNDCP, LOGL_INFO,
		     "New data compression entity (%i) created.\n",
		     comp_entity->entity);

	return comp_entity;
}

/* Free a list with compression entities */
void gprs_sndcp_comp_free(struct llist_head *comp_entities)
{
	struct llist_head *ce, *ce2;
	struct gprs_sndcp_comp *comp_entity;

	OSMO_ASSERT(comp_entities);

		llist_for_each_entry(comp_entity, comp_entities, list) {
			/* Free compression entity */
			if (comp_entity->compclass ==
			    SNDCP_XID_PROTOCOL_COMPRESSION) {
				LOGP(DSNDCP, LOGL_INFO,
				     "Deleting header compression entity %i ...\n",
				     comp_entity->entity);
				gprs_sndcp_pcomp_term(comp_entity);
			} else
				LOGP(DSNDCP, LOGL_INFO,
				     "Deleting data compression entity %i ...\n",
				     comp_entity->entity);
		}

		llist_for_each_safe(ce, ce2, comp_entities) {
			llist_del(ce);
			talloc_free(ce);
		}
	
}

/* Delete a compression entity */
void gprs_sndcp_comp_delete(struct llist_head *comp_entities, int entity)
{
	struct gprs_sndcp_comp *comp_entity;
	struct gprs_sndcp_comp *comp_entity_to_delete = NULL;

	OSMO_ASSERT(comp_entities);

		llist_for_each_entry(comp_entity, comp_entities, list) {
			if (comp_entity->entity == entity)
				comp_entity_to_delete = comp_entity;
		}

		if (comp_entity_to_delete) {
			if (comp_entity_to_delete->compclass ==
			    SNDCP_XID_PROTOCOL_COMPRESSION) {
				LOGP(DSNDCP, LOGL_INFO,
				     "Deleting header compression entity %i ...\n",
				     comp_entity_to_delete->entity);
				gprs_sndcp_pcomp_term(comp_entity_to_delete);
			} else
				LOGP(DSNDCP, LOGL_INFO,
				     "Deleting data compression entity %i ...\n",
				     comp_entity_to_delete->entity);

			/* Delete compression entity */
			llist_del(&comp_entity_to_delete->list);
			talloc_free(comp_entity_to_delete);
		}
	
}

/* Create and Add a new compression entity
 * (returns a pointer to the compression entity that has just been created) */
struct gprs_sndcp_comp *gprs_sndcp_comp_entities_add(const void *ctx, struct
						     llist_head
						     *comp_entities, const struct
						     gprs_sndcp_comp_field
						     *comp_field)
{
	struct gprs_sndcp_comp *comp_entity;

	OSMO_ASSERT(comp_entities);
	OSMO_ASSERT(comp_field);

	/* Just to be sure, if the entity is already in
	 * the list it will be deleted now */
	gprs_sndcp_comp_delete(comp_entities, comp_field->entity);

	/* Create and add a new entity to the list */
	comp_entity = gprs_sndcp_comp_create(ctx, comp_field);

	if (comp_entity) {
		llist_add(&comp_entity->list, comp_entities);
		return comp_entity;
	}

	return NULL;
}

/* Find compression entity by its entity number */
struct gprs_sndcp_comp *gprs_sndcp_comp_by_entity(const struct
						  llist_head
						  *comp_entities, int entity)
{
	struct gprs_sndcp_comp *comp_entity;

	OSMO_ASSERT(comp_entities);


		llist_for_each_entry(comp_entity, comp_entities, list) {
			if (comp_entity->entity == entity)
				return comp_entity;
		}


	LOGP(DSNDCP, LOGL_ERROR,
	     "Could not find a matching compression entity for given entity number %i.\n",
	     entity);
	return NULL;
}

/* Find which compression entity handles the specified pcomp/dcomp */
struct gprs_sndcp_comp *gprs_sndcp_comp_by_comp(const struct
						llist_head
						*comp_entities, int comp)
{
	struct gprs_sndcp_comp *comp_entity;
	int i;

	OSMO_ASSERT(comp_entities);

		llist_for_each_entry(comp_entity, comp_entities, list) {
			for (i = 0; i < comp_entity->comp_len; i++) {
				if (comp_entity->comp[i] == comp)
					return comp_entity;
			}
		}
	

	LOGP(DSNDCP, LOGL_ERROR,
	     "Could not find a matching compression entity for given pcomp/dcomp value %i.\n",
	     comp);
	return NULL;
}

/* Find which compression entity handles the specified nsapi */
struct gprs_sndcp_comp *gprs_sndcp_comp_by_nsapi(const struct
						 llist_head
						 *comp_entities, int nsapi)
{
	struct gprs_sndcp_comp *comp_entity;
	int i;

	OSMO_ASSERT(comp_entities);



	llist_for_each_entry(comp_entity, comp_entities, list) {
		for (i = 0; i < comp_entity->nsapi_len; i++) {
			if (comp_entity->nsapi[i] == nsapi)
				return comp_entity;
		}
	}

	LOGP(DSNDCP, LOGL_ERROR,
	     "Could not find a matching compression entity for given nsapi value %i\n",
	     nsapi);
	return NULL;

}

/* Find a comp_index for a given pcomp/dcomp value */
int gprs_sndcp_comp_get_idx(const struct
			    gprs_sndcp_comp
			    *comp_entity, int comp)
{
	int i;

	OSMO_ASSERT(comp_entity);


	/* A pcomp/dcomp field set to zero always disables
	 * all sort of compression and is assigned fix. So we
	 * just return zero in this case */
	if (comp == 0)
		return 0;

	/* Look in the pcomp/dcomp list for the index */
	for (i = 0; i < comp_entity->comp_len; i++) {
		if (comp_entity->comp[i] == comp)
			return i + 1;
	}

	LOGP(DSNDCP, LOGL_ERROR,
	     "Could not find a matching comp_index for given pcomp/dcomp value %i\n",
	     comp);
	return 0;

}

/* Find a pcomp/dcomp value for a given comp_index */
int gprs_sndcp_comp_get_comp(const struct
			     gprs_sndcp_comp
			     *comp_entity, int comp_index)
{
	OSMO_ASSERT(comp_entity);

	/* A comp_index of zero translates to zero right away. */
	if (comp_index == 0)
		return 0;

	if (comp_index > comp_entity->comp_len) {
		LOGP(DSNDCP, LOGL_ERROR,
		     "Could not find a matching pcomp/dcomp value for given comp_index value %i.\n",
		     comp_index);
		return 0;
	}

	/* Look in the pcomp/dcomp list for the comp_index */
	return comp_entity->comp[comp_index - 1];

}
