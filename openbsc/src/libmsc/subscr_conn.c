/* MSC subscriber connection implementation */

/*
 * (C) 2016 by sysmocom s.m.f.c. <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
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

#include <osmocom/core/logging.h>
#include <osmocom/core/fsm.h>

#include <openbsc/osmo_msc.h>
#include <openbsc/debug.h>

static const struct value_string subscr_conn_fsm_event_names[] = {
	{ SUB_CON_E_LU_RES, "LU-FSM-DONE" },
	OSMO_VALUE_STRING(SUB_CON_E_PARQ_SUCCESS),
	OSMO_VALUE_STRING(SUB_CON_E_PARQ_FAILURE),
	{ SUB_CON_E_MO_CLOSE, "MO-CLOSE-REQUEST" },
	{ SUB_CON_E_CN_CLOSE, "CN-CLOSE-REQUEST" },
	{ SUB_CON_E_CLOSE_CONF, "CLOSE-CONF" },
	{ 0, NULL }
};

void subscr_conn_fsm_new(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	int rc;
	struct gsm_subscriber_connection *conn = fi->priv;
	switch (event) {
	case SUB_CON_E_PARQ_SUCCESS:
		osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_S_ACCEPTED, 0, 0);
		rc = gsm48_tx_mm_serv_ack(conn);
		if (rc)
			LOGPFSML(fi, LOGL_ERROR,
				 "Failed to send CM Service Accept\n");
		break;
	default:
		LOGPFSM(fi, "Unhandled event: %s\n",
			osmo_fsm_event_name(fi->fsm, event));
		break;
	}
}

void subscr_conn_fsm_accepted(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
}

void subscr_conn_fsm_releasing(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
}

#define S(x)	(1 << (x))

static const struct osmo_fsm_state subscr_conn_fsm_states[] = {
	[SUBSCR_CONN_S_NEW] = {
		.name = OSMO_STRINGIFY(SUBSCR_CONN_S_NEW),
		.in_event_mask = S(SUB_CON_E_LU_RES) |
				 S(SUB_CON_E_PARQ_SUCCESS) |
				 S(SUB_CON_E_PARQ_FAILURE) |
				 S(SUB_CON_E_MO_CLOSE) |
				 S(SUB_CON_E_CN_CLOSE) |
				 S(SUB_CON_E_CLOSE_CONF),
		.out_state_mask = S(SUBSCR_CONN_S_ACCEPTED) |
				  S(SUBSCR_CONN_S_RELEASING),
		.action = subscr_conn_fsm_new,
	},
	[SUBSCR_CONN_S_ACCEPTED] = {
		.name = OSMO_STRINGIFY(SUBSCR_CONN_S_ACCEPTED),
		.in_event_mask = S(SUB_CON_E_MO_CLOSE) |
				 S(SUB_CON_E_CN_CLOSE) |
				 S(SUB_CON_E_CLOSE_CONF),
		.out_state_mask = S(SUBSCR_CONN_S_RELEASING),
		.action = subscr_conn_fsm_accepted,
	},
	[SUBSCR_CONN_S_RELEASING] = {
		.name = OSMO_STRINGIFY(SUBSCR_CONN_S_RELEASING),
		.out_state_mask = S(SUBSCR_CONN_S_RELEASED),
		.action = subscr_conn_fsm_releasing,
	},
	[SUBSCR_CONN_S_RELEASED] = {
		.name = OSMO_STRINGIFY(SUBSCR_CONN_S_RELEASED),
	},
};

static struct osmo_fsm subscr_conn_fsm = {
	.name = "Subscr_Conn",
	.states = subscr_conn_fsm_states,
	.num_states = ARRAY_SIZE(subscr_conn_fsm_states),
	.allstate_event_mask = 0,
	.allstate_action = NULL,
	.log_subsys = DVLR,
	.event_names = subscr_conn_fsm_event_names,
};

int msc_create_conn_fsm(struct gsm_subscriber_connection *conn, const char *id)
{	
	struct osmo_fsm_inst *fi;
	OSMO_ASSERT(conn);

	if (conn->master_fsm) {
		LOGP(DMM, LOGL_ERROR,
		     "%s: Error: connection already in use\n", id);
		return -EINVAL;
	}

	fi = osmo_fsm_inst_alloc(&subscr_conn_fsm, conn, conn, LOGL_DEBUG, id);

	if (!fi) {
		LOGP(DMM, LOGL_ERROR,
		     "%s: Failed to allocate subscr conn master FSM\n", id);
		return -ENOMEM;
	}
	conn->master_fsm = fi;
	return 0;
}

bool msc_subscr_conn_is_accepted(struct gsm_subscriber_connection *conn)
{

	return false;
}

void msc_subscr_conn_init(void)
{
	osmo_fsm_register(&subscr_conn_fsm);
}
