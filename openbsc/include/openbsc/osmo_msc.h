/* Routines for the MSC handling */

#ifndef OSMO_MSC_H
#define OSMO_MSC_H

#include <osmocom/core/fsm.h>

#include <openbsc/gsm_data.h>

#include "bsc_api.h"

#define MSC_HLR_REMOTE_IP_DEFAULT "127.0.0.1"
#define MSC_HLR_REMOTE_PORT_DEFAULT 2222

enum subscr_conn_fsm_event {
	/* LU FSM has terminated */
	SUB_CON_E_LU_RES,
	/* Process Access Request has terminated */
	SUB_CON_E_PARQ_SUCCESS,
	SUB_CON_E_PARQ_FAILURE,
	/* MS/BTS/BSC originated close request */
	SUB_CON_E_MO_CLOSE,
	/* MSC originated close request, primarily originates from
	 * subscr_con_put() in case reference coult reaches 0 */
	SUB_CON_E_CN_CLOSE,
	/* BSC erports confirmation of connection close */
	SUB_CON_E_CLOSE_CONF,
};

enum subscr_conn_fsm_state {
	SUBSCR_CONN_S_NEW,
	SUBSCR_CONN_S_ACCEPTED,
	SUBSCR_CONN_S_REJECTED,
	SUBSCR_CONN_S_RELEASING,
	SUBSCR_CONN_S_RELEASED,
};

void msc_subscr_conn_init(void);

struct bsc_api *msc_bsc_api();
struct gsm_subscriber_connection *subscr_con_get(struct gsm_subscriber_connection *conn);
void subscr_con_put(struct gsm_subscriber_connection *conn);

int msc_create_conn_fsm(struct gsm_subscriber_connection *conn, const char *id);

int msc_vlr_init(void *ctx,
		 const char *gsup_server_addr_str,
		 uint16_t gsup_server_port);

void msc_release_connection(struct gsm_subscriber_connection *conn);

bool msc_subscr_conn_is_accepted(struct gsm_subscriber_connection *conn);

#endif
