/* Routines for the MSC handling */

#ifndef OSMO_MSC_H
#define OSMO_MSC_H

#include <osmocom/core/fsm.h>

#include <openbsc/gsm_data.h>

#include "bsc_api.h"

#define MSC_HLR_REMOTE_IP_DEFAULT "127.0.0.1"
#define MSC_HLR_REMOTE_PORT_DEFAULT 2222

enum subscr_conn_fsm_event {
	/* Mark 0 as invalid to catch uninitialized vars */
	SUBSCR_CONN_E_INVALID = 0,
	/* LU or Process Access FSM has determined that this conn is good */
	SUBSCR_CONN_E_ACCEPTED,
	/* Some async action has completed, check again whether all is done */
	SUBSCR_CONN_E_BUMP,
	/* MS/BTS/BSC originated close request */
	SUBSCR_CONN_E_MO_CLOSE,
	/* MSC originated close request, e.g. failed authentication */
	SUBSCR_CONN_E_CN_CLOSE,
	/* BSC reports confirmation of connection close */
	SUBSCR_CONN_E_CLOSE_CONF,
};

enum subscr_conn_fsm_state {
	SUBSCR_CONN_S_NEW,
	SUBSCR_CONN_S_ACCEPTED,
	SUBSCR_CONN_S_RELEASED,
};

void msc_subscr_conn_init(void);

struct bsc_api *msc_bsc_api();
#define subscr_con_get(conn) _subscr_con_get(conn, __BASE_FILE__, __LINE__)
struct gsm_subscriber_connection *
_subscr_con_get(struct gsm_subscriber_connection *conn,
		const char *file, int line);
#define subscr_con_put(conn) _subscr_con_put(conn, __BASE_FILE__, __LINE__)
void _subscr_con_put(struct gsm_subscriber_connection *conn, const char *file,
		     int line);

int msc_create_conn_fsm(struct gsm_subscriber_connection *conn, const char *id);

int msc_vlr_init(struct gsm_network *net,
		 const char *gsup_server_addr_str,
		 uint16_t gsup_server_port);

void msc_release_connection(struct gsm_subscriber_connection *conn);

bool msc_subscr_conn_is_accepted(struct gsm_subscriber_connection *conn);

void msc_release_anchor(struct gsm_subscriber_connection *conn);

#endif
