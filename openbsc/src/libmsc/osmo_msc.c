/* main MSC management code... */

/*
 * (C) 2010,2013 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
 *
 * All Rights Reserved
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

#include <openbsc/bsc_api.h>
#include <openbsc/debug.h>
#include <openbsc/transaction.h>
#include <openbsc/db.h>
#include <openbsc/vlr.h>
#include <openbsc/osmo_msc.h>

#include <openbsc/gsm_04_11.h>

/* Receive a SAPI-N-REJECT from BSC */
static void msc_sapi_n_reject(struct gsm_subscriber_connection *conn, int dlci)
{
	int sapi = dlci & 0x7;

	if (sapi == UM_SAPI_SMS)
		gsm411_sapi_n_reject(conn);
}

/* Receive a CLEAR REQUEST from BSC */
static int msc_clear_request(struct gsm_subscriber_connection *conn, uint32_t cause)
{
	gsm0408_clear_request(conn, cause);
	return 1;
}

/* Receive a COMPLETE LAYER3 INFO from BSC */
static int msc_compl_l3(struct gsm_subscriber_connection *conn, struct msgb *msg,
			uint16_t chosen_channel)
{
	gsm0408_new_conn(conn);
	gsm0408_dispatch(conn, msg);

	/*
	 * If this is a silent call we want the channel to remain open as long as
	 * possible and this is why we accept this connection regardless of any
	 * pending transaction or ongoing operation.
	 */
	if (conn->silent_call)
		return BSC_API_CONN_POL_ACCEPT;
	if (conn->sec_operation || conn->anch_operation)
		return BSC_API_CONN_POL_ACCEPT;
	if (trans_has_conn(conn))
		return BSC_API_CONN_POL_ACCEPT;

	LOGP(DRR, LOGL_INFO, "MSC Complete L3: Rejecting connection.\n");
	return BSC_API_CONN_POL_REJECT;
}

/* Receive a DTAP message from BSC */
static void msc_dtap(struct gsm_subscriber_connection *conn, uint8_t link_id, struct msgb *msg)
{
	gsm0408_dispatch(conn, msg);
}

/* Receive an ASSIGNMENT COMPLETE from BSC */
static void msc_assign_compl(struct gsm_subscriber_connection *conn,
			     uint8_t rr_cause, uint8_t chosen_channel,
			     uint8_t encr_alg_id, uint8_t speec)
{
	LOGP(DRR, LOGL_DEBUG, "MSC assign complete (do nothing).\n");
}

/* Receive an ASSIGNMENT FAILURE from BSC */
static void msc_assign_fail(struct gsm_subscriber_connection *conn,
			    uint8_t cause, uint8_t *rr_cause)
{
	LOGP(DRR, LOGL_DEBUG, "MSC assign failure (do nothing).\n");
}

/* Receive a CLASSMARK CHNAGE from BSC */
static void msc_classmark_chg(struct gsm_subscriber_connection *conn,
			      const uint8_t *cm2, uint8_t cm2_len,
			      const uint8_t *cm3, uint8_t cm3_len)
{
	struct gsm_subscriber *subscr = conn->subscr;

	if (subscr) {
		subscr->equipment.classmark2_len = cm2_len;
		memcpy(subscr->equipment.classmark2, cm2, cm2_len);
		if (cm3) {
			subscr->equipment.classmark3_len = cm3_len;
			memcpy(subscr->equipment.classmark3, cm3, cm3_len);
		}
		db_sync_equipment(&subscr->equipment);
	}
}

/* Receive a CIPHERING MODE COMPLETE from BSC */
static void msc_ciph_m_compl(struct gsm_subscriber_connection *conn,
			     struct msgb *msg, uint8_t alg_id)
{
	gsm_cbfn *cb;

	DEBUGP(DRR, "CIPHERING MODE COMPLETE\n");

	/* Safety check */
	if (!conn->sec_operation) {
		DEBUGP(DRR, "No authentication/cipher operation in progress !!!\n");
		return;
	}

	/* FIXME: check for MI (if any) */

	/* Call back whatever was in progress (if anything) ... */
	cb = conn->sec_operation->cb;
	if (cb) {
		cb(GSM_HOOK_RR_SECURITY, GSM_SECURITY_SUCCEEDED,
			NULL, conn, conn->sec_operation->cb_data);

	}

	/* Complete the operation */
	release_security_operation(conn);
}


/* MSC-level operations to be called by libbsc in NITB */
static struct bsc_api msc_handler = {
	.sapi_n_reject = msc_sapi_n_reject,
	.compl_l3 = msc_compl_l3,
	.dtap = msc_dtap,
	.clear_request = msc_clear_request,
	.assign_compl = msc_assign_compl,
	.assign_fail = msc_assign_fail,
	.classmark_chg = msc_classmark_chg,
	.cipher_mode_compl = msc_ciph_m_compl,
};

struct bsc_api *msc_bsc_api() {
	return &msc_handler;
}

/* lchan release handling */
void msc_release_connection(struct gsm_subscriber_connection *conn)
{
	/* skip when we are in release, e.g. due an error */
	if (conn->in_release)
		return;

	if (conn->silent_call)
		LOGP(DMSC, LOGL_ERROR, "release_connection() but silent_call active?!?\n");

	/* check if there is a pending operation */
	if (conn->sec_operation || conn->anch_operation)
		LOGP(DMSC, LOGL_ERROR, "relase_connection() but {loc,sec,anch}_operation alive?!?\n");

	if (trans_has_conn(conn))
		LOGP(DMSC, LOGL_ERROR, "release_conncetion() but transactions alive?!?\n");

	/* no more connections, asking to release the channel */

	/*
	 * We had stopped the LU expire timer T3212. Now we are about
	 * to send the MS back to the idle state and this should lead
	 * to restarting the timer. Set the new expiration time.
	 */
	if (conn->expire_timer_stopped)
		subscr_update_expire_lu(conn->subscr, conn->bts);

	conn->in_release = 1;

	/* Let VLR know that a given subscriber is gone */
	if (conn->subscr)
		vlr_sub_disconnected(conn->subscr->vsub);

	gsm0808_clear(conn);
	/* TODO: is there anything to wait for? */
	osmo_fsm_inst_dispatch(conn->master_fsm, SUB_CON_E_CLOSE_CONF, NULL);
}

/* increment the ref-count. Needs to be called by every user */
struct gsm_subscriber_connection *subscr_con_get(struct gsm_subscriber_connection *conn)
{
	OSMO_ASSERT(conn);

	if (conn->in_release)
		return NULL;

	conn->use_count++;
	DEBUGP(DMSC, "increased subscr_con use_count to %u\n", conn->use_count);

	return conn;
}

/* decrement the ref-count. Once it reaches zero, we release */
void subscr_con_put(struct gsm_subscriber_connection *conn)
{
	OSMO_ASSERT(conn);

	if (conn->use_count == 0) {
		LOGP(DMSC, LOGL_ERROR, "tryin to decrement conn use count, but is alrady 0\n");
		return;
	}

	conn->use_count--;
	DEBUGP(DMSC, "decreased subscr_con use_count to %u\n", conn->use_count);

	if (conn->use_count == 0)
		osmo_fsm_inst_dispatch(conn->master_fsm, SUB_CON_E_MO_CLOSE, NULL);
}
