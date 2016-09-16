/* Implementation for MSC decisions which interface to send messages out on. */

/* (C) 2016 by sysmocom s.m.f.c GmbH <info@sysmocom.de>
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
 */

#include <osmocom/core/logging.h>
#include <osmocom/core/write_queue.h>

#include <osmocom/ranap/ranap_msg_factory.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/msc_ifaces.h>
#include <openbsc/iu.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/transaction.h>

#include "../../bscconfig.h"

static int msc_tx(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	switch (conn->via_iface) {
	case IFACE_A:
		msg->dst = conn;
		return a_tx(msg);

	case IFACE_IU:
		msg->dst = conn->iu.ue_ctx;
		return iu_tx(msg, 0);

	default:
		LOGP(DMSC, LOGL_ERROR,
		     "msc_tx(): conn->via_iface invalid (%d)\n",
		     conn->via_iface);
		return -1;
	}
}


int msc_tx_dtap(struct gsm_subscriber_connection *conn,
		struct msgb *msg)
{
	return msc_tx(conn, msg);
}


/* 9.2.5 CM service accept */
int msc_gsm48_tx_mm_serv_ack(struct gsm_subscriber_connection *conn)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 SERV ACC");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_CM_SERV_ACC;

	DEBUGP(DMM, "-> CM SERVICE ACCEPT\n");

	return msc_tx_dtap(conn, msg);
}

/* 9.2.6 CM service reject */
int msc_gsm48_tx_mm_serv_rej(struct gsm_subscriber_connection *conn,
			     enum gsm48_reject_value value)
{
	struct msgb *msg;

	msg = gsm48_create_mm_serv_rej(value);
	if (!msg) {
		LOGP(DMM, LOGL_ERROR, "Failed to allocate CM Service Reject.\n");
		return -1;
	}

	DEBUGP(DMM, "-> CM SERVICE Reject cause: %d\n", value);

	return msc_tx_dtap(conn, msg);
}

#ifdef BUILD_IU
int msc_tx_iu_common_id(struct gsm_subscriber_connection *conn)
{
	if (conn->via_iface != IFACE_IU)
		return 0;

	return iu_tx_common_id(conn->iu.ue_ctx, conn->subscr->imsi);
}

static int iu_rab_act_cs(struct ue_conn_ctx *uectx, uint8_t rab_id,
			 uint32_t rtp_ip, uint16_t rtp_port,
			 bool use_x213_nsap)
{
	struct msgb *msg;

	LOGP(DIUCS, LOGL_DEBUG, "Assigning RAB: rab_id=%d, rtp=%x:%u,"
	     " use_x213_nsap=%d\n", rab_id, rtp_ip, rtp_port, use_x213_nsap);

	msg = ranap_new_msg_rab_assign_voice(rab_id, rtp_ip, rtp_port,
					     use_x213_nsap);
	msg->l2h = msg->data;

	return iu_rab_act(uectx, msg);
}

static void mgcp_forward(struct osmo_wqueue *mgcpa, struct msgb *msg)
{
	if (msgb_l2len(msg) > 4096) {
		LOGP(DMGCP, LOGL_ERROR, "Can not forward too big message.\n");
		msgb_free(msg);
		return;
	}

	if (osmo_wqueue_enqueue(mgcpa, msg) != 0) {
		LOGP(DMGCP, LOGL_FATAL, "Could not queue message to MGCP GW.\n");
		msgb_free(msg);
	}
	else
		LOGP(DMGCP, LOGL_INFO, "Queued %u\n",
		     msgb_l2len(msg));
}

static unsigned int mgcp_next_trans_id = 423;
static uint16_t mgcp_next_endpoint = 3;

static void mgcp_crcx(struct osmo_wqueue *mgcpa, uint16_t rtp_endpoint,
		      unsigned int call_id)
{
	struct msgb *msg = msgb_alloc_headroom(1024, 128, "MGCP Tx");

	static char compose[1024];
	snprintf(compose, sizeof(compose),
		 "CRCX %u %u@mgw MGCP 1.0\r\n"
		 "C: %u\r\n"
		 "L: p:20, a:AMR, nt:IN\r\n"
		 "M: recvonly\r\n"
		 ,
		 mgcp_next_trans_id ++,
		 rtp_endpoint,
		 call_id);


	char *dst = (char*)msgb_put(msg, strlen(compose));
	memcpy(dst, compose, strlen(compose));
	msg->l2h = msg->data;
	DEBUGP(DMGCP, "mgcp_crcx msgb_l2len=%u\n", msgb_l2len(msg));

	mgcp_forward(mgcpa, msg);
}

static void mgcp_mdcx(struct osmo_wqueue *mgcpa, uint16_t rtp_endpoint,
		      const char *rtp_conn_addr, uint16_t rtp_port)
{
	struct msgb *msg = msgb_alloc_headroom(1024, 128, "MGCP Tx");
	static unsigned int mgcp_next_trans_id = 423;

	static char compose[1024];
	snprintf(compose, sizeof(compose),
		 "MDCX %u %u@mgw MGCP 1.0\r\n"
		 "Z: noasnwer\r\n"
		 "c=IN IP4 1 %s\r\n"
		 "m=audio %u RTP/AVP 255\r\n"
		 ,
		 mgcp_next_trans_id ++,
		 rtp_endpoint,
		 rtp_conn_addr,
		 rtp_port);


	char *dst = (char*)msgb_put(msg, strlen(compose));
	memcpy(dst, compose, strlen(compose));
	msg->l2h = msg->data;
	DEBUGP(DMGCP, "mgcp_mdcx msgb_l2len=%u\n", msgb_l2len(msg));

	mgcp_forward(mgcpa, msg);
}


static int conn_iu_rab_act_cs(struct gsm_trans *trans)
{
	struct gsm_subscriber_connection *conn = trans->conn;
	struct ue_conn_ctx *uectx = conn->iu.ue_ctx;
	struct osmo_wqueue *mgcpa = conn->network->hack.mgcp_agent;
	OSMO_ASSERT(mgcpa);

	/* DEV HACK. Where to scope the rtp endpoint? At the conn / subscriber
	 * / ue_conn_ctx? */
	conn->iu.mgcp_rtp_endpoint = mgcp_next_endpoint ++;
	conn->iu.mgcp_rtp_port_ue = 4000 + 2 * conn->iu.mgcp_rtp_endpoint;
	conn->iu.mgcp_rtp_port_cn = 16000 + 2 * conn->iu.mgcp_rtp_endpoint;

	uint32_t rtp_ip = 0xc0a80084; // 192.168.0.132
	//uint32_t rtp_ip = 0x0a090178; // 10.9.1.120
	mgcp_crcx(mgcpa, conn->iu.mgcp_rtp_endpoint, trans->callref);

	/* HACK. where to scope the RAB Id? At the conn / subscriber /
	 * ue_conn_ctx? */
	static uint8_t next_rab_id = 1;
	conn->iu.rab_id = next_rab_id ++;

	return iu_rab_act_cs(uectx, conn->iu.rab_id, rtp_ip, conn->iu.mgcp_rtp_port_ue, 1);
	/* use_x213_nsap == 0 for ip.access nano3G */
}
#endif

int msc_call_assignment(struct gsm_trans *trans)
{
	struct gsm_subscriber_connection *conn = trans->conn;

	switch (conn->via_iface) {
	case IFACE_A:
		LOGP(DMSC, LOGL_ERROR,
		     "msc_call_assignment(): A-interface BSSMAP Assignment"
		     " Request not yet implemented\n");
		return -ENOTSUP;

	case IFACE_IU:
#ifdef BUILD_IU
		return conn_iu_rab_act_cs(trans);
#else
		LOGP(DMSC, LOGL_ERROR,
		     "msc_call_assignment(): IuCS RAB Activation not supported"
		     " in this build\n");
		return -ENOTSUP;
#endif

	default:
		LOGP(DMSC, LOGL_ERROR,
		     "msc_tx(): conn->via_iface invalid (%d)\n",
		     conn->via_iface);
		return -1;
	}
}

int msc_call_bridge(struct gsm_trans *trans1, struct gsm_trans *trans2)
{
	struct gsm_subscriber_connection *conn1 = trans1->conn;
	struct gsm_subscriber_connection *conn2 = trans2->conn;

	struct osmo_wqueue *mgcpa = conn1->network->hack.mgcp_agent;
	OSMO_ASSERT(mgcpa);

	const char *ip = "192.168.0.132";

	mgcp_mdcx(mgcpa, conn1->iu.mgcp_rtp_endpoint,
		  ip, conn2->iu.mgcp_rtp_port_cn);
	mgcp_mdcx(mgcpa, conn2->iu.mgcp_rtp_endpoint,
		  ip, conn1->iu.mgcp_rtp_port_cn);

	return 0;
}
