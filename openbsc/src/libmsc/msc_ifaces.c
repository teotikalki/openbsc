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

static void mgcp_crcx(struct osmo_wqueue *mgcpa, uint16_t rtp_idx)
{
	struct msgb *msg = msgb_alloc_headroom(1024, 128, "MGCP Tx");

	static char compose[1024];
	snprintf(compose, sizeof(compose),
		 "CRCX 1234 %u@mgw MGCP 1.0\r\n"
		 "C: 23\r\n"
		 "L: p:20, a:AMR, nt:IN\r\n"
		 "M: recvonly\r\n"
		 , rtp_idx);


	char *dst = (char*)msgb_put(msg, strlen(compose));
	memcpy(dst, compose, strlen(compose));
	msg->l2h = msg->data;
	DEBUGP(DMGCP, "mgcp_crcx msgb_l2len=%u\n", msgb_l2len(msg));

	mgcp_forward(mgcpa, msg);
}


static int conn_iu_rab_act_cs(struct gsm_subscriber_connection *conn)
{
	struct ue_conn_ctx *uectx = conn->iu.ue_ctx;
	struct osmo_wqueue *mgcpa = conn->network->hack.mgcp_agent;

	/* DEV HACK */
	uint16_t rtp_idx = 1;
	uint32_t rtp_ip = 0xc0a80084; // 192.168.0.132
	uint16_t rtp_port = 4000 + 2*rtp_idx;
	OSMO_ASSERT(mgcpa);
	mgcp_crcx(mgcpa, rtp_idx);

	/* HACK. where to scope the RAB Id, the conn? the subscriber? the
	 * ue_conn_ctx? */
	static uint8_t next_rab_id = 1;
	conn->iu.rab_id = next_rab_id ++;

	return iu_rab_act_cs(uectx, conn->iu.rab_id, rtp_ip, rtp_port, 0);
	/* use_x213_nsap == 0 for ip.access nano3G */
}
#endif

int msc_call_assignment(struct gsm_subscriber_connection *conn)
{
	switch (conn->via_iface) {
	case IFACE_A:
		LOGP(DMSC, LOGL_ERROR,
		     "msc_call_assignment(): A-interface BSSMAP Assignment"
		     " Request not yet implemented\n");
		return -ENOTSUP;

	case IFACE_IU:
#ifdef BUILD_IU
		return conn_iu_rab_act_cs(conn);
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
