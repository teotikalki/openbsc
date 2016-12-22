#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/application.h>
#include <osmocom/gsm/protocol/gsm_04_11.h>
#include <openbsc/gsm_data.h>
#include <openbsc/osmo_msc.h>
#include <openbsc/vlr.h>
#include <openbsc/gsup_client.h>
#include <openbsc/debug.h>

#define btw(fmt, args...) fprintf(stderr, "- " fmt "\n", ## args )
#define comment_start() fprintf(stderr, "===== %s\n", __func__);
#define comment_end() fprintf(stderr, "===== %s: SUCCESS\n\n", __func__);

struct gsm_network *net = NULL;
extern struct vlr_instance *g_vlr;

struct gsm_bts *the_bts;

struct msgb *gsup_tx_expected = NULL;
bool gsup_tx_confirmed;

struct msgb *msgb_from_hex(const char *label, uint16_t size, const char *hex)
{
	struct msgb *msg = msgb_alloc(size, label);
	unsigned char *rc;
	msg->l2h = msg->head;
	rc = msgb_put(msg, osmo_hexparse(hex, msg->head, msgb_tailroom(msg)));
	OSMO_ASSERT(rc == msg->l2h);
	return msg;
}

void gsup_expect_tx(const char *hex)
{
	talloc_free(gsup_tx_expected);
	gsup_tx_expected = NULL;
	if (!hex)
		return;
	gsup_tx_expected = msgb_from_hex("gsup_tx_expected", 1024, hex);
	gsup_tx_confirmed = false;
}

int vlr_gsupc_read_cb(struct gsup_client *gsupc, struct msgb *msg);

void gsup_rx(const char *label, const char *rx_hex, const char *expect_tx_hex)
{
	int rc;
	struct msgb *msg;

	gsup_expect_tx(expect_tx_hex);

	msg = msgb_from_hex(label, 1024, rx_hex);
	fprintf(stderr, "<-- GSUP rx %s: %s\n", label,
		osmo_hexdump_nospc(msgb_l2(msg), msgb_l2len(msg)));
	rc = vlr_gsupc_read_cb(g_vlr->gsup_client, msg);
	fprintf(stderr, "<-- GSUP rx %s: vlr_gsupc_read_cb() returns %d\n",
		label, rc);
	OSMO_ASSERT(gsup_tx_confirmed);
	talloc_free(msg);
}

#define EXPECT_ACCEPTED(accepted) do { \
		OSMO_ASSERT(msc_subscr_conn_is_accepted(conn) == accepted); \
		fprintf(stderr, "msc_subscr_conn_is_accepted() == " #accepted "\n"); \
	} while (false)

struct gsm_subscriber_connection *conn_new(void)
{
	struct gsm_subscriber_connection *conn;
	conn = msc_subscr_con_allocate(net);
	conn->bts = the_bts;
	subscr_con_get(conn);
	return conn;
}

void conn_free(struct gsm_subscriber_connection *conn)
{
	subscr_con_put(conn);
	msc_subscr_con_free(conn);
}

int mm_rx_loc_upd_req(struct gsm_subscriber_connection *conn, struct msgb *msg);
int gsm48_rx_mm_serv_req(struct gsm_subscriber_connection *conn, struct msgb *msg);

void fake_rx_lu_req(struct gsm_subscriber_connection *conn,
		    bool authentication_required)
{
	struct msgb *msg;

	msg = msgb_from_hex("LU Req", 1024,
	       "050802008168000130089910070000006402");
	msg->l3h = msg->l2h = msg->l1h = msg->data;
	OSMO_ASSERT( mm_rx_loc_upd_req(conn, msg) == 0 );
	OSMO_ASSERT(conn->conn_fsm);
	OSMO_ASSERT(conn->subscr);
	OSMO_ASSERT(conn->subscr->vsub);
	talloc_free(msg);
}

void fake_rx_cm_service_req(struct gsm_subscriber_connection *conn,
			    bool authentication_required)
{
	struct msgb *msg;

	msg = msgb_from_hex("CM Service Req", 1024,
			    "05247803305886089910070000006402");
	msg->l3h = msg->l2h = msg->l1h = msg->data;
	OSMO_ASSERT( gsm48_rx_mm_serv_req(conn, msg) == 0 );
	OSMO_ASSERT(conn->conn_fsm);
	OSMO_ASSERT(conn->subscr);
	OSMO_ASSERT(conn->subscr->vsub);
	talloc_free(msg);
}

int fake_rx(struct gsm_subscriber_connection *conn,
	    uint8_t pdisc, uint8_t msg_type)
{
	int rc;
	struct msgb *msg;
	struct gsm48_hdr *gh;

	btw("fake rx 04.08: pdisc=%u msg_type=%u", pdisc, msg_type);

	msg = msgb_alloc(1024, "fake_rx");
	msg->l1h = msg->l2h = msg->l3h = msg->data;

	gh = (struct gsm48_hdr*)msgb_put(msg, sizeof(*gh));

	gh->proto_discr = pdisc;
	gh->msg_type = msg_type;

	/* some data, whatever */
	msgb_put(msg, 123);
	rc = gsm0408_dispatch(conn, msg);

	btw("fake rx 04.08: rc=%d", rc);

	talloc_free(msg);
	return rc;
}

void thwart_rx_non_initial_requests(struct gsm_subscriber_connection *conn)
{
	OSMO_ASSERT(fake_rx(conn, GSM48_PDISC_CC, GSM48_MT_CC_SETUP) == -EACCES);
	OSMO_ASSERT(fake_rx(conn, GSM48_PDISC_MM, GSM48_MT_MM_TMSI_REALL_COMPL) == -EACCES);
	OSMO_ASSERT(fake_rx(conn, GSM48_PDISC_RR, GSM48_MT_RR_PAG_RESP) == -EACCES);
	OSMO_ASSERT(fake_rx(conn, GSM48_PDISC_SMS, GSM411_MT_CP_DATA) == -EACCES);
}

void test_early_stage()
{
	comment_start();

	struct gsm_subscriber_connection *conn = NULL;
	
	btw("NULL conn");
	EXPECT_ACCEPTED(false);

	btw("freshly allocated conn");
	conn = msc_subscr_con_allocate(net);
	conn->bts = the_bts;
	EXPECT_ACCEPTED(false);

	btw("no conn_fsm present");
	subscr_con_get(conn);
	EXPECT_ACCEPTED(false);

	btw("conn_fsm present, in new state");
	OSMO_ASSERT(msc_create_conn_fsm(conn, "test") == 0);
	OSMO_ASSERT(conn->conn_fsm);
	OSMO_ASSERT(conn->conn_fsm->state == SUBSCR_CONN_S_NEW);
	EXPECT_ACCEPTED(false);

	btw("requests shall be thwarted");
	thwart_rx_non_initial_requests(conn);

	btw("fake: acceptance");
	conn->subscr = subscr_alloc();
	OSMO_ASSERT(conn->subscr);
	osmo_fsm_inst_state_chg(conn->conn_fsm, SUBSCR_CONN_S_ACCEPTED, 0, 0);
	EXPECT_ACCEPTED(true);

	btw("subscr_con_put() implicitly deallocates conn and all FSMs");
	subscr_con_put(conn);
	OSMO_ASSERT(llist_empty(&net->subscr_conns));

	btw("new conn, accepted");
	conn = conn_new();
	conn->subscr = subscr_alloc();
	OSMO_ASSERT(conn->subscr);
	OSMO_ASSERT(msc_create_conn_fsm(conn, "test") == 0);
	osmo_fsm_inst_state_chg(conn->conn_fsm, SUBSCR_CONN_S_ACCEPTED, 0, 0);
	EXPECT_ACCEPTED(true);

	btw("close event also implicitly deallocates conn");
	osmo_fsm_inst_dispatch(conn->conn_fsm, SUBSCR_CONN_E_CN_CLOSE, NULL);
	OSMO_ASSERT(llist_empty(&net->subscr_conns));

	comment_end();
}

void test_no_authen()
{
	comment_start();

	btw("new conn");
	struct gsm_subscriber_connection *conn = conn_new();

	btw("Location Update request causes a GSUP LU request to HLR");
	gsup_expect_tx("04010809710000004026f0");
	fake_rx_lu_req(conn, false);
	OSMO_ASSERT(gsup_tx_confirmed);

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("_INSERT_DATA_RESULT",
		"10010809710000004026f00804036470f1",
		"12010809710000004026f0");

	btw("having received subscriber data does not mean acceptance");
	EXPECT_ACCEPTED(false);

	btw("requests shall be thwarted");
	thwart_rx_non_initial_requests(conn);

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	gsup_rx("_UPDATE_LOCATION_RESULT", "06010809710000004026f0", NULL);

	btw("now the conn is accepted");
	EXPECT_ACCEPTED(true);

	btw("some time passes, the conn is discarded");
	conn_free(conn);

	btw("after a while, a new conn...");
	conn = conn_new();
	EXPECT_ACCEPTED(false);

	btw("...sends a CM Service Request");
	fake_rx_cm_service_req(conn, false);
	EXPECT_ACCEPTED(true);

	btw("conn is released");
	conn_free(conn);
	comment_end();
}

void test_cm_service_without_lu()
{
	comment_start();

	struct gsm_subscriber_connection *conn = conn_new();

	/* Having received subscriber data is not sufficient. */
	EXPECT_ACCEPTED(false);

	conn_free(conn);
	comment_end();
}

static struct log_info_cat test_categories[] = {
	[DRLL] = {
		.name = "DRLL",
		.description = "A-bis Radio Link Layer (RLL)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DMM] = {
		.name = "DMM",
		.description = "Layer3 Mobility Management (MM)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DCC] = {
		.name = "DCC",
		.description = "Layer3 Call Control (CC)",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMM] = {
		.name = "DMM",
		.description = "Layer3 Mobility Management (MM)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DVLR] = {
		.name = "DVLR",
		.description = "Visitor Location Register",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static struct log_info info = {
	.cat = test_categories,
	.num_cat = ARRAY_SIZE(test_categories),
};

extern void *tall_bsc_ctx;

int fake_mncc_recv(struct gsm_network *net, struct msgb *msg)
{
	fprintf(stderr, "rx MNCC\n");
	return 0;
}

/* override, requires '-Wl,--wrap=gsup_client_create' */
struct gsup_client *
__real_gsup_client_create(const char *ip_addr, unsigned int tcp_port,
			  gsup_client_read_cb_t read_cb,
			  struct oap_client_config *oap_config);
struct gsup_client *
__wrap_gsup_client_create(const char *ip_addr, unsigned int tcp_port,
			  gsup_client_read_cb_t read_cb,
			  struct oap_client_config *oap_config)
{
	struct gsup_client *gsupc;
	gsupc = talloc_zero(tall_bsc_ctx, struct gsup_client);
	OSMO_ASSERT(gsupc);
	return gsupc;
}

/* override, requires '-Wl,--wrap=gsup_client_send' */
int __real_gsup_client_send(struct gsup_client *gsupc, struct msgb *msg);
int __wrap_gsup_client_send(struct gsup_client *gsupc, struct msgb *msg)
{
	fprintf(stderr, "--> GSUP tx: %s\n",
	       osmo_hexdump_nospc(msg->data, msg->len));

	OSMO_ASSERT(gsup_tx_expected);
	if (msg->len != gsup_tx_expected->len
	    || memcmp(msg->data, gsup_tx_expected->data, msg->len)) {
		fprintf(stderr, "Mismatch! Expected:\n%s\n",
		       osmo_hexdump_nospc(gsup_tx_expected->data,
					  gsup_tx_expected->len));
		abort();
	}

	talloc_free(msg);
	gsup_tx_confirmed = true;
	return 0;
}

/* override, requires '-Wl,--wrap=gsm0808_submit_dtap' */
int __real_gsm0808_submit_dtap(struct gsm_subscriber_connection *conn,
			       struct msgb *msg, int link_id, int allow_sacch);
int __wrap_gsm0808_submit_dtap(struct gsm_subscriber_connection *conn,
			       struct msgb *msg, int link_id, int allow_sacch)
{
	fprintf(stderr, "tx DTAP to MS: %s\n",
		osmo_hexdump_nospc(msg->data, msg->len));
	talloc_free(msg);
	return 0;
}

static int fake_vlr_tx_lu_acc(void *msc_conn_ref)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	fprintf(stderr, "LU Accept for %s\n", subscr_name(conn->subscr));
	return 0;
}


int main(void)
{
	void *msgb_ctx;
	tall_bsc_ctx = talloc_named_const(NULL, 0, "subscr_conn_test_ctx");
	msgb_ctx = msgb_talloc_ctx_init(tall_bsc_ctx, 0);
	osmo_init_logging(&info);

	OSMO_ASSERT(osmo_stderr_target);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_timestamp(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);

	net = gsm_network_init(tall_bsc_ctx, 1, 1, fake_mncc_recv);
	the_bts = gsm_bts_alloc(net);

	bsc_api_init(net, msc_bsc_api());

	osmo_fsm_log_addr(false);
	OSMO_ASSERT(msc_vlr_init(tall_bsc_ctx, "none", 0) == 0);
	OSMO_ASSERT(g_vlr);
	OSMO_ASSERT(g_vlr->gsup_client);
	msc_subscr_conn_init();

	g_vlr->ops.tx_lu_acc = fake_vlr_tx_lu_acc;

	test_early_stage();
	test_no_authen();

	printf("Done\n");

	gsup_expect_tx(NULL);
	talloc_free(the_bts);

	talloc_report_full(msgb_ctx, stderr);
	fprintf(stderr, "talloc_total_blocks(tall_bsc_ctx) == %zu\n",
		talloc_total_blocks(tall_bsc_ctx));
	if (talloc_total_blocks(tall_bsc_ctx) != 9)
		talloc_report_full(tall_bsc_ctx, stderr);
	return 0;
}
