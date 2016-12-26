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

#if 1
/* show lines in test comments? Helpful for debugging. */
#define btw(fmt, args...) fprintf(stderr, "- %3d: " fmt "\n", __LINE__, ## args )
#else
#define btw(fmt, args...) fprintf(stderr, "- " fmt "\n", ## args )
#endif

#define comment_start() fprintf(stderr, "===== %s\n", __func__);
#define comment_end() fprintf(stderr, "===== %s: SUCCESS\n\n", __func__);

struct gsm_network *net = NULL;

struct gsm_bts *the_bts;

struct msgb *gsup_tx_expected = NULL;
bool gsup_tx_confirmed;

struct msgb *dtap_tx_expected = NULL;
bool dtap_tx_confirmed;

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
	OSMO_ASSERT(!gsup_tx_expected);
	if (!hex)
		return;
	gsup_tx_expected = msgb_from_hex("gsup_tx_expected", 1024, hex);
	gsup_tx_confirmed = false;
}

void dtap_expect_tx(const char *hex)
{
	OSMO_ASSERT(!dtap_tx_expected);
	if (!hex)
		return;
	dtap_tx_expected = msgb_from_hex("dtap_tx_expected", 1024, hex);
	dtap_tx_confirmed = false;
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
	rc = vlr_gsupc_read_cb(net->vlr->gsup_client, msg);
	fprintf(stderr, "<-- GSUP rx %s: vlr_gsupc_read_cb() returns %d\n",
		label, rc);
	if (expect_tx_hex)
		OSMO_ASSERT(gsup_tx_confirmed);
	talloc_free(msg);
}

bool conn_exists(struct gsm_subscriber_connection *conn)
{
	struct gsm_subscriber_connection *c;
	llist_for_each_entry(c, &net->subscr_conns, entry) {
		if (c == conn)
			return true;
	}
	return false;
}

#define EXPECT_ACCEPTED(expect_accepted) do { \
		if (g_conn) { \
			OSMO_ASSERT(g_conn); \
			OSMO_ASSERT(conn_exists(g_conn)); \
		} \
		bool accepted = msc_subscr_conn_is_accepted(g_conn); \
		fprintf(stderr, "msc_subscr_conn_is_accepted() == %s\n", \
			accepted ? "true" : "false"); \
		OSMO_ASSERT(accepted == expect_accepted); \
	} while (false)

struct gsm_subscriber_connection *conn_new(void)
{
	struct gsm_subscriber_connection *conn;
	conn = msc_subscr_con_allocate(net);
	conn->bts = the_bts;
	return conn;
}

/* TODO copied from libosmo-abis/src/subchan_demux.c, remove dup */
static int llist_len(struct llist_head *head)
{
	struct llist_head *entry;
	int i = 0;

	llist_for_each(entry, head)
		i++;

	return i;
}

#define EXPECT_CONN_COUNT(N) do { \
		int l = llist_len(&net->subscr_conns); \
		fprintf(stderr, "nr of conns == %d\n", l); \
		OSMO_ASSERT(l == (N)); \
	} while (false)

struct gsm_subscriber_connection *g_conn = NULL;

void rx_from_ms(struct msgb *msg)
{
	int rc;

	struct gsm48_hdr *gh = msgb_l3(msg);
	btw("rx from MS: pdisc=0x%02x msg_type=0x%02x",
	    gh->proto_discr, gh->msg_type);

	if (!g_conn) {
		g_conn = conn_new();
		rc = net->bsc_api->compl_l3(g_conn, msg, 23);
		if (rc == BSC_API_CONN_POL_REJECT) {
			msc_subscr_con_free(g_conn);
			g_conn = NULL;
		}
	} else
		net->bsc_api->dtap(g_conn, 23, msg);

	if (g_conn && !conn_exists(g_conn))
		g_conn = NULL;
}

void ms_sends_lu_req()
{
	struct msgb *msg;

	msg = msgb_from_hex("LU Req", 1024,
	       "050802008168000130089910070000006402");
	msg->l3h = msg->l2h = msg->l1h = msg->data;
	rx_from_ms(msg);
	talloc_free(msg);
}

void ms_sends_cm_service_req()
{
	struct msgb *msg;

	msg = msgb_from_hex("CM Service Req", 1024,
			    "05247803305886089910070000006402");
	msg->l3h = msg->l2h = msg->l1h = msg->data;
	rx_from_ms(msg);
	talloc_free(msg);
}

void ms_sends_msg(const char *hex)
{
	struct msgb *msg;

	msg = msgb_from_hex("ms_sends_msg", 1024, hex);
	msg->l1h = msg->l2h = msg->l3h = msg->data;
	rx_from_ms(msg);
	talloc_free(msg);
}

int ms_sends_msg_fake(uint8_t pdisc, uint8_t msg_type)
{
	int rc;
	struct msgb *msg;
	struct gsm48_hdr *gh;

	msg = msgb_alloc(1024, "ms_sends_msg_fake");
	msg->l1h = msg->l2h = msg->l3h = msg->data;

	gh = (struct gsm48_hdr*)msgb_put(msg, sizeof(*gh));
	gh->proto_discr = pdisc;
	gh->msg_type = msg_type;
	/* some amount of data, whatever */
	msgb_put(msg, 123);

	rc = gsm0408_dispatch(g_conn, msg);

	talloc_free(msg);
	return rc;
}

void thwart_rx_non_initial_requests()
{
	btw("requests shall be thwarted");
	OSMO_ASSERT(ms_sends_msg_fake(GSM48_PDISC_CC, GSM48_MT_CC_SETUP) == -EACCES);
	OSMO_ASSERT(ms_sends_msg_fake(GSM48_PDISC_MM, GSM48_MT_MM_TMSI_REALL_COMPL) == -EACCES);
	OSMO_ASSERT(ms_sends_msg_fake(GSM48_PDISC_RR, GSM48_MT_RR_PAG_RESP) == -EACCES);
	OSMO_ASSERT(ms_sends_msg_fake(GSM48_PDISC_SMS, GSM411_MT_CP_DATA) == -EACCES);
}

void clear_vlr()
{
	struct vlr_subscriber *vsub, *n;
	llist_for_each_entry_safe(vsub, n, &net->vlr->subscribers, list) {
		vlr_sub_free(vsub);
	}
	
	EXPECT_CONN_COUNT(0);

	net->authentication_required = false;
	net->a5_encryption = VLR_CIPH_NONE;
	net->vlr->cfg.check_imei_rqd = false;
	net->vlr->cfg.alloc_tmsi = false;

}

void test_early_stage()
{
	comment_start();
	clear_vlr();

	btw("NULL conn");
	EXPECT_ACCEPTED(false);

	btw("freshly allocated conn");
	g_conn = msc_subscr_con_allocate(net);
	g_conn->bts = the_bts;
	EXPECT_ACCEPTED(false);

	btw("conn_fsm present, in state NEW");
	OSMO_ASSERT(msc_create_conn_fsm(g_conn, "test") == 0);
	OSMO_ASSERT(g_conn->conn_fsm);
	OSMO_ASSERT(g_conn->conn_fsm->state == SUBSCR_CONN_S_NEW);
	EXPECT_ACCEPTED(false);

	thwart_rx_non_initial_requests();

	btw("fake: acceptance");
	g_conn->subscr = subscr_alloc();
	OSMO_ASSERT(g_conn->subscr);
	/* mark as silent call so it sticks around */
	g_conn->silent_call = 1;
	osmo_fsm_inst_state_chg(g_conn->conn_fsm, SUBSCR_CONN_S_ACCEPTED, 0, 0);
	EXPECT_ACCEPTED(true);
	g_conn->silent_call = 0;

	btw("CLOSE event marks conn_fsm as released");
	osmo_fsm_inst_dispatch(g_conn->conn_fsm, SUBSCR_CONN_E_CN_CLOSE, NULL);
	OSMO_ASSERT(g_conn->conn_fsm->state == SUBSCR_CONN_S_RELEASED);

	btw("messaging dispatch would now remove the conn");
	msc_subscr_con_free(g_conn);
	EXPECT_CONN_COUNT(0);
	g_conn = NULL;

	comment_end();
}

void test_cm_service_without_lu()
{
	comment_start();
	clear_vlr();

	btw("CM Service Request without a prior Location Updating");
	ms_sends_cm_service_req();

	btw("conn was released");
	EXPECT_CONN_COUNT(0);

	comment_end();
}

void test_no_authen()
{
	comment_start();
	clear_vlr();

	net->authentication_required = false;
	net->a5_encryption = VLR_CIPH_NONE;
	net->vlr->cfg.check_imei_rqd = false;
	net->vlr->cfg.alloc_tmsi = false;

	btw("Location Update request causes a GSUP LU request to HLR");
	gsup_expect_tx("04010809710000004026f0");
	ms_sends_lu_req();
	OSMO_ASSERT(gsup_tx_confirmed);

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("_INSERT_DATA_REQUEST",
		"10010809710000004026f00804036470f1",
		"12010809710000004026f0");

	btw("having received subscriber data does not mean acceptance");
	EXPECT_ACCEPTED(false);

	thwart_rx_non_initial_requests();

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	gsup_rx("_UPDATE_LOCATION_RESULT", "06010809710000004026f0", NULL);

	/* HACK */
	osmo_fsm_inst_dispatch(g_conn->conn_fsm, SUBSCR_CONN_E_BUMP, NULL);

	btw("a LU Accept was sent, and the conn was discarded");
	EXPECT_CONN_COUNT(0);

	btw("after a while, a new conn sends a CM Service Request");
	ms_sends_cm_service_req();
	OSMO_ASSERT(g_conn->conn_fsm);
	OSMO_ASSERT(g_conn->subscr);
	OSMO_ASSERT(g_conn->subscr->vsub);
	EXPECT_ACCEPTED(true);

	btw("a USSD request is serviced");
	dtap_expect_tx("8b2a1c27a225020100302002013b301b04010f0416d9775d0e2ae3"
		       "e965f73cfd7683d27310cd06bbc51a0d");
	ms_sends_msg("0b3b1c15a11302010002013b300b04010f0406aa510c061b017f0100");

	btw("conn is released");
	// FIXME: should happen implicitly
	osmo_fsm_inst_dispatch(g_conn->conn_fsm, SUBSCR_CONN_E_CN_CLOSE, NULL);
	EXPECT_CONN_COUNT(0);

	btw("subscriber detaches");
	ms_sends_msg("050130089910070000006402");

	EXPECT_CONN_COUNT(0);
	comment_end();
}

void test_authen()
{
	comment_start();
	clear_vlr();

	net->authentication_required = true;

	btw("new conn");
	struct gsm_subscriber_connection *conn = conn_new();

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_lu_req();
	OSMO_ASSERT(gsup_tx_confirmed);

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
	gsup_rx("OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT",
		"0a"
		/* imsi */
		"0108" "09710000004026f0"
		/* 5 auth vectors... */
		/* TL    TL     rand */
		"0322"  "2010" "585df1ae287f6e273dce07090d61320b"
		/*       TL     sres       TL     kc */
			"2104" "2d8b2c3e" "2208" "61855fb81fc2a800"
		"0322"  "2010" "12aca96fb4ffdea5c985cbafa9b6e18b"
			"2104" "20bde240" "2208" "07fa7502e07e1c00"
		"0322"  "2010" "e7c03ba7cf0e2fde82b2dc4d63077d42"
			"2104" "a29514ae" "2208" "e2b234f807886400"
		"0322"  "2010" "fa8f20b781b5881329d4fea26b1a3c51"
			"2104" "5afc8d72" "2208" "2392f14f709ae000"
		"0322"  "2010" "0fd4cc8dbe8715d1f439e304edfd68dc"
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000",
		NULL);

#if 0
	handled in bsc_api.c and never reaches the MSC
	btw("MS may send a Classmark Change");
	ms_sends_msg("061603305886200b6014042f6513b8800d2100");
#endif

#if 0
	//makes me think: should this ever reach the MSC?
	//we're certainly not doing anything with it.
	btw("MS may send a UTRAN Classmark Change");
	ms_sends_msg("06604a40000350caab541a955aa22920c11200060005628425"
		    "1cfba267aed97284a39f744cf5db2f509473ee899ebb65872d0101c4"
		    "109c38f5d0d133d76cb4006407406f5293492d691006c6c0");
#endif

	btw("If the HLR were to send a GSUP _UPDATE_LOCATION_RESULT we'd still reject");
	gsup_rx("_UPDATE_LOCATION_RESULT", "06010809710000004026f0", NULL);
	EXPECT_ACCEPTED(false);

	thwart_rx_non_initial_requests();

	btw("MS sends Authen Response, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0");
	ms_sends_msg("05542d8b2c3e");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("_INSERT_DATA_REQUEST",
		"10010809710000004026f00804036470f1",
		"12010809710000004026f0");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	gsup_rx("_UPDATE_LOCATION_RESULT", "06010809710000004026f0", NULL);

	btw("now the conn is accepted");
	EXPECT_ACCEPTED(true);

	btw("the conn is discarded");
	osmo_fsm_inst_dispatch(conn->conn_fsm, SUBSCR_CONN_E_CN_CLOSE, NULL);
	EXPECT_CONN_COUNT(0);

	btw("after a while, a new conn...");
	conn = conn_new();
	EXPECT_ACCEPTED(false);

	btw("...sends a CM Service Request. VLR responds with Auth Req, 2nd auth vector");
	ms_sends_cm_service_req();
	OSMO_ASSERT(conn->conn_fsm);
	OSMO_ASSERT(conn->subscr);
	OSMO_ASSERT(conn->subscr->vsub);

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Authen Response, VLR accepts with a CM Service Accept");
	gsup_expect_tx(NULL);
	ms_sends_msg("0554" "20bde240" /* 2nd vector's sres, s.a. */);

	btw("a USSD request is serviced");
	dtap_expect_tx("8b2a1c27a225020100302002013b301b04010f0416d9775d0e2ae3"
		       "e965f73cfd7683d27310cd06bbc51a0d");
	ms_sends_msg("0b3b1c15a11302010002013b300b04010f0406aa510c061b017f0100");

	btw("conn is released");
	// FIXME: should happen implicitly
	osmo_fsm_inst_dispatch(conn->conn_fsm, SUBSCR_CONN_E_CN_CLOSE, NULL);
	EXPECT_CONN_COUNT(0);

	comment_end();
}

void test_ciph()
{
	comment_start();
	clear_vlr();

	/* implicit: net->authentication_required = true; */
	net->a5_encryption = VLR_CIPH_A5_1;

	btw("new conn");
	struct gsm_subscriber_connection *conn = conn_new();

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_lu_req();
	OSMO_ASSERT(gsup_tx_confirmed);

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
	gsup_rx("OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT",
		"0a"
		/* imsi */
		"0108" "09710000004026f0"
		/* 5 auth vectors... */
		/* TL    TL     rand */
		"0322"  "2010" "585df1ae287f6e273dce07090d61320b"
		/*       TL     sres       TL     kc */
			"2104" "2d8b2c3e" "2208" "61855fb81fc2a800"
		"0322"  "2010" "12aca96fb4ffdea5c985cbafa9b6e18b"
			"2104" "20bde240" "2208" "07fa7502e07e1c00"
		"0322"  "2010" "e7c03ba7cf0e2fde82b2dc4d63077d42"
			"2104" "a29514ae" "2208" "e2b234f807886400"
		"0322"  "2010" "fa8f20b781b5881329d4fea26b1a3c51"
			"2104" "5afc8d72" "2208" "2392f14f709ae000"
		"0322"  "2010" "0fd4cc8dbe8715d1f439e304edfd68dc"
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000",
		NULL);

	btw("MS sends Authen Response, VLR accepts and sends GSUP LU Req to HLR, also Ciphering Mode Command to MS");
	gsup_expect_tx("04010809710000004026f0");
	ms_sends_msg("05542d8b2c3e");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("_INSERT_DATA_REQUEST",
		"10010809710000004026f00804036470f1",
		"12010809710000004026f0");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	gsup_rx("_UPDATE_LOCATION_RESULT", "06010809710000004026f0", NULL);

	btw("conn is released");
	// FIXME: should happen implicitly
	osmo_fsm_inst_dispatch(conn->conn_fsm, SUBSCR_CONN_E_CN_CLOSE, NULL);
	EXPECT_CONN_COUNT(0);

	comment_end();
}

#if 0
void test_no_authen_imei()
{
	comment_start();
	clear_vlr();

	net->authentication_required = false;
	net->a5_encryption = VLR_CIPH_NONE;

	btw("new conn");
	struct gsm_subscriber_connection *conn = conn_new();

	btw("Location Update request causes a GSUP LU request to HLR");
	gsup_expect_tx("04010809710000004026f0");
	ms_sends_lu_req();
	OSMO_ASSERT(gsup_tx_confirmed);

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("_INSERT_DATA_REQUEST",
		"10010809710000004026f00804036470f1",
		"12010809710000004026f0");

	btw("having received subscriber data does not mean acceptance");
	EXPECT_ACCEPTED(false);

	thwart_rx_non_initial_requests();

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	gsup_rx("_UPDATE_LOCATION_RESULT", "06010809710000004026f0", NULL);

	btw("now the conn is accepted");
	EXPECT_ACCEPTED(true);

	btw("the conn is discarded");
	osmo_fsm_inst_dispatch(conn->conn_fsm, SUBSCR_CONN_E_CN_CLOSE, NULL);
	EXPECT_CONN_COUNT(0);

	btw("after a while, a new conn...");
	conn = conn_new();
	EXPECT_ACCEPTED(false);

	btw("...sends a CM Service Request");
	ms_sends_cm_service_req();
	OSMO_ASSERT(conn->conn_fsm);
	OSMO_ASSERT(conn->subscr);
	OSMO_ASSERT(conn->subscr->vsub);
	EXPECT_ACCEPTED(true);

	btw("a USSD request is serviced");
	dtap_expect_tx("8b2a1c27a225020100302002013b301b04010f0416d9775d0e2ae3"
		       "e965f73cfd7683d27310cd06bbc51a0d");
	ms_sends_msg("0b3b1c15a11302010002013b300b04010f0406aa510c061b017f0100");

	btw("conn is released");
	osmo_fsm_inst_dispatch(conn->conn_fsm, SUBSCR_CONN_E_CN_CLOSE, NULL);
	EXPECT_CONN_COUNT(0);

	comment_end();
}
#endif


static struct log_info_cat test_categories[] = {
	[DMSC] = {
		.name = "DMSC",
		.description = "Mobile Switching Center",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
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
	[DRR] = {
		.name = "DRR",
		.description = "Layer3 Radio Resource (RR)",
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
	[DREF] = {
		.name = "DREF",
		.description = "Reference Counting",
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
	fprintf(stderr, "GSUP --> HLR: %s\n",
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
	talloc_free(gsup_tx_expected);
	gsup_tx_expected = NULL;
	return 0;
}

/* override, requires '-Wl,--wrap=gsm0808_submit_dtap' */
int __real_gsm0808_submit_dtap(struct gsm_subscriber_connection *conn,
			       struct msgb *msg, int link_id, int allow_sacch);
int __wrap_gsm0808_submit_dtap(struct gsm_subscriber_connection *conn,
			       struct msgb *msg, int link_id, int allow_sacch)
{
	btw("DTAP --> MS: %s", osmo_hexdump_nospc(msg->data, msg->len));

	OSMO_ASSERT(dtap_tx_expected);
	if (msg->len != dtap_tx_expected->len
	    || memcmp(msg->data, dtap_tx_expected->data, msg->len)) {
		fprintf(stderr, "Mismatch! Expected:\n%s\n",
		       osmo_hexdump_nospc(dtap_tx_expected->data,
					  dtap_tx_expected->len));
		abort();
	}

	btw("DTAP matches expected message");

	talloc_free(msg);
	dtap_tx_confirmed = true;
	talloc_free(dtap_tx_expected);
	dtap_tx_expected = NULL;
	return 0;
}

static int fake_vlr_tx_lu_acc(void *msc_conn_ref)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	btw("sending LU Accept for %s", subscr_name(conn->subscr));
	return 0;
}

static int fake_vlr_tx_lu_rej(void *msc_conn_ref, uint8_t cause)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	btw("sending LU Reject for %s, cause %u", subscr_name(conn->subscr), cause);
	return 0;
}

static int fake_vlr_tx_cm_serv_acc(void *msc_conn_ref)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	btw("sending CM Service Accept for %s", subscr_name(conn->subscr));
	return 0;
}

static int fake_vlr_tx_cm_serv_rej(void *msc_conn_ref,
				   enum vlr_proc_arq_result result)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	btw("sending CM Service Reject for %s, result %s",
	    subscr_name(conn->subscr),
	    vlr_proc_arq_result_name(result));
	return 0;
}

static int fake_vlr_tx_auth_req(void *msc_conn_ref, struct gsm_auth_tuple *at)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	btw("sending Auth Request for %s: tuple use_count=%d key_seq=%d auth_types=0x%x and...",
	    subscr_name(conn->subscr),
	    at->use_count, at->key_seq, at->vec.auth_types);
	btw("...rand=%s",
	    osmo_hexdump_nospc((void*)&at->vec.rand, sizeof(at->vec.rand)));
	btw("...kc=%s",
	    osmo_hexdump_nospc((void*)&at->vec.kc, sizeof(at->vec.ck)));
	btw("...expecting sres=%s",
	    osmo_hexdump_nospc((void*)&at->vec.sres, sizeof(at->vec.sres)));
	return 0;
}

static int fake_vlr_tx_auth_rej(void *msc_conn_ref)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	btw("sending Auth Reject for %s", subscr_name(conn->subscr));
	return 0;
}

static int fake_vlr_tx_ciph_mode_cmd(void *msc_conn_ref)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	btw("sending Ciphering Mode Command for %s", subscr_name(conn->subscr));
	return 0;
}

int main(int argc, const char **argv)
{
	void *msgb_ctx;
	tall_bsc_ctx = talloc_named_const(NULL, 0, "subscr_conn_test_ctx");
	msgb_ctx = msgb_talloc_ctx_init(tall_bsc_ctx, 0);
	osmo_init_logging(&info);

	OSMO_ASSERT(osmo_stderr_target);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_timestamp(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, argc > 1? 1 : 0);
	log_set_print_category(osmo_stderr_target, 1);

	net = gsm_network_init(tall_bsc_ctx, 1, 1, fake_mncc_recv);
	bsc_api_init(net, msc_bsc_api());
	the_bts = gsm_bts_alloc(net);

	osmo_fsm_log_addr(false);
	OSMO_ASSERT(msc_vlr_init(net, "none", 0) == 0);
	OSMO_ASSERT(net->vlr);
	OSMO_ASSERT(net->vlr->gsup_client);
	msc_subscr_conn_init();

	net->vlr->ops.tx_lu_acc = fake_vlr_tx_lu_acc;
	net->vlr->ops.tx_lu_rej = fake_vlr_tx_lu_rej;
	net->vlr->ops.tx_cm_serv_acc = fake_vlr_tx_cm_serv_acc;
	net->vlr->ops.tx_cm_serv_rej = fake_vlr_tx_cm_serv_rej;
	net->vlr->ops.tx_auth_req = fake_vlr_tx_auth_req;
	net->vlr->ops.tx_auth_rej = fake_vlr_tx_auth_rej;
	net->vlr->ops.set_ciph_mode = fake_vlr_tx_ciph_mode_cmd;

	test_early_stage();
	test_cm_service_without_lu();
	test_no_authen();
	test_authen();
	test_ciph();

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
