AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBSMPP34_CFLAGS) \
	$(LIBCRYPTO_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(NULL)

EXTRA_DIST = \
	subscr_conn_test.ok \
	subscr_conn_test.err \
	$(NULL)

noinst_PROGRAMS = \
	subscr_conn_test \
	$(NULL)

subscr_conn_test_SOURCES = \
	subscr_conn_test.c \
	$(NULL)

subscr_conn_test_LDADD = \
	$(top_builddir)/src/libcommon-cs/libcommon-cs.a \
	$(top_builddir)/src/libmsc/libmsc.a \
	$(top_builddir)/src/libvlr/libvlr.a \
	$(top_builddir)/src/libbsc/libbsc.a \
	$(top_builddir)/src/libtrau/libtrau.a \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBSMPP34_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBCRYPTO_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	-ldbi \
	-lrt

subscr_conn_test_LDFLAGS = \
	-Wl,--wrap=gsup_client_create \
	-Wl,--wrap=gsup_client_send \
	-Wl,--wrap=gsm0808_submit_dtap \
	$(NULL)
