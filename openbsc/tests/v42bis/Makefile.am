AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBCARES_CFLAGS)

EXTRA_DIST = v42bis_test.ok

noinst_PROGRAMS = v42bis_test

v42bis_test_SOURCES = v42bis_test.c

v42bis_test_LDADD = \
	$(top_builddir)/src/gprs/v42bis.o \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOGB_LIBS) \
	$(LIBCARES_LIBS) \
	$(LIBCRYPTO_LIBS) \
	-lgtp -lrt -lm


