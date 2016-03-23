#ifndef _MNCC_INT_H
#define _MNCC_INT_H

#include <stdint.h>

#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

struct mncc_int {
	uint8_t def_codec[2];
};

extern struct mncc_int mncc_int;

enum gsm48_chan_mode mncc_codec_for_mode(enum gsm_chan_t lchan_type);

#endif
