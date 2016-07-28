#ifndef _GPRS_SNDCP_hdrcomp_H
#define _GPRS_SNDCP_hdrcomp_H

#define GPRS_SNDCP_HDRCOMP_BYPASS 0 /* 1=Bypass any header compression, 0=Normal */

/* Initalize header compression */
void gprs_sndcp_hdrcomp_init(void);

/* Expand header compressed packet */
int gprs_sndcp_hdrcomp_expand(uint8_t *packet, int packet_len, int pcomp);

/* Expand header compressed packet */
int gprs_sndcp_hdrcomp_compress(uint8_t *packet, int packet_len, int *pcomp);

#endif

