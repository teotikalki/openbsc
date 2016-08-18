/* Test v42bis Compression/Decompression */

/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
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

#include <openbsc/v42bis.h>
#include <openbsc/v42bis_private.h>
#include <openbsc/debug.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <osmocom/core/application.h>

#include <stdio.h>
#include <string.h>

#define BLOCK_SIZE 100
#define MAX_BLOCK_SIZE 2048

/* A struct to capture the output data of compressor and decompressor */
struct v42bis_output_buffer {
	uint8_t *buf;
	uint8_t *buf_pointer;
	int len;
};

/* A simple testpattern generator */
static void gen_test_pattern(uint8_t *data, int len)
{
	int i;
	for (i = 0; i < len; i++)
		data[i] = i & 0xF0;
}

/* Handler to capture the output data from the compressor */
void tx_v42bis_frame_handler(void *user_data, const uint8_t *pkt, int len)
{
	struct v42bis_output_buffer *output_buffer =
	    (struct v42bis_output_buffer *)user_data;
	memcpy(output_buffer->buf_pointer, pkt, len);
	output_buffer->buf_pointer += len;
	output_buffer->len += len;
	return;
}

/* Handler to capture the output data from the decompressor */
void tx_v42bis_data_handler(void *user_data, const uint8_t *buf, int len)
{
	/* stub */
	return;
}

/* Handler to capture the output data from the compressor */
void rx_v42bis_frame_handler(void *user_data, const uint8_t *pkt, int len)
{
	/* stub */
	return;
}

/* Handler to capture the output data from the decompressor */
void rx_v42bis_data_handler(void *user_data, const uint8_t *buf, int len)
{
	struct v42bis_output_buffer *output_buffer =
	    (struct v42bis_output_buffer *)user_data;
	memcpy(output_buffer->buf_pointer, buf, len);
	output_buffer->buf_pointer += len;
	output_buffer->len += len;
	return;
}

/* Test V.42bis compression and decompression */
static void test_v42bis(const void *ctx)
{
	v42bis_state_t *tx_state;
	v42bis_state_t *rx_state;

	uint8_t uncompressed_original[BLOCK_SIZE];
	uint8_t compressed[BLOCK_SIZE];
	uint8_t uncompressed[BLOCK_SIZE];

	int rc;
	struct v42bis_output_buffer compressed_data;
	struct v42bis_output_buffer uncompressed_data;

	/* Initalize */
	tx_state =
	    v42bis_init(ctx, NULL, 3, MAX_BLOCK_SIZE, 6,
			&tx_v42bis_frame_handler, NULL, MAX_BLOCK_SIZE,
			&tx_v42bis_data_handler, NULL, MAX_BLOCK_SIZE);
	OSMO_ASSERT(tx_state);
	rx_state =
	    v42bis_init(ctx, NULL, 3, MAX_BLOCK_SIZE, 6,
			&rx_v42bis_frame_handler, NULL, MAX_BLOCK_SIZE,
			&rx_v42bis_data_handler, NULL, MAX_BLOCK_SIZE);
	OSMO_ASSERT(rx_state);
	v42bis_compression_control(tx_state, V42BIS_COMPRESSION_MODE_ALWAYS);
	v42bis_compression_control(rx_state, V42BIS_COMPRESSION_MODE_ALWAYS);

	/* Generate test pattern for input */
	gen_test_pattern(uncompressed_original, sizeof(uncompressed_original));

	/* Run compressor */
	compressed_data.buf = compressed;
	compressed_data.buf_pointer = compressed;
	compressed_data.len = 0;
	tx_state->compress.user_data = (&compressed_data);
	rc = v42bis_compress(tx_state, uncompressed_original,
			     sizeof(uncompressed_original));
	OSMO_ASSERT(rc == 0);
	rc = v42bis_compress_flush(tx_state);
	OSMO_ASSERT(rc == 0);

	/* Decompress again */
	uncompressed_data.buf = uncompressed;
	uncompressed_data.buf_pointer = uncompressed;
	uncompressed_data.len = 0;
	rx_state->decompress.user_data = (&uncompressed_data);
	rc = v42bis_decompress(rx_state, compressed_data.buf,
			       compressed_data.len);
	OSMO_ASSERT(rc == 0);
	rc = v42bis_decompress_flush(rx_state);
	OSMO_ASSERT(rc == 0);

	/* Check results */
	printf("uncompressed_original= %s\n",
	       osmo_hexdump_nospc(uncompressed_original,
				  sizeof(uncompressed_original)));
	printf("uncompressed=          %s\n",
	       osmo_hexdump_nospc(uncompressed_data.buf,
				  uncompressed_data.len));
	printf("compressed=            %s\n",
	       osmo_hexdump_nospc(compressed_data.buf, compressed_data.len));
	rc = memcmp(uncompressed, uncompressed_original, BLOCK_SIZE);
	OSMO_ASSERT(rc == 0);

	v42bis_free(tx_state);
	v42bis_free(rx_state);
}

static struct log_info_cat gprs_categories[] = {
	[DV42BIS] = {
		     .name = "DV42BIS",
		     .description = "V.42bis data compression (SNDCP)",
		     .enabled = 1,.loglevel = LOGL_DEBUG,
		     }
};

static struct log_info info = {
	.cat = gprs_categories,
	.num_cat = ARRAY_SIZE(gprs_categories),
};

int main(int argc, char **argv)
{
	void *v42bis_ctx;

	osmo_init_logging(&info);

	v42bis_ctx = talloc_named_const(NULL, 0, "v42bis_ctx");

	test_v42bis(v42bis_ctx);
	printf("Done\n");

	talloc_report_full(v42bis_ctx, stderr);
	OSMO_ASSERT(talloc_total_blocks(v42bis_ctx) == 1);
	return 0;
}

/* stubs */
struct osmo_prim_hdr;
int bssgp_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	abort();
}
