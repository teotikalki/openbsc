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
#include <stdbool.h>

#define P0 3
#define P1 512
#define P2 20

#define BLOCK_SIZE 1024
#define MAX_BLOCK_SIZE 1024

/* Sample packets to test with */
#define COMPR_PACKETS_LEN 11
char *compr_packets[] = {
	"4500010268000700004006cefac0a80002550d93d740000050462c7ba7e4d1753a80184000aad500000101080a0001a670084dafb4474554202f20485454502f312e310d0a4163636570743a206d756c7469706172742f6d697865642c206170706c69636174696f6e2f766e642e7761702e6d756c7469706172742e6d6978656433005ab97a052b960d59b368d5b2ddb3e60e9c372ef610b6dbf56bd8b165030f2e7cf88dd63b68f64c3d9b76ed1cb58847b490d122e8d0a24761185913d50e1aa423f0dc49036387d6d7b169e4d0cac68e1cd93b70f0804123f7eee03372dcc801038f193b306a68b5b2864d9a3b629a30b1a2b5081b35384613357a07c6133271d4e021a3064d52347182ee81b119c69c3a72d2b079b37e4409c177e6f4902163738cdd71f8a0a903d68ec21866e4c0918185087dfb329cec9831834d951a337c4a2e1174891c3badf5e8d113a38f1c336e24520c8a65751d1844d4c7696d852c1f240e992becf8918d0c9145465441939fcc6a1950a206b7e1fca38e1145eaebc129230aeb24f57bcab011c3c68829f5efe7bfcbe4c814e731668c3042f6fef93a62d9909561e4c91123c163d0085a3a4e1c3466c6c649ea048d519d5ff3a0f95ef4280c2471269e61633ee9193469de8845a3554d9fa74199c48622e7fa7dac30ac602f9af40a9ef0236a54268247cd7f923946d0a8d1c3c68d1e35788c5002e54ad0a00100",
	"4500010268000900004006cef8c0a80002550d93d740000050462c7ba7e4d1753a801840007e7f00000101080a0001d1cc084db0ae474554202f20485454502f312e310d0a4163636570743a206d756c7469706172742f6d697865642c206170706c69636174696f6e2f766e642e7761702e6d756c7469706172742e6d6978656433005ab97a052b960d59b368d5b2ddb3e60e9c372ef610b6dbf56bd8b165030f2e7cf88dd63b68f64c3d9b76ed1cb58847b490d122e8d0a24761185913d50e1aa423f0dc49036387d6d7b169e4d0cac68e1cd93b70f0804123f7eee03372dcc801038f193b306a68b5b2864d9a3b629a30b1a2b5081b35384613357a07c6133271d4e021a3064d52347182ee81b119c69c3a72d2b079b37e4409c177e6f4902163738cdd71f8a0a903d68ec21866e4c0918185087dfb329cec9831834d951a337c4a2e1174891c3badf5e8d113a38f1c336e24520c8a65751d1844d4c7696d852c1f240e992becf8918d0c9145465441939fcc6a1950a206b7e1fca38e1145eaebc129230aeb24f57bcab011c3c68829f5efe7bfcbe4c814e731668c3042f6fef93a62d9909561e4c91123c163d0085a3a4e1c3466c6c649ea048d519d5ff3a0f95ef4280c2471269e61633ee9193469de8845a3554d9fa74199c48622e7fa7dac30ac602f9af40a9ef0236a54268247cd7f923946d0a8d1c3c68d1e35788c5002e54ad0a00100",
	"4500010268000b00004006cef6c0a80002550d93d740000050462c7ba7e4d1753b80193fff131c00000101080a00022884084dc558474554202f20485454502f312e310d0a4163636570743a206d756c7469706172742f6d697865642c206170706c69636174696f6e2f766e642e7761702e6d756c7469706172742e6d6978656433005ab97a052b960d59b368d5b2ddb3e60e9c372ef610b6dbf56bd8b165030f2e7cf88dd63b68f64c3d9b76ed1cb58847b490d122e8d0a24761185913d50e1aa423f0dc49036387d6d7b169e4d0cac68e1cd93b70f0804123f7eee03372dcc801038f193b306a68b5b2864d9a3b629a30b1a2b5081b35384613357a07c6133271d4e021a3064d52347182ee81b119c69c3a72d2b079b37e4409c177e6f4902163738cdd71f8a0a903d68ec21866e4c0918185087dfb329cec9831834d951a337c4a2e1174891c3badf5e8d113a38f1c336e24520c8a65751d1844d4c7696d852c1f240e992be4e8918d8c9045465441939fcc6a1950a206b7e1dca38e1145eaebb929230aeb24f579cab011c3c68829f5efe7afcbe4c814e731668c3042f6fef93a62d9909561e4c91123c163d0084a3a4e1c3466c6c649ea048dd19c5ff3a0f95ef4280c2471269e61633ee9193469de8845a3554d9fa74199c48622c7fa7dac30ac5c2f9af40a1ef0236a502682478dff913946d0a8d1c3c68d1e35788c5002e54ad0a00100",
	"4500010268000c00004006cef5c0a80002550d93d740000050462c7ba7e4d1753b80193fff65ab00000101080a0002d5f4084dc558474554202f20485454502f312e310d0a4163636570743a206d756c7469706172742f6d697865642c206170706c69636174696f6e2f766e642e7761702e6d756c7469706172742e6d6978656433005ab97a052b960d59b368d5b2ddb3e60e9c372ef610b6dbf56bd8b165030f2e7cf88dd63b68f64c3d9b76ed1cb58847b490d122e8d0a24761185913d50e1aa423f0dc49036387d6d7b169e4d0cac68e1cd93b70f0804123f7eee03372dcc801038f193b306a68b5b2864d9a3b629a30b1a2b5081b35384613357a07c6133271d4e021a3064d52347182ee81b119c69c3a72d2b079b37e4409c177e6f4902163738cdd71f8a0a903d68ec21866e4c0918185087dfb329cec9831834d951a337c4a2e1174891c3badf5e8d113a38f1c336e24520c8a65751d1844d4c7696d852c1f240e992be4e8918d8c9045465441939fcc6a1950a206b7e1dca38e1145eaebb929230aeb24f579cab011c3c68829f5efe7afcbe4c814e731668c3042f6fef93a62d9909561e4c91123c163d0084a3a4e1c3466c6c649ea048dd19c5ff3a0f95ef4280c2471269e61633ee9193469de8845a3554d9fa74199c48622c7fa7dac30ac5c2f9af40a1ef0236a502682478dff913946d0a8d1c3c68d1e35788c5002e54ad0a00100",
	"450001022d000f00004006ac5ec0a800020a0901ab40011f4046a2f5a8e0a618025018400093480000474554202f20485454502f312e310d0a4163636570743a206d756c7469706172742f6d697865642c206170706c69636174696f6e2f766e642e7761702e6d756c7469706172742e6d697865642c206170706c69636174696f6e33005cbd8215bb67cd1d386f5cecd1cb766ad5ab59b7decdbbb7ef1ba877d0ec49daf56bd83960fd8e6821a3c5cd9c3b7bc230b2e6a81d343e47e0b99306c60ea8a54fd3c801958d1d39a877e0e00183c6ebd8b767e4b89103061e337660d4806a650d9b3477c4346162056a11366a7064d6c9f30e8c2764e2a8c143460d9a9f68e2dcdc0323328c3975e4a461f326fc881278efcce9214346e418b1e3f04153c7aa9dfd31ccc88123030b11f5ec6538d93163069b2a3566d0445ce2e612397646d398118347cd9a3a68f49848f12696d0756010011f67b415ad7c90fc17be5f224536322e16195105cd7b32a16540397adb06718a3a461459afe7a58c28a293acb729c3460c1b23a6ac6ffffe2d93235388c79831c288d6f6ddeb6065a355869127478cdcae79b3739c3868cc648df3d3091a9e31abe641537d674f1848e2203cc386fbcf3368d2bcc18a06aa9a3e456fde0c00",
	"450001022d001000004006ac5dc0a800020a0901ab40011f4046a2f5a8e0a618025018400093480000474554202f20485454502f312e310d0a4163636570743a206d756c7469706172742f6d697865642c206170706c69636174696f6e2f766e642e7761702e6d756c7469706172742e6d697865642c206170706c69636174696f6e33005cbd8215bb67cd1d386f5cecd1cb766ad5ab59b7decdbbb7ef1ba877d0ec49daf56bd83960fd8e6821a3c5cd9c3b7bc230b2e6a81d343e47e0b99306c60ea8a54fd3c801958d1d39a877e0e00183c6ebd8b767e4b89103061e337660d4806a650d9b3477c4346162056a11366a7064d6c9f30e8c2764e2a8c143460d9a9f68e2dcdc0323328c3975e4a461f326fc881278efcce9214346e418b1e3f04153c7aa9dfd31ccc88123030b11f5ec6538d93163069b2a3566d0445ce2e612397646d398118347cd9a3a68f49848f12696d0756010011f67b415ad7c90fc17be5f224536322e16195105cd7b32a16540397adb06718a3a461459afe7a58c28a293acb729c3460c1b23a6ac6ffffe2d93235388c79831c288d6f6ddeb6065a355869127478cdcae79b3739c3868cc648df3d3091a9e31abe641537d674f1848e2203cc386fbcf3368d2bcc18a06aa9a3e456fde0c00",
	"450001022d001100004006ac5cc0a800020a0901ab40011f4046a2f5a8e0a618025018400093480000474554202f20485454502f312e310d0a4163636570743a206d756c7469706172742f6d697865642c206170706c69636174696f6e2f766e642e7761702e6d756c7469706172742e6d697865642c206170706c69636174696f6e33005cbd8215bb67cd1d386f5cecd1cb766ad5ab59b7decdbbb7ef1ba877d0ec49daf56bd83960fd8e6821a3c5cd9c3b7bc230b2e6a81d343e47e0b99306c60ea8a54fd3c801958d1d39a877e0e00183c6ebd8b767e4b89103061e337660d4806a650d9b3477c4346162056a11366a7064d6c9f30e8c2764e2a8c143460d9a9f68e2dcdc0323328c3975e4a461f326fc881278efcce9214346e418b1e3f04153c7aa9dfd31ccc88123030b11f5ec6538d93163069b2a3566d0445ce2e612397646d398118347cd9a3a68f49848f12696d0756010011f67b415ad7c90fc17be5f224536322e16195105cd7b32a16540397adb06718a3a461459afe7a58c28a293acb729c3460c1b23a6ac6ffffe2d93235388c79831c288d6f6ddeb6065a355869127478cdcae79b3739c3868cc648df3d3091a9e31abe641537d674f1848e2203cc386fbcf3368d2bcc18a06aa9a3e456fde0c00",
	"450001022d001200004006ac5bc0a800020a0901ab40011f4046a2f5a8e0a618025018400093480000474554202f20485454502f312e310d0a4163636570743a206d756c7469706172742f6d697865642c206170706c69636174696f6e2f766e642e7761702e6d756c7469706172742e6d697865642c206170706c69636174696f6e33005cbd8215bb67cd1d386f5cecd1cb766ad5ab59b7decdbbb7ef1ba877d0ec49daf56bd83960fd8e6821a3c5cd9c3b7bc230b2e6a81d343e47e0b99306c60ea8a54fd3c801958d1d39a877e0e00183c6ebd8b767e4b89103061e337660d4806a650d9b3477c4346162056a11366a7064d6c9f30e8c2764e2a8c143460d9a9f68e2dcdc0323328c3975e4a461f326fc881278efcce9214346e418b1e3f04153c7aa9dfd31ccc88123030b11f5ec6538d93163069b2a3566d0445ce2e612397646d398118347cd9a3a68f49848f12696d0756010011f67b415ad7c90fc17be5f224536322e16195105cd7b32a16540397adb06718a3a461459afe7a58c28a293acb729c3460c1b23a6ac6ffffe2d93235388c79831c288d6f6ddeb6065a355869127478cdcae79b3739c3868cc648df3d3091a9e31abe641537d674f1848e2203cc386fbcf3368d2bcc18a06aa9a3e456fde0c00",
	"4500010268001300004006ceeec0a80002550d93d740000050462c7ba7e4d1753b80193fff7b4a00000101080a0003c054084dc558474554202f20485454502f312e310d0a4163636570743a206d756c7469706172742f6d697865642c206170706c69636174696f6e2f766e642e7761702e6d756c7469706172742e6d6978656433005bbb7e0d3b964dd9b369d7b6ddb3e60e9c372ef614beeb15ac58b2660513368cf8cdd63b68f65045ab96ed9cb58947b490d1422851a34861185923d50e9aa423f0dc490363c756d8b269e4d8cac68e9cd93b70f0804143376fe13372dcc801038f193b306a6cb5b2864d9a3b629a30b1b2b5081b353848173d7a07c6133271d4e021a3068d52347184ee81c119c69c3a72d2b079c37e4489c177e6f4902183730cde71f8a0a913d6cec21866e4c091818548fdfb329cec9831834d951a337e4e2e2174891c3baef5e8d113a38f1c336e2656148a85751d1844d6c7716da52c1f240f9b2fecf8918d0c9145465441a39f0c6b1950a40ab7f1fca38e1145ecebc129234aeb24f67bcab011c3c68829f6f1ebb7cbe4c894e731668c3052163ffa3a63d9949561e4c91123c263d0105a3a4e1c3466c8c651ea04cd519d60f3a0016f14290c2471289e61735ee9193469de8c45b3554d1fa84299c88622e73afeac30ac6037aaf40a9ef0236a54268247cd7f923946d0a8d1c3c68d1e35788c5002e58a50a10100",
	"450001022d001400004006ac59c0a800020a0901ab40011f4046a2f5a8e0a618025018400093480000474554202f20485454502f312e310d0a4163636570743a206d756c7469706172742f6d697865642c206170706c69636174696f6e2f766e642e7761702e6d756c7469706172742e6d697865642c206170706c69636174696f6e33005cbd8215bb67cd1d386f5cecd1cb766ad5ab59b7decdbbb7ef1ba877d0ec49daf56bd83960fd8e6821a3c5cd9c3b7bc230b2e6a81d343e47e0b99306c60ea8a54fd3c801958d1d39a877e0e00183c6ebd8b767e4b89103061e337660d4806a650d9b3477c4346162056a11366a7064d6c9f30e8c2764e2a8c143460d9a9f68e2dcdc0323328c3975e4a461f326fc881278efcce9214346e418b1e3f04153c7aa9dfd31ccc88123030b11f5ec6538d93163069b2a3566d0445ce2e612397646d398118347cd9a3a68f49848f12696d0756010011f67b415ad7c90fc17be5f224536322e16195105cd7b32a16540397adb06718a3a461459afe7a58c28a293acb729c3460c1b23a6ac6ffffe2d93235388c79831c288d6f6ddeb6065a355869127478cdcae79b3739c3868cc648df3d3091a9e31abe641537d674f1848e2203cc386fbcf3368d2bcc18a06aa9a3e456fde0c00",
	"450001022d001500004006ac58c0a800020a0901ab40011f4046a2f5a8e0a618025018400093480000474554202f20485454502f312e310d0a4163636570743a206d756c7469706172742f6d697865642c206170706c69636174696f6e2f766e642e7761702e6d756c7469706172742e6d697865642c206170706c69636174696f6e33005cbd8215bb67cd1d386f5cecd1cb766ad5ab59b7decdbbb7ef1ba877d0ec49daf56bd83960fd8e6821a3c5cd9c3b7bc230b2e6a81d343e47e0b99306c60ea8a54fd3c801958d1d39a877e0e00183c6ebd8b767e4b89103061e337660d4806a650d9b3477c4346162056a11366a7064d6c9f30e8c2764e2a8c143460d9a9f68e2dcdc0323328c3975e4a461f326fc881278efcce9214346e418b1e3f04153c7aa9dfd31ccc88123030b11f5ec6538d93163069b2a3566d0445ce2e612397646d398118347cd9a3a68f49848f12696d0756010011f67b415ad7c90fc17be5f224536322e16195105cd7b32a16540397adb06718a3a461459afe7a58c28a293acb729c3460c1b23a6ac6ffffe2d93235388c79831c288d6f6ddeb6065a355869127478cdcae79b3739c3868cc648df3d3091a9e31abe641537d674f1848e2203cc386fbcf3368d2bcc18a06aa9a3e456fde0c00",
};

#define UNCOMPR_PACKETS_LEN 6
char *uncompr_packets[] = {
	"45000236000700004006cf2cc0a80002550d93d7400000501e200da7c0c95a70801840002e3700000101080a000174140853d489474554202f20485454502f312e310d0a4163636570743a206d756c7469706172742f6d697865642c206170706c69636174696f6e2f766e642e7761702e6d756c7469706172742e6d697865642c206170706c69636174696f6e2f766e642e7761702e7868746d6c2b786d6c2c206170706c69636174696f6e2f7868746d6c2b786d6c2c20746578742f766e642e7761702e776d6c2c202a2f2a0d0a4163636570742d436861727365743a207574662d382c207574662d31362c2069736f2d383835392d312c2069736f2d31303634362d7563732d322c2053686966745f4a49532c20426967350d0a4163636570742d4c616e67756167653a20656e0d0a782d7761702d70726f66696c653a2022687474703a2f2f7761702e736f6e796572696373736f6e2e636f6d2f554170726f662f4b38303069523230312e786d6c220d0a486f73743a207777772e7a6f636b2e636f6d0d0a557365722d4167656e743a20536f6e794572696373736f6e4b383030692f5232422052656c656173652f4d61722d31332d323030372042726f777365722f4e657446726f6e742f332e332050726f66696c652f4d4944502d322e3020436f6e66696775726174696f6e2f434c44432d312e310d0a436f6e6e656374696f6e3a204b6565702d416c6976650d0a4163636570742d456e636f64696e673a206465666c6174652c20677a69700d0a0d0a",
	"4510004046dd40004006a9a7c0a8646ec0a864640017ad8b81980100f3ac984d801800e32a1600000101080a000647de06d1bf5efffd18fffd20fffd23fffd27",
	"4510005b46de40004006a98bc0a8646ec0a864640017ad8b8198010cf3ac984d801800e3867500000101080a000647df06d1bf61fffb03fffd1ffffd21fffe22fffb05fffa2001fff0fffa2301fff0fffa2701fff0fffa1801fff0",
	"4510003746df40004006a9aec0a8646ec0a864640017ad8b81980133f3ac989f801800e35fd700000101080a000647e106d1bf63fffd01",
	"4510003746e040004006a9adc0a8646ec0a864640017ad8b81980136f3ac98a2801800e35fd200000101080a000647e106d1bf64fffb01",
	"4510007446e140004006a96fc0a8646ec0a864640017ad8b81980139f3ac98a5801800e37b9b00000101080a000647e206d1bf640d0a2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d0d0a57656c6c636f6d6520746f20706f6c6c75780d0a2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d0d0a0d0a",
	"4510004246e240004006a9a0c0a8646ec0a864640017ad8b81980179f3ac98a5801800e3dab000000101080a000647ec06d1bf6f706f6c6c7578206c6f67696e3a20"
};

/* Calculate IP Header checksum */
static uint16_t calc_ip_csum(uint8_t *data, int len)
{
	int i;
	uint32_t accumulator = 0;
	uint16_t *pointer = (uint16_t *) data;

	for (i = len; i > 1; i -= 2) {
		accumulator += *pointer;
		pointer++;
	}

	if (len % 2)
		accumulator += *pointer;

	accumulator = (accumulator & 0xffff) + ((accumulator >> 16) & 0xffff);
	accumulator += (accumulator >> 16) & 0xffff;
	return (~accumulator);
}

/* Calculate TCP/IP checksum */
static uint16_t calc_tcpip_csum(const void *ctx, uint8_t *packet, int len)
{
	uint8_t *buf;
	uint16_t csum;

	buf = talloc_zero_size(ctx, len);
	memset(buf, 0, len);
	memcpy(buf, packet + 12, 8);
	buf[9] = packet[9];
	buf[11] = (len - 20) & 0xFF;
	buf[10] = (len - 20) >> 8 & 0xFF;
	memcpy(buf + 12, packet + 20, len - 20);
	csum = calc_ip_csum(buf, len - 20 + 12);
	talloc_free(buf);
	return csum;
}

/* A simple function to show the ascii content of a packet */
void show_packet(uint8_t *packet, int len)
{
	int i;
	char c;
	for (i = 0; i < len; i++) {
		c = packet[i];
		if (c >= 0x20 && c <= 0x7E)
			printf("%c", c);
		else
			printf(".");
	}
	printf("\n");
}

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
	/* stub, never used */
	OSMO_ASSERT(false);
	return;
}

/* Handler to capture the output data from the compressor */
void rx_v42bis_frame_handler(void *user_data, const uint8_t *pkt, int len)
{
	/* stub, never used */
	OSMO_ASSERT(false);
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
static void v42bis(const void *ctx, int mode, uint8_t *testvec, int len)
{
	v42bis_state_t *tx_state;
	v42bis_state_t *rx_state;
	uint8_t *uncompressed_original;
	uint8_t *compressed;
	uint8_t *uncompressed;

	uncompressed_original = talloc_zero_size(ctx, len);
	uncompressed = talloc_zero_size(ctx, len);

	/* Note: We allocate double the size for the compressed buffer,
	 * because in some cases the compression may increase the amount.
	 * of data. */
	compressed = talloc_zero_size(ctx, len * 2);

	int rc;
	int rc_sum = 0;
	struct v42bis_output_buffer compressed_data;
	struct v42bis_output_buffer uncompressed_data;

	/* Initalize */
	tx_state =
	    v42bis_init(ctx, NULL, P0, P1, P2,
			&tx_v42bis_frame_handler, NULL, MAX_BLOCK_SIZE,
			&tx_v42bis_data_handler, NULL, MAX_BLOCK_SIZE);
	OSMO_ASSERT(tx_state);
	rx_state =
	    v42bis_init(ctx, NULL, P0, P1, P2,
			&rx_v42bis_frame_handler, NULL, MAX_BLOCK_SIZE,
			&rx_v42bis_data_handler, NULL, MAX_BLOCK_SIZE);
	OSMO_ASSERT(rx_state);
	v42bis_compression_control(tx_state, mode);

	/* Setup input data */
	memcpy(uncompressed_original, testvec, len);

	/* Run compressor */
	compressed_data.buf = compressed;
	compressed_data.buf_pointer = compressed;
	compressed_data.len = 0;
	tx_state->compress.user_data = (&compressed_data);
	rc = v42bis_compress(tx_state, uncompressed_original, len);
	printf("v42bis_compress() rc=%d\n", rc);
	OSMO_ASSERT(rc == 0);
	rc = v42bis_compress_flush(tx_state);
	printf("v42bis_compress_flush() rc=%d\n", rc);
	OSMO_ASSERT(rc == 0);

	/* Decompress again */
	uncompressed_data.buf = uncompressed;
	uncompressed_data.buf_pointer = uncompressed;
	uncompressed_data.len = 0;
	rx_state->decompress.user_data = (&uncompressed_data);
	rc = v42bis_decompress(rx_state, compressed_data.buf,
			       compressed_data.len);
	printf("v42bis_decompress() rc=%d\n", rc);
	rc = v42bis_decompress_flush(rx_state);
	rc_sum += rc;
	printf("v42bis_decompress_flush() rc=%d\n", rc);
	rc_sum += rc;

	/* Check results */
	printf("Mode: %i\n", mode);

	printf("uncompressed_original= %s ASCII:",
	       osmo_hexdump_nospc(uncompressed_original, len));
	show_packet(uncompressed_original, len);
	printf("uncompressed=          %s ASCII:",
	       osmo_hexdump_nospc(uncompressed_data.buf,
				  uncompressed_data.len));
	show_packet(uncompressed_data.buf, uncompressed_data.len);
	printf("compressed=            %s ASCII:",
	       osmo_hexdump_nospc(compressed_data.buf, compressed_data.len));
	show_packet(compressed_data.buf, compressed_data.len);

	rc = memcmp(uncompressed, uncompressed_original, len);
	printf("memcmp() rc=%d\n", rc);
	rc_sum += rc;
	OSMO_ASSERT(rc_sum == 0);

	/* Free buffers and exit */
	v42bis_free(tx_state);
	v42bis_free(rx_state);
	talloc_free(uncompressed_original);
	talloc_free(compressed);
	talloc_free(uncompressed);
	printf("\n");
}

/* Test V.42bis compression and decompression with generated data*/
static void test_v42bis(const void *ctx)
{
	printf("Testing compression/decompression with generated data:\n");
	uint8_t testvec[BLOCK_SIZE];
	int len = sizeof(testvec);
	gen_test_pattern(testvec, len);
	v42bis(ctx, V42BIS_COMPRESSION_MODE_DYNAMIC, testvec, len);
	v42bis(ctx, V42BIS_COMPRESSION_MODE_NEVER, testvec, len);
	v42bis(ctx, V42BIS_COMPRESSION_MODE_ALWAYS, testvec, len);
}

/* Test V.42bis compression and decompression with some TCP/IP packets */
static void test_v42bis_tcpip(const void *ctx, int packet_id)
{
	uint8_t *testvec;
	int len;
	printf
	    ("Testing compression/decompression with realistic TCP/IP packets:\n");
	printf("Packet No.: %i\n", packet_id);
	len = strlen(uncompr_packets[packet_id]);
	testvec = talloc_zero_size(ctx, len);
	len = osmo_hexparse(uncompr_packets[packet_id], testvec, len);
	v42bis(ctx, V42BIS_COMPRESSION_MODE_DYNAMIC, testvec, len);
	v42bis(ctx, V42BIS_COMPRESSION_MODE_NEVER, testvec, len);
	v42bis(ctx, V42BIS_COMPRESSION_MODE_ALWAYS, testvec, len);
	talloc_free(testvec);
}

/* Test V.42bis decompression with real, sniffed packets */
static void test_v42bis_tcpip_decompress(const void *ctx, int packet_id)
{
	uint8_t *compressed;
	int compressed_len;
	uint8_t *uncompressed;
	v42bis_state_t *rx_state;
	int rc;
	int rc_sum = 0;
	int len;
	struct v42bis_output_buffer uncompressed_data;

	printf
	    ("Testing decompression with sniffed compressed TCP/IP packets:\n");
	printf("Packet No.: %i\n", packet_id);
	len = strlen(compr_packets[packet_id]);

	uncompressed = talloc_zero_size(ctx, len);
	compressed = talloc_zero_size(ctx, len);

	/* Initalize */
	rx_state =
	    v42bis_init(ctx, NULL, P0, P1, P2,
			&rx_v42bis_frame_handler, NULL, MAX_BLOCK_SIZE,
			&rx_v42bis_data_handler, NULL, MAX_BLOCK_SIZE);
	OSMO_ASSERT(rx_state);
	rx_state->decompress.transparent = 1;
	rx_state->compress.change_transparency = 1;

	/* Setup input data */
	compressed_len =
	    osmo_hexparse(compr_packets[packet_id], compressed, len);

	/* Decompress */
	uncompressed_data.buf = uncompressed;
	uncompressed_data.buf_pointer = uncompressed;
	uncompressed_data.len = 0;
	rx_state->decompress.user_data = (&uncompressed_data);
	rc = v42bis_decompress_flush(rx_state);
	printf("v42bis_decompress_flush() rc=%d\n", rc);
	rc_sum += rc;
	rc = v42bis_decompress(rx_state, compressed, compressed_len);
	printf("v42bis_decompress() rc=%d\n", rc);
	rc_sum += rc;
	rc = v42bis_decompress_flush(rx_state);
	printf("v42bis_decompress_flush() rc=%d\n", rc);
	rc_sum += rc;

	/* Check results */
	printf("compressed=   %s ASCII:",
	       osmo_hexdump_nospc(compressed, compressed_len));
	show_packet(compressed, compressed_len);
	printf("uncompressed= %s ASCII:",
	       osmo_hexdump_nospc(uncompressed_data.buf,
				  uncompressed_data.len));
	show_packet(uncompressed_data.buf, uncompressed_data.len);

	printf("IP-Header checksum=%d\n",
	       calc_ip_csum(uncompressed_data.buf, 20));
	printf("TCP/IP Checksum=%d\n",
	       calc_tcpip_csum(ctx, uncompressed_data.buf, 20));
	OSMO_ASSERT(rc_sum == 0);

	/* Free buffers and exit */
	v42bis_free(rx_state);
	talloc_free(uncompressed);
	talloc_free(compressed);
	printf("\n");
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
	int i;

	osmo_init_logging(&info);

	v42bis_ctx = talloc_named_const(NULL, 0, "v42bis_ctx");

//      test_v42bis(v42bis_ctx);

//      for(i=0;i<UNCOMPR_PACKETS_LEN;i++)
//              test_v42bis_tcpip(v42bis_ctx,i);

//      for(i=0;i<COMPR_PACKETS_LEN;i++)
//              test_v42bis_tcpip_decompress(v42bis_ctx,i);

	test_v42bis_tcpip_decompress(v42bis_ctx, 0);

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
