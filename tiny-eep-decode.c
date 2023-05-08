// SPDX-License-Identifier: BSD-2-Clause
/*
 * Utility to decode the content of an EEPROM which follows the KEU tiny EEPROM
 * specification.
 *
 * Copyright (c) 2023, Kontron Europe GmbH
 */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>

#include "tiny-eep.h"
#include "crc8.h"

#define DEBUG(lvl, fmt, ...)                                    \
do {                                                            \
    if (verbose > lvl) {                                        \
        fprintf(stderr, "%s() " fmt, __func__, ## __VA_ARGS__); \
    }                                                           \
} while (0)

static int verbose = 0;
static const char *string_pool[256];
static uint8_t buf[256];

static int decode_ascii_strings(void *buf)
{
	struct tag_ascii_strings *tlv = buf;
	uint8_t *strings = tlv->strings;
	char tmp[32], *_tmp;
	int offset, idx = 0;

	offset = 0;
	_tmp = tmp;
	while (offset < tlv->length) {
		*_tmp++ = (char)(*strings & 0x7f);
		if (offset == tlv->length || *strings & 0x80) {
			*_tmp++ = '\0';
			DEBUG(0, "[%d] %s\n", idx, tmp);
			string_pool[idx++] = strdup(tmp);
			_tmp = tmp;
		}
		offset++;
		strings++;
	};

	return offset;
}

static int decode_base_mac_address(void *buf)
{
	struct tag_mac_address *tlv = buf;

	/* can't use ether_ntoa() because it suppresses leading zeros. */
	printf("base-mac-address=%02x:%02x:%02x:%02x:%02x:%02x\n",
	       tlv->mac_address[0], tlv->mac_address[1], tlv->mac_address[2],
	       tlv->mac_address[3], tlv->mac_address[4], tlv->mac_address[5]);

	return sizeof(*tlv);
}

static int decode_factory_test_flags(void *buf)
{
	struct tag_factory_test_flags *tlv = buf;

	printf("factory-test-flags=0x%02x\n", tlv->flags);

	return sizeof(*tlv);
}

static char *_batch_code_to_str(struct rev6 *rev6, uint16_t batch)
{
	static char buf[16];

	if (rev6->major & MAJOR_PROTOTYPE) {
		sprintf(buf, "0%c", 'A' + (rev6->major & 0xf));
	} else {
		sprintf(buf, "%02d", rev6->major);
	}

	if (batch)
		sprintf(buf+2, "%02d%04d%c%c",
			rev6->minor, batch, rev6->internal[0], rev6->internal[1]);
	else
		sprintf(buf+2, "%02d%c%c",
			rev6->minor, rev6->internal[0], rev6->internal[1]);

	return buf;
}

static char *rev6_to_str(struct rev6 *rev6)
{
	return _batch_code_to_str(rev6, 0);
}

static char *batch_code_to_str(struct batch_code *code)
{
	return _batch_code_to_str(&code->rev6, code->batch);
}

static int decode_serial_number(void *buf)
{
	struct tag_serial_number *tlv = buf;
	printf("serial-number=%s\n", string_pool[tlv->serial_number]);

	return sizeof(*tlv);
}

static int decode_product_identity(void *buf)
{
	struct tag_product_identity *tlv = buf;
	const char *prefix;

	if (tlv->tag == TAG_SYSTEM_PRODUCT_IDENTITY)
		prefix = "system-product";
	else
		prefix = "product";

	printf("%s.serial-number=%s\n", prefix, string_pool[tlv->serial_number]);
	printf("%s.part-number=%s\n", prefix, string_pool[tlv->part_number]);
	printf("%s.rev6=%s\n", prefix, rev6_to_str(&tlv->rev6));

	return sizeof(*tlv);
}

static int decode_product_identity_batch(void *buf)
{
	struct tag_product_identity_batch *tlv = buf;
	const char *prefix;

	if (tlv->tag == TAG_SYSTEM_PRODUCT_IDENTITY_BATCH)
		prefix = "system-product";
	else
		prefix = "product";

	printf("%s.serial-number=%s\n", prefix, string_pool[tlv->serial_number]);
	printf("%s.part-number=%s\n", prefix, string_pool[tlv->part_number]);
	printf("%s.batch-code=%s\n", prefix, batch_code_to_str(&tlv->batch_code));

	return sizeof(*tlv);
}

static int decode_tlv(uint8_t **buf, int pass)
{
	uint8_t id = **buf;

	DEBUG(0, "found tag %02x\n", id);

	if (pass == 1) {
		if (id == TAG_ASCII_STRINGS)
			decode_ascii_strings(*buf);
	} else {
		switch (id) {
		case TAG_SERIAL_NUMBER:
			decode_serial_number(*buf);
			break;
		case TAG_BASE_MAC_ADDRESS:
			decode_base_mac_address(*buf);
			break;
		case TAG_FACTORY_TEST_FLAGS:
			decode_factory_test_flags(*buf);
			break;
		case TAG_PRODUCT_IDENTITY:
		case TAG_SYSTEM_PRODUCT_IDENTITY:
			decode_product_identity(*buf);
			break;
		case TAG_PRODUCT_IDENTITY_BATCH:
		case TAG_SYSTEM_PRODUCT_IDENTITY_BATCH:
			decode_product_identity_batch(*buf);
			break;
		default:
			/* skip tag */
			break;
		}
	}

	if (!TAG_LENGTH(id))
		*buf += *(*buf + 1);
	else
		*buf += TAG_LENGTH(id) + 1;

	return TAG_LENGTH(id);
}

static void usage(const char *prog)
{
	printf("%s [-h] [-v] BINARY\n"
	       "\n"
	       "Opens BINARY for reading and decodes its content.\n"
	       "\n"
	       "Options:\n"
	       "  -h   This help text.\n"
	       "  -v   Be more verbose.\n"
	       "\n", prog);
}

int main(int argc, char **argv)
{
	struct eep_header *hdr = (void*)buf;
	int ret, opt, i;
	uint8_t *ptr;
	FILE *f;

	while ((opt = getopt(argc, argv, "hv")) != -1) {
		switch (opt) {
		case 'v':
			verbose++;
			break;
		case 'h':
			usage(argv[0]);
			return EXIT_SUCCESS;
		};
	};

	if (optind >= argc) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	f = fopen(argv[optind], "r");
	if (!f) {
		fprintf(stderr, "Could not open file: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	ret = fread(buf, sizeof(*hdr), 1, f);
	if (ret == -1) {
		fprintf(stderr, "Could not read file: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	if (hdr->magic != TINY_EEP_MAGIC) {
		fprintf(stderr, "Invalid magic %02Xh (expected %02Xh)\n",
			hdr->magic, TINY_EEP_MAGIC);
		return EXIT_FAILURE;
	}

	if (hdr->version != TINY_EEP_VERSION) {
		fprintf(stderr, "Invalid version %02Xh (expected %02Xh)\n",
			hdr->version, TINY_EEP_VERSION);
		return EXIT_FAILURE;
	}

	rewind(f);
	ret = fread(buf, hdr->length, 1, f);
	if (ret == -1) {
		fprintf(stderr, "Could not read file: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	/* Two passes, pass 1 will decode strings and pass 2 all other TLVs. */
	for (i = 1; i <= 2; i++) {
		DEBUG(0, "decoding pass %d\n", i);

		ptr = hdr->data;
		do {
			ret = decode_tlv(&ptr, i);
		} while (ret > 0);

		if (ret < 0) {
			fprintf(stderr, "Decoding pass %d failed (%d)\n", i, ret);
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}
