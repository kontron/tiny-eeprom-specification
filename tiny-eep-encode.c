// SPDX-License-Identifier: BSD-2-Clause
/*
 * Utility to encode the content of an EEPROM which follows the KEU tiny EEPROM
 * specification.
 *
 * Copyright (c) 2023, Kontron Europe GmbH
 */
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <netinet/ether.h>
#include <getopt.h>
#include <errno.h>
#include <ctype.h>

#include "tiny-eep.h"
#include "crc8.h"

#define DEBUG(lvl, fmt, ...)                                    \
do {                                                            \
    if (verbose > lvl) {                                        \
        fprintf(stderr, "%s() " fmt, __func__, ## __VA_ARGS__); \
    }                                                           \
} while (0)


struct tlv_data {
	uint8_t buf[4096];
	size_t len;
};

struct strings_pool {
	uint8_t buf[4096];
	int idx;
	size_t len;
};

static struct tlv_data _tlv_data, *tlv_data = &_tlv_data;
static struct strings_pool _pool, *pool = &_pool;

static int verbose = 0;

static void strings_pool_init(void)
{
	memset(pool->buf, 0, sizeof(pool->buf));
	pool->idx = 0;
	pool->len = 0;
}

static int string_add(const char *str)
{
	int len = strlen(str);

	DEBUG(0, "add %s @%02lu\n", str, pool->len);
	memcpy(pool->buf + pool->len, str, len);
	pool->buf[pool->len + len - 1] |= 0x80;
	pool->len += len;

	return pool->idx++;
}

static void tlv_add_header(void)
{
	struct eep_header *hdr = (struct eep_header*)&tlv_data->buf;

	hdr->magic = TINY_EEP_MAGIC;
	hdr->version = TINY_EEP_VERSION;

	tlv_data->len += sizeof(*hdr);
}

static int tlv_validate(void)
{
	if (tlv_data->len > UINT8_MAX)
		return 1;

	return 0;
}

static void tlv_finish(void)
{
	struct eep_header *hdr = (struct eep_header*)&tlv_data->buf;

	/* update total length */
	hdr->length = tlv_data->len;

	/* append crc8 */
	tlv_data->buf[tlv_data->len] = crc8(tlv_data->buf, tlv_data->len);
	tlv_data->len++;
}

static void tlv_init(void)
{
	memset(tlv_data->buf, 0, sizeof(tlv_data->buf));
	tlv_data->len = 0;
}

static void tlv_add(void *tlv, size_t len)
{
	DEBUG(0, "add id %02x len(%lu) @%02lu\n", *(char*)tlv, len, tlv_data->len);
	memcpy(tlv_data->buf + tlv_data->len, tlv, len);
	tlv_data->len += len;
}

static void tlv_add_strings_pool(void)
{
	tlv_data->buf[tlv_data->len] = TAG_ASCII_STRINGS;
	tlv_data->buf[tlv_data->len + 1] = pool->len;
	memcpy(tlv_data->buf + tlv_data->len + 2, pool->buf, pool->len);
	tlv_data->len += pool->len + 2;
}

static void tlv_add_serial_number(const char *serial_number)
{
	struct tag_serial_number tlv;

	tlv.tag = TAG_SERIAL_NUMBER;
	tlv.serial_number = string_add(serial_number);
	tlv_add(&tlv, sizeof(tlv));
}

static void tlv_add_base_mac_address(struct ether_addr *addr)
{
	struct tag_mac_address tlv;

	tlv.tag = TAG_BASE_MAC_ADDRESS;
	assert(sizeof(tlv.mac_address) == ETH_ALEN);
	memcpy(&tlv.mac_address, addr, ETH_ALEN);
	tlv_add(&tlv, sizeof(tlv));
}

static int parse_rev6_major_minor(const char *str,
				  uint8_t *major, uint8_t *minor)
{
	char tmp[3] = { 0 };

	strncpy(tmp, &str[0], 2);
	if (isdigit(tmp[0]) && isdigit(tmp[1])) {
		*major = strtoul(tmp, NULL, 10);
	} else {
		if (tmp[0] != '0')
			return -EINVAL;
		*major = strtoul(tmp + 1, NULL, 10);
		*major |= MAJOR_PROTOTYPE;
	}

	strncpy(tmp, &str[2], 2);
	*minor = strtol(tmp, NULL, 10);

	return 0;
}

static int parse_rev6(const char *str, struct rev6 *rev6)
{
	int ret;

	if (strlen(str) != 6)
		return -EINVAL;

	if (!isalnum(str[0]) || !isalnum(str[1]) ||
	    !isdigit(str[2]) || !isdigit(str[3]) ||
	    !isalnum(str[4]) || !isalnum(str[5]))
		return -EINVAL;

	ret = parse_rev6_major_minor(str, &rev6->major, &rev6->minor);
	if (ret)
		return ret;

	memcpy(rev6->internal, &str[4], 2);

	return 0;
}

static int parse_batch_code(const char *str, struct rev6 *rev6, uint16_t *batch)
{
	int ret;
	char tmp[5] = { 0 };

	if (strlen(str) != 10)
		return -EINVAL;

	if (!isalnum(str[0]) || !isalnum(str[1]) ||
	    !isdigit(str[2]) || !isdigit(str[3]) ||
	    !isalnum(str[4]) || !isalnum(str[5]) ||
	    !isalnum(str[6]) || !isalnum(str[7]) ||
	    !isalnum(str[8]) || !isalnum(str[9]))
		return -EINVAL;


	ret = parse_rev6_major_minor(str, &rev6->major, &rev6->minor);
	if (ret)
		return ret;

	strncpy(tmp, &str[4], 4);
	*batch = strtol(tmp, NULL, 10);
	memcpy(rev6->internal, &str[8], 2);

	return 0;
}

struct product_identity {
	char *serial_number;
	char *part_number;
	struct rev6 rev6;
	uint16_t batch;
};

static void _tlv_add_product_identity(uint8_t tag,
				      struct product_identity *id)
{
	struct tag_product_identity tlv;

	tlv.tag = tag;
	tlv.serial_number = string_add(id->serial_number);
	tlv.part_number = string_add(id->part_number);
	memcpy(&tlv.rev6, &id->rev6, sizeof(tlv.rev6));
	tlv_add(&tlv, sizeof(tlv));
}

static void tlv_add_product_identiy(struct product_identity *id)
{
	_tlv_add_product_identity(TAG_PRODUCT_IDENTITY, id);
}

static void tlv_add_system_product_identiy(struct product_identity *id)
{
	_tlv_add_product_identity(TAG_SYSTEM_PRODUCT_IDENTITY, id);
}

static void _tlv_add_product_identity_batch(uint8_t tag,
					    struct product_identity *id)
{
	struct tag_product_identity_batch tlv;

	tlv.tag = tag;
	tlv.serial_number = string_add(id->serial_number);
	tlv.part_number = string_add(id->part_number);
	memcpy(&tlv.batch_code.rev6, &id->rev6, sizeof(tlv.batch_code.rev6));
	tlv.batch_code.batch = id->batch;
	tlv_add(&tlv, sizeof(tlv));
}

static void tlv_add_product_identiy_batch(struct product_identity *id)
{
	_tlv_add_product_identity_batch(TAG_PRODUCT_IDENTITY_BATCH, id);
}

static void tlv_add_system_product_identiy_batch(struct product_identity *id)
{
	_tlv_add_product_identity_batch(TAG_SYSTEM_PRODUCT_IDENTITY_BATCH, id);
}

static void tlv_add_factory_test_flags(uint8_t flags)
{
	struct tag_factory_test_flags tlv;

	tlv.tag = TAG_FACTORY_TEST_FLAGS;
	tlv.flags = flags;
	tlv_add(&tlv, sizeof(tlv));
}

static void usage(const char *prog)
{
	printf("%s [-h] [-v] OUTPUT\n"
	       "\n"
	       "Writes the EEPROM content to OUTPUT.\n"
	       "\n"
	       "Options:\n"
	       "  -h --help                     This help text.\n"
	       "  -v --verbose                  Be more verbose.\n"
	       "  --serial-number SERIAL        Set serial-number\n"
	       "  --base-mac-address MAC        Set the base MAC address.\n"
	       "  --product ID                  Set the product identity.\n"
	       "  --product-batch BATCH         Set the product identity w/ batch code.\n"
	       "  --system-product ID           Set the system product identity.\n"
	       "  --system-product-batch BATCH  Set the system product identity w/ batch code.\n"
	       "  --factory-test-flags FLAGS    Set the factory test flags.\n"
	       "\n"
	       "Formats:\n"
	       "  SERIAL       is a string.\n"
	       "  MAC          is a MAC address given as XX:XX:XX:XX:XX:XX.\n"
	       "  ID           is SERIALNUMBER:PARTNUMBER:REV6.\n"
	       "  BATCH        is SERIALNUMBER:PARTNUMBER:BATCHCODE.\n"
	       "  FLAGS        is a number between 0 and 255.\n"
	       "  REV6         is MMNNII.\n"
	       "  BATCHCODE    is MMNNBBBBII.\n"
	       "  SERIALNUMER  is a string.\n"
	       "  PARTNUMBER   is a string.\n"
	       "  MM           is the major revision as either a 2 digits number or 0A, 0B, ..\n"
	       "  NN           is the minor revision as a 2 digits number.\n"
	       "  II           is the internal revision as two arbitrary characters.\n"
	       "  BBBB         is the batch code as a 4 digits number.\n"
	       "\n", prog);
}

enum {
	OPT_SERIAL_NUMBER = 256,
	OPT_BASE_MAC_ADDRESS,
	OPT_PRODUCT,
	OPT_PRODUCT_BATCH,
	OPT_SYSTEM_PRODUCT,
	OPT_SYSTEM_PRODUCT_BATCH,
	OPT_FACTORY_TEST_FLAGS,
};

static const struct option opts[] = {
	{"help", no_argument, 0, 'h'},
	{"verbose", no_argument, 0, 'v'},
	{"serial-number", required_argument, 0, OPT_SERIAL_NUMBER},
	{"base-mac-address", required_argument, 0, OPT_BASE_MAC_ADDRESS},
	{"product", required_argument, 0, OPT_PRODUCT},
	{"product-batch", required_argument, 0, OPT_PRODUCT_BATCH},
	{"system-product", required_argument, 0, OPT_SYSTEM_PRODUCT},
	{"system-product-batch", required_argument, 0, OPT_SYSTEM_PRODUCT_BATCH},
	{"factory-test-flags", required_argument, 0, OPT_FACTORY_TEST_FLAGS},
	{}
};

int main(int argc, char **argv)
{
	int opt;
	FILE *f;
	char *o_serial_number = NULL;
	struct ether_addr *o_base_mac_address = NULL;
	struct product_identity o_product = { 0 };
	struct product_identity o_product_batch = { 0 };
	struct product_identity o_system_product = { 0 };
	struct product_identity o_system_product_batch = { 0 };
	struct product_identity *id = NULL;
	int o_factory_test_flags = -1;
	char *o_filename = NULL;

	while ((opt = getopt_long(argc, argv, "dv", opts, NULL)) != -1) {
		switch (opt) {
		case 'v':
			verbose++;
			break;

		case OPT_SERIAL_NUMBER:
			o_serial_number = optarg;
			break;

		case OPT_BASE_MAC_ADDRESS:
			o_base_mac_address = ether_aton(optarg);
			if (!o_base_mac_address) {
				fprintf(stderr, "Could not parse MAC address\n");
				return EXIT_FAILURE;
			}
			break;

		case OPT_PRODUCT:
			id = &o_product;
			goto parse;
		case OPT_PRODUCT_BATCH:
			id = &o_product_batch;
			goto parse;
		case OPT_SYSTEM_PRODUCT:
			id = &o_system_product;
			goto parse;
		case OPT_SYSTEM_PRODUCT_BATCH:
		{
			int ret;
			char *batch_code;

			id = &o_system_product_batch;
parse:

			id->serial_number = strtok(optarg, ":");
			id->part_number = strtok(NULL, ":");
			batch_code = strtok(NULL, ":");

			if (!id->serial_number || !id->part_number || !batch_code) {
				fprintf(stderr, "Could not parse identify token\n");
				return EXIT_FAILURE;
			}

			if (opt == OPT_PRODUCT ||
			    opt == OPT_SYSTEM_PRODUCT) {
				ret = parse_rev6(batch_code, &id->rev6);
				if (ret) {
					fprintf(stderr, "Could not parse rev6\n");
					return EXIT_FAILURE;
				}
			} else {
				ret = parse_batch_code(batch_code, &id->rev6, &id->batch);
				if (ret) {
					fprintf(stderr, "Could not parse batch code\n");
					return EXIT_FAILURE;
				}
			}
			break;
		}

		case OPT_FACTORY_TEST_FLAGS:
		{
			char *endptr;

			o_factory_test_flags = strtoul(optarg, &endptr, 0);
			if (*endptr != '\0') {
				fprintf(stderr, "Could not parse flags\n");
				return EXIT_FAILURE;
			}
			if (o_factory_test_flags > UINT8_MAX) {
				fprintf(stderr, "flags outside of its range\n");
				return EXIT_FAILURE;
			}

			break;
		}

		default:
			break;
		}
	}

	if (optind >= argc) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	o_filename = argv[optind];

	strings_pool_init();
	tlv_init();
	tlv_add_header();

	if (o_serial_number)
		tlv_add_serial_number(o_serial_number);

	if (o_base_mac_address) {
		tlv_add_base_mac_address(o_base_mac_address);
	}

	if (o_product.serial_number)
		tlv_add_product_identiy(&o_product);

	if (o_product_batch.serial_number)
		tlv_add_product_identiy_batch(&o_product_batch);

	if (o_system_product.serial_number)
		tlv_add_system_product_identiy(&o_system_product);

	if (o_system_product_batch.serial_number)
		tlv_add_system_product_identiy_batch(&o_system_product_batch);

	if (o_factory_test_flags != -1)
		tlv_add_factory_test_flags(o_factory_test_flags);

	tlv_add_strings_pool();

	if (tlv_validate()) {
		fprintf(stderr, "Could not generate binary. Size exceeded?\n");
		return EXIT_FAILURE;
	}

	tlv_finish();

	f = fopen(o_filename, "w");
	if (!f) {
		fprintf(stderr, "Could not open file: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	fwrite(tlv_data->buf, tlv_data->len, 1, f);

	fclose(f);

	return EXIT_SUCCESS;
}
