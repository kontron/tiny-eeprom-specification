#include <stdio.h>
#include <stdint.h>

/*
 * Tiny EEPROM specification.
 *
 * At the moment, the only supported encoding are ASCII strings, but
 * they are not terminated by a NUL byte. Instead, the last character
 * of a string has the most significant bit set.
 *
 * After the strings pool, there is a CRC8 checksum.
 *
 * Sometimes, there are tight size constrains and the usual KEU EEPROM
 * (similar to the PICMG EEP) specification cannot be used. This
 * specification tries to fill that gap.
 *
 * There is a three byte header consisting of a magic value 'V' (for
 * 'V'PD), a version and the total length. The version is set to 2
 * because there already exist EEPROM contents with version 1. This is
 * the generalized successor of the former specification (which was
 * just used on one board).
 *
 * The basic idea is to have the usual TLV pairs, so older parsers can
 * just skip unknown (to the older parser) types. The type and length
 * are encoded in one byte. The length field has 4 bits, thus a TLV
 * pair can be at most 17 bytes long. All TLV pairs are concatenated
 * after the EEPROM header.
 *
 * To save space within a TLV (remember the largest value can just hold
 * 16 bytes), strings are stored in a common pool. The type will specify
 * the encoding of the strings stored in the pool. It is the duty of the
 * encoding to determine the length of individual strings. To simplify
 * things, there can only be one strings pool which needs to be the last
 * TLV. If a parser cannot decode the strings pool, it shouldn't abort
 * but just display any references as undecodable. A TLV pair can
 * reference a string by an index.
 *
 * At the moment, the only supported encoding are ASCII strings, but
 * they are not terminated by a NUL byte. Instead, the last character
 * of a string has the most significant bit set.
 *
 * After the strings pool, there is a CRC8 checksum.
 */
typedef uint8_t string_idx_t;

#define TINY_EEP_MAGIC 'V'
#define TINY_EEP_VERSION 2

struct eep_header {
	uint8_t magic;
	uint8_t version;
	uint8_t length;
};

/*
 * Type length tag
 *
 * Bit  Description
 * 7:4  length
 * 3:0  type id
 *
 * Type ids are only unique together with the length. This way, the id
 * can be reused with another length.
 * If the length is zero, the type is followed by one byte indicating
 * its length. This way a tag can be up to 256 bytes long.
 *
 * Long Tags:
 *  00h   reserved
 *  01h   ASCII encoded strings pool
 *
 * Tags:
 *  10h   serial number
 *  11h   factory test flags
 *  60h   base MAC address
 *  61h   product identity
 *  62h   system product identity
 *  80h   product identity w/ batch code
 *  81h   system product identity w/ batch code
 */
#define TAG_LENGTH(x) ((x) >> 4 & 0xf)

enum {
	TAG_ASCII_STRINGS = 0x01,
	TAG_SERIAL_NUMBER = 0x10,
	TAG_FACTORY_TEST_FLAGS = 0x11,
	TAG_BASE_MAC_ADDRESS = 0x60,
	TAG_PRODUCT_IDENTITY = 0x61,
	TAG_SYSTEM_PRODUCT_IDENTITY = 0x62,
	TAG_PRODUCT_IDENTITY_BATCH = 0x80,
	TAG_SYSTEM_PRODUCT_IDENTITY_BATCH = 0x81,
};

/*
 * Special ASCII encoded strings (tag 01h)
 *
 * Size: variable.
 */
struct tag_ascii_strings {
	uint8_t tag;
	uint8_t length;
	uint8_t strings[0];
};

/*
 * Serial number (tag 10h)
 *
 * Size: 2 bytes.
 */
struct tag_serial_number {
	uint8_t tag;
	string_idx_t serial_number;
} __attribute__((packed));

/*
 * (Base) Hardware ethernet address (tag 60h)
 *
 * Due to size constraints, only the base MAC address is stored.
 *
 * Size: 7 bytes.
 */
struct tag_mac_address {
	uint8_t tag;
	uint8_t mac_address[6];
} __attribute__((packed));

/*
 * Rev6
 *
 * Structure: MM NN II
 *
 * MM
 *   is alphanumeric, but has the form 0A, 0B, 0C, .., 00, 01, 02, ..
 *   Thus, we distiguish the two forms with the most significant bit
 *   and leave the remaining 7 bits as the actual value. Example values
 *   are 80h:'0A', 81h:'0B', 00h:'00', 63h:'99'.
 * NN
 *   are digits, identity mapped
 *   Examples: 00h:'00', 01h:'01', 0Ah:'10', 63h:'99'
 * II
 *   is alphanumeric. Treated as a free-form two characters value.
 *
 * Size: 4 bytes.
 */
struct rev6 {
	uint8_t major;
#define MAJOR_PROTOTYPE 0x80
	uint8_t minor;
	char internal[2];
} __attribute__((packed));

/*
 * Batch code
 *
 * Structure: MM NN BBBB II
 *
 * See Rev6 for MM, NN and II.
 *
 * BBBB
 *   are digits, identity mapped
 *
 * Size: 6 bytes.
 */
struct batch_code {
	struct rev6 rev6;
	uint16_t batch;
} __attribute__((packed));

/*
 * Product identity (tag 61h or 62h)
 *
 * Combine serial number, part number and rev6 to uniquely identify
 * a product.
 *
 * Serial number and part number are pointers to the strings pool
 * and are flexible in size;
 *
 * Size: 7 bytes.
 *
 */
struct tag_product_identity {
	uint8_t tag;
	string_idx_t serial_number;
	string_idx_t part_number;
	struct rev6 rev6;
} __attribute__((packed));

/*
 * Product identity with batch (tag 80h or 81h)
 *
 * Combine serial number, part number and batch code to uniquely
 * identify a product.
 *
 * Serial number and part number are pointers to the strings pool
 * and are flexible in size;
 *
 * Size: 9 bytes.
 *
 */
struct tag_product_identity_batch {
	uint8_t tag;
	string_idx_t serial_number;
	string_idx_t part_number;
	struct batch_code batch_code;
} __attribute__((packed));

/*
 * Factory test flags (tag 11h)
 *
 * Bit   Description
 *   7   reserved
 *   6   reserved
 *   5   reserved
 *   4   reserved
 *   3   system test successful
 *   2   burn-in test successful
 *   1   configuration test successful
 *   0   assembly test successful
 *
 * Size: 2 bytes.
 */
struct tag_factory_test_flags {
	uint8_t tag;
	uint8_t flags;
};

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <ctype.h>

#ifdef DEBUG
#define debug printf
#else
#define debug(...)
#endif

/*
 * usage: tiny-eep [options] image.bin
 *
 * General options:
 *  -d --decode
 *  -v --verbos
 *
 * TLVs:
 *  --base-mac-address 00:01:02:33:44:55
 *  --serial-number USD0A0001
 *  --factory-test-flags 0x0f
 *  --factory-test-flags-set 0x01
 *  --factory-test-flags-clear 0x01
 *  --product <serial>:<part>:<rev6>
 *  --product-batch <serial>:<part>:<batchcode>
 *  --system-product <serial>:<part>:<rev6>
 *  --system-product-batch <serial>:<part>:<batchcode>
 */

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

static void strings_pool_init(void)
{
	memset(pool->buf, 0, sizeof(pool->buf));
	pool->idx = 0;
	pool->len = 0;
}

static int string_add(const char *str)
{
	int len = strlen(str);

	debug("strings: add %s @%02lu\n", str, pool->len);
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

/* CRC-8 (ITU-T) polynomial is 0x07, init is 0x00 */
static uint8_t crc8(uint8_t *buf, size_t len)
{
	uint8_t crc = 0x00;
	int i;

	while (len--) {
		crc ^= *buf++;
		for (i = 0; i < 8; i++)
			crc = crc & 0x80 ? (crc << 1) ^ 0x07 : crc << 1;
	}
	return crc;
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
	debug("tlv: add tlv id %02x len(%lu) @%02lu\n", *(char*)tlv, len, tlv_data->len);
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

static void tlv_add_serial_number(struct tlv_data *data,
				  const char *serial_number)
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

static struct rev6 *parse_rev6(const char *str)
{
	static struct rev6 rev6;
	char tmp[3] = { 0 };

	if (strlen(str) != 6)
		return NULL;

	if (!isalnum(str[0]) || !isalnum(str[1]) ||
	    !isdigit(str[2]) || !isdigit(str[3]) ||
	    !isalnum(str[4]) || !isalnum(str[5]))
		return NULL;

	strncpy(tmp, &str[0], 2);
	if (isdigit(tmp[0]) && isdigit(tmp[1])) {
		rev6.major = strtoul(tmp, NULL, 10);
	} else {
		if (tmp[0] != '0')
			return NULL;
		rev6.major = strtoul(tmp + 1, NULL, 10);
		rev6.major |= MAJOR_PROTOTYPE;
	}

	strncpy(tmp, &str[2], 2);
	rev6.minor = strtol(tmp, NULL, 10);
	memcpy(rev6.internal, &str[4], 2);

	return &rev6;
}

static void _tlv_add_product_identity(uint8_t tag,
				      const char *serial_number,
				      const char *part_number,
				      struct rev6 *rev6)
{
	struct tag_product_identity tlv;

	tlv.tag = tag;
	tlv.serial_number = string_add(serial_number);
	tlv.part_number = string_add(part_number);
	memcpy(&tlv.rev6, rev6, sizeof(tlv.rev6));
	tlv_add(&tlv, sizeof(tlv));
}

static void tlv_add_product_identiy(const char *serial_number,
				    const char *part_number,
				    struct rev6 *rev6)
{
	_tlv_add_product_identity(TAG_PRODUCT_IDENTITY,
				  serial_number, part_number, rev6);
}

static void tlv_add_system_product_identiy(const char *serial_number,
					   const char *part_number,
					   struct rev6 *rev6)
{
	_tlv_add_product_identity(TAG_SYSTEM_PRODUCT_IDENTITY,
				  serial_number, part_number, rev6);
}

static void tlv_add_factory_test_flags(uint8_t flags)
{
	struct tag_factory_test_flags tlv;

	tlv.tag = TAG_FACTORY_TEST_FLAGS;
	tlv.flags = flags;
	tlv_add(&tlv, sizeof(tlv));
}

static void hexdump(uint8_t *buf, size_t len)
{
	int i = 0;

	for (i = 0; i < len; i++) {
		if (i && (i % 16 == 0))
			printf("\n");
		if (i % 16 == 0)
			printf("%02x: ", i);
		printf("%02x ", buf[i]);
	}
	printf("\n");
}

static void sample_encode(void)
{
	strings_pool_init();
	tlv_init();
	tlv_add_header();
	tlv_add_product_identiy("USD090005", "1234-5678",
				parse_rev6("0A0506"));
	tlv_add_system_product_identiy("KAD000001", "8765-4321",
				       parse_rev6("120599"));
	tlv_add_factory_test_flags(0xf);
	tlv_add_strings_pool();

	tlv_finish();

	hexdump(tlv_data->buf, tlv_data->len);
}

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
			printf("[%d] %s\n", idx++, tmp);
			_tmp = tmp;
		}
		offset++;
		strings++;
	};

	return offset;
}

static int decode_factory_test_flags(void *buf)
{
	struct tag_factory_test_flags *tlv = buf;

	printf("factory test flags %02x\n", tlv->flags);

	return sizeof(*tlv);
}

static char *rev6_to_str(struct rev6 *rev6)
{
	static char buf[16];

	if (rev6->major & MAJOR_PROTOTYPE) {
		sprintf(buf, "0%c", 'A' + (rev6->major & 0xf));
	} else {
		sprintf(buf, "%02d", rev6->major);
	}

	sprintf(buf+2, "%02d%04d%c%c",
		rev6->minor, 0, rev6->internal[0], rev6->internal[1]);

	return buf;
}

static int decode_product_identity(void *buf)
{
	struct tag_product_identity *tlv = buf;

	printf("%sproduct identity serial_numer %d part_numer %d rev6 %s\n",
	       tlv->tag == TAG_SYSTEM_PRODUCT_IDENTITY ? "system " : "",
	       tlv->serial_number, tlv->part_number, rev6_to_str(&tlv->rev6));

	return sizeof(*tlv);
}

static int decode_tlv(uint8_t **buf)
{
	uint8_t id = **buf;

	printf("found tag %02x\n", id);

	switch (id) {
	case TAG_ASCII_STRINGS:
		decode_ascii_strings(*buf);
		break;
	case TAG_FACTORY_TEST_FLAGS:
		decode_factory_test_flags(*buf);
		break;
	case TAG_PRODUCT_IDENTITY:
	case TAG_SYSTEM_PRODUCT_IDENTITY:
		decode_product_identity(*buf);
		break;
	default:
		/* skip tag */
		break;
	}

	if (!TAG_LENGTH(id))
		*buf += *(*buf + 1);
	else
		*buf += TAG_LENGTH(id) + 1;

	return TAG_LENGTH(id);
}

static int sample_decode(void)
{
	uint8_t *buf = tlv_data->buf;
	int ret;

	if (*buf++ != TINY_EEP_MAGIC)
		return 1;
	if (*buf++ != TINY_EEP_VERSION)
		return 1;

	/* skip length */
	buf += 1;

	do {
		ret = decode_tlv(&buf);
	} while (ret > 0);

	return ret;
}

int main(int argc, char **argv)
{
	int ret;

	sample_encode();

	ret = sample_decode();
	if (ret)
		printf("decoding failed\n");

	return 0;
}
