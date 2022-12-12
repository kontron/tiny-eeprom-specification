# Tiny EEPROM specification

## Overview

Sometimes, there are tight size constrains and the usual KEU EEPROM
(similar to the PICMG EEP) specification cannot be used. This
specification tries to fill that gap.

There is a three byte header consisting of a magic value 'V' (for
*V*PD), a version and the total length. The version is set to 2
because there already exist EEPROM contents with version 1. This is
the generalized successor of the former specification (which was
just used on one board).

The basic idea is to have the usual TLV pairs, so older parsers can
just skip unknown (to the older parser) types. The type and length
are encoded in one byte. The length field has 4 bits, thus a TLV
pair can be at most 17 bytes long. All TLV pairs are concatenated
after the EEPROM header.

To save space within a TLV (remember the largest value can just hold
16 bytes), strings are stored in a common pool. The type will specify
the encoding of the strings stored in the pool. It is the duty of the
encoding to determine the length of individual strings. To simplify
things, there can only be one strings pool which needs to be the last
TLV. If a parser cannot decode the strings pool, it shouldn't abort
but just display any references as undecodable. A TLV pair can
reference a string by an index.

At the moment, the only supported encoding are ASCII strings, but
they are not terminated by a NUL byte. Instead, the last character
of a string has the most significant bit set.

After the strings pool, there is a CRC8 checksum.

## String index

```
typedef uint8_t string_idx_t;
```

## Header

```
#define TINY_EEP_MAGIC 'V'
#define TINY_EEP_VERSION 2

struct eep_header {
	uint8_t magic;
	uint8_t version;
	uint8_t length;
};
```

## Type-Length tag

```
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
```

## Tags

```
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
```

```
/*
 * Serial number (tag 10h)
 *
 * Size: 2 bytes.
 */
struct tag_serial_number {
	uint8_t tag;
	string_idx_t serial_number;
} __attribute__((packed));
```

```
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
```

```
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
```

```
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
```

```
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
```

```
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
```
