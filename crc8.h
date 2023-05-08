#ifndef __CRC8_H
#define __CRC8_H

/* CRC-8 (ITU-T) polynomial is 0x07, init is 0x00 */
static inline uint8_t crc8(uint8_t *buf, size_t len)
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

#endif /* __CRC8_H */
