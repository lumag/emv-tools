#ifndef TLV_H
#define TLV_H

#include <stdint.h>
#include <stdbool.h>

struct tlv_elem_info {
	uint16_t tag;
	size_t len;
	const unsigned char *ptr;
};

struct tlv *tlv_parse(const unsigned char *buf, size_t len);
struct tlv *tlv_new(uint16_t tag, const unsigned char *buf, size_t len);
void tlv_free(struct tlv *tlv);
bool tlv_visit(struct tlv *tlv, bool (*cb)(void *data, const struct tlv_elem_info *tei), void *data);
const struct tlv_elem_info *tlv_get(struct tlv *tlv, uint16_t tag);
bool tlv_remove(struct tlv *tlv, uint16_t tag);

#endif
