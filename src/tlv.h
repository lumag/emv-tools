#ifndef TLV_H
#define TLV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint16_t tlv_tag_t;

struct tlv {
	tlv_tag_t tag;
	size_t len;
	const unsigned char *value;
};

static inline tlv_tag_t tlv_tag(const struct tlv *tlv)
{
	return tlv->tag < 0x100 ? tlv->tag :
		(tlv->tag >> 8) | (tlv->tag << 8);
}

struct tlvdb;
typedef bool (*tlv_cb)(void *data, const struct tlv *tlv);

struct tlvdb *tlvdb_fixed(tlv_tag_t tag, size_t len, const unsigned char *value);
struct tlvdb *tlvdb_parse(const unsigned char *buf, size_t len);
void tlvdb_free(struct tlvdb *tlvdb);

void tlvdb_add(struct tlvdb *tlvdb, struct tlvdb *other);

void tlvdb_visit(const struct tlvdb *tlvdb, tlv_cb cb, void *data);
const struct tlv *tlvdb_get(const struct tlvdb *tlvdb, tlv_tag_t tag, const struct tlv *prev);

tlv_tag_t tlv_parse_tag(const unsigned char **buf, size_t *len);
size_t tlv_parse_len(const unsigned char **buf, size_t *len);

#endif
