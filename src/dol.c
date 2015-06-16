#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "dol.h"
#include "tlv.h"

#include <stdlib.h>
#include <string.h>

static size_t dol_calculate_len(const struct tlv *tlv, size_t data_len)
{
	if (!tlv)
		return 0;

	const unsigned char *buf = tlv->value;
	size_t left = tlv->len;
	size_t count = 0;

	while (left) {
		tlv_tag_t tag = tlv_parse_tag(&buf, &left);
		size_t taglen = tlv_parse_len(&buf, &left);

		if (tag == TLV_TAG_INVALID || taglen == TLV_LEN_INVALID)
			return 0;

		count += taglen;

		/* Last tag can be of variable length */
		if (taglen == 0 && left == 0)
			count = data_len;
	}

	return count;
}

unsigned char *dol_process(const struct tlv *tlv, const struct tlvdb *tlvdb, size_t *len)
{
	if (!tlv) {
		*len = 0;
		return NULL;
	}

	const unsigned char *buf = tlv->value;
	size_t left = tlv->len;
	size_t res_len = dol_calculate_len(tlv, 0);
	unsigned char *res;
	size_t pos = 0;

	if (!res_len) {
		*len = 0;
		return NULL;
	}

	res = malloc(res_len);

	while (left) {
		tlv_tag_t tag = tlv_parse_tag(&buf, &left);
		size_t taglen = tlv_parse_len(&buf, &left);

		if (tag == TLV_TAG_INVALID || taglen == TLV_LEN_INVALID || pos + taglen > res_len) {
			free(res);
			return NULL;
		}

		const struct tlv *tag_tlv = tlvdb_get(tlvdb, tag, NULL);
		if (!tag_tlv) {
			memset(res + pos, 0, taglen);
		} else if (tag_tlv->len > taglen) {
			memcpy(res + pos, tag_tlv->value, taglen);
		} else {
			// FIXME: cn data should be padded with 0xFF !!!
			memcpy(res + pos, tag_tlv->value, tag_tlv->len);
			memset(res + pos + tag_tlv->len, 0, taglen - tag_tlv->len);
		}
		pos += taglen;
	}

	*len = pos;

	return res;
}

struct tlvdb *dol_parse(const struct tlv *tlv, const unsigned char *data, size_t data_len)
{
	if (!tlv)
		return NULL;

	const unsigned char *buf = tlv->value;
	size_t left = tlv->len;
	size_t res_len = dol_calculate_len(tlv, data_len);
	size_t pos = 0;
	struct tlvdb *db = NULL;

	if (res_len != data_len)
		return NULL;

	while (left) {
		tlv_tag_t tag = tlv_parse_tag(&buf, &left);
		size_t taglen = tlv_parse_len(&buf, &left);

		if (tag == TLV_TAG_INVALID || taglen == TLV_LEN_INVALID || pos + taglen > res_len) {
			tlvdb_free(db);
			return NULL;
		}

		/* Last tag can be of variable length */
		if (taglen == 0 && left == 0)
			taglen = res_len - pos;

		struct tlvdb *tag_db = tlvdb_fixed(tag, taglen, data + pos);
		if (!db)
			db = tag_db;
		else
			tlvdb_add(db, tag_db);

		pos += taglen;
	}

	return db;
}
