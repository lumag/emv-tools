#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "tlvs.h"
#include "tlv.h"

struct tlvs {
	struct tlvs *next;
	struct tlv *tlv;
};

struct tlvs *tlvs_new(void)
{
	struct tlvs *s = calloc(1, sizeof(*s));
	return s;
}

void tlvs_free(struct tlvs *tlvs)
{
	struct tlvs *s, *n;
	for (s = tlvs; s; s = n) {
		n = s->next;
		tlv_free(s->tlv);
		free(s);
	}
}

void tlvs_add(struct tlvs *tlvs, struct tlv *tlv)
{
	if (!tlvs)
		return;

	if (!tlv)
		return;

	struct tlvs *s = malloc(sizeof *s);
	s->tlv = tlvs->tlv;
	s->next = tlvs->next;
	tlvs->next = s;
	tlvs->tlv = tlv;
}

const struct tlv_elem_info *tlvs_get(struct tlvs *tlvs, uint16_t tag)
{
	struct tlvs *s;
	const struct tlv_elem_info *e;

	for (s = tlvs; s; s = s->next) {
		e = tlv_get(s->tlv, tag);
		if (e)
			return e;
	}

	return NULL;
}

bool tlvs_visit(struct tlvs *tlvs, bool (*cb)(void *data, const struct tlv_elem_info *tei), void *data)
{
	struct tlvs *s;
	bool b;

	for (s = tlvs; s; s = s->next) {
		if (!s->tlv)
			continue;
		b = tlv_visit(s->tlv, cb, data);

		if (!b)
			return false;
	}

	return true;
}
