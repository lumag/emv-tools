#include <stdio.h>
#include <stdlib.h>

#include "scard.h"
#include "sc_helpers.h"
#include "tlv.h"

static void dump(const unsigned char *ptr, size_t len)
{
	int i, j;

	for (i = 0; i < len; i += 16) {
		printf("\t%02x:", i);
		for (j = 0; j < 16; j++) {
			if (i + j < len)
				printf(" %02hhx", ptr[i + j]);
			else
				printf("   ");
		}
		printf(" |");
		for (j = 0; j < 16 && i + j < len; j++) {
			printf("%c", (ptr[i+j] >= 0x20 && ptr[i+j] < 0x7f) ? ptr[i+j] : '.' );
		}
		printf("\n");
	}
}

static bool print_cb(void *data, const struct tlv *tlv)
{
	if (!tlv) {
		printf("NULL\n");
		return false;
	}

	if (tlv->tag < 0x100)
		printf("Got tag %02hx len %02x:\n", tlv->tag, tlv->len);
	else
		printf("Got tag %04hx len %02x:\n", tlv->tag, tlv->len);

	dump(tlv->value, tlv->len);

	return true;
}

static struct tlvdb *docmd(struct sc *sc,
		unsigned char cla,
		unsigned char ins,
		unsigned char p1,
		unsigned char p2,
		size_t dlen,
		const unsigned char *data)
{
	unsigned short sw;
	size_t outlen;
	unsigned char *outbuf;
	struct tlvdb *tlvdb = NULL;

	printf("CMD: %02hhx %02hhx %02hhx %02hhx (%02zx)\n", cla, ins, p1, p2, dlen);
	outbuf = sc_command(sc, cla, ins, p1, p2,
			dlen, data, &sw, &outlen);
	if (scard_is_error(sc)) {
		printf(scard_error(sc));
		return NULL;
	}
	printf("response (%hx):\n", sw);
#if 0
	int i;
	for(i=0; i<outlen; i++)
		printf("%02X ", outbuf[i]);
	printf("\n");
#endif
	if (sw == 0x9000) {
		tlvdb = tlvdb_parse(outbuf, outlen);
	}

	if (!tlvdb)
		free(outbuf);

//	printf("\n");

	return tlvdb;
}

int main(void)
{
	struct sc *sc;
#if 0
	unsigned char cmd1[] = {
		0x31, 0x50, 0x41, 0x59, 0x2e, 0x53, 0x59, 0x53, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31,
	};
#endif
	unsigned char cmd4[] = {
		0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10,
	};
	unsigned char cmd5[] = {
		0x83, 0x00,
	};

	sc = scard_init();
	if (scard_is_error(sc)) {
		printf(scard_error(sc));
		return 1;
	}

	scard_connect(sc, 0);
	if (scard_is_error(sc)) {
		printf(scard_error(sc));
		return 1;
	}

#if 0
	tlv_free(docmd(sc, 0x00, 0xa4, 0x04, 0x00, sizeof(cmd1), cmd1));
	tlv_free(docmd(sc, 0x00, 0xb2, 0x01, (0x01 << 3) | 0x04, 0, NULL));
	tlv_free(docmd(sc, 0x00, 0xb2, 0x02, (0x01 << 3) | 0x04, 0, NULL));
#endif

	struct tlvdb *s;
	struct tlvdb *t;
	const struct tlv *e;
	s = docmd(sc, 0x00, 0xa4, 0x04, 0x00, sizeof(cmd4), cmd4);
	if (!s)
		return 1;
	t = docmd(sc, 0x80, 0xa8, 0x00, 0x00, sizeof(cmd5), cmd5);
	if (!t)
		return 1;
	if ((e = tlvdb_get(t, 0x80, NULL)) != NULL) {
		struct tlvdb *t1, *t2;
		t1 = tlvdb_fixed(0x82, 2, e->value);
		t2 = tlvdb_fixed(0x94, e->len - 2, e->value+2);
		tlvdb_add(s, t1);
		tlvdb_add(s, t2);
		tlvdb_free(t);
	} else {
		tlvdb_add(s, t);
	}

	e = tlvdb_get(s, 0x94, NULL);
	int i;
	for (i = 0; i < e->len; i += 4) {
		unsigned char p2 = e->value[i + 0];
		unsigned char first = e->value[i + 1];
		unsigned char last = e->value[i + 2];
//		unsigned char sdarec = e->value[i + 3];

		if (p2 == 0 || p2 == (31 << 3) || first == 0 || first > last)
			break; /* error */

		for (; first <= last; first ++) {
			t = docmd(sc, 0x00, 0xb2, first, p2 | 0x04, 0, NULL);
			if (!t)
				return 1;
			tlvdb_add(s, t);
		}

	}

	tlvdb_visit(s, print_cb, NULL);
	tlvdb_free(s);

	scard_disconnect(sc);
	if (scard_is_error(sc)) {
		printf(scard_error(sc));
		return 1;
	}
	scard_shutdown(&sc);
	if (scard_is_error(sc)) {
		printf(scard_error(sc));
		return 1;
	}

	return 0;
}
