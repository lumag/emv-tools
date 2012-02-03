#include <stdio.h>
#include <stdlib.h>

#include "scard.h"
#include "sc_helpers.h"
#include "tlv.h"

#ifdef WIN32
static char *pcsc_stringify_error(LONG rv)
{

	static char out[20];
	sprintf_s(out, sizeof(out), "0x%08X", rv);

	return out;
}
#endif

#define CHECK(f, rv) \
	if (SCARD_S_SUCCESS != rv) \
	{ \
	 printf(f ": %s\n", pcsc_stringify_error(rv)); \
	 return -1; \
	}

static bool print_cb(void *data, const struct tlv_elem_info *tei)
{
	int i, j;

	if (!tei) {
		printf("NULL\n");
		return false;
	}

	if (tei->tag < 0x100)
		printf("Got tag %02hx len %02x:\n", tei->tag, tei->len);
	else
		printf("Got tag %04hx len %02x:\n", tei->tag, tei->len);
	for (i = 0; i < tei->len; i += 16) {
		printf("\t%02x:", i);
		for (j = 0; j < 16; j++) {
			if (i + j < tei->len)
				printf(" %02hhx", tei->ptr[i + j]);
			else
				printf("   ");
		}
		printf(" |");
		for (j = 0; j < 16 && i + j < tei->len; j++) {
			printf("%c", (tei->ptr[i+j] >= 0x20 && tei->ptr[i+j] < 0x7f) ? tei->ptr[i+j] : '.' );
		}
		printf("\n");
	}

	return true;
}

static struct tlv *docmd(struct sc *sc,
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
	struct tlv *tlv = NULL;

	printf("CMD: %02hhx %02hhx %02hhx %02hhx (%02hhx)\n", cla, ins, p1, p2, dlen);
	outbuf = sc_command(sc, cla, ins, p1, p2,
		       dlen, data, &sw, &outlen);
	if (scard_is_error(sc)) {
		printf(scard_error(sc));
		return NULL;
	}
	printf("response (%hx): ", sw);
#if 0
	int i;
	for(i=0; i<outlen; i++)
		printf("%02X ", outbuf[i]);
	printf("\n");
#endif
	if (sw == 0x9000) {
		tlv = tlv_parse(outbuf, outlen);
		tlv_visit(tlv, print_cb, NULL);
	}

	free(outbuf);

	printf("\n");

	return tlv;
}

int main(void)
{
	struct sc *sc;
	unsigned char cmd1[] = {
	       0x31, 0x50, 0x41, 0x59, 0x2e, 0x53, 0x59, 0x53, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31,
	};
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

	scard_connect(sc);
	if (scard_is_error(sc)) {
		printf(scard_error(sc));
		return 1;
	}

	tlv_free(docmd(sc, 0x00, 0xa4, 0x04, 0x00, sizeof(cmd1), cmd1));
	tlv_free(docmd(sc, 0x00, 0xb2, 0x01, (0x01 << 3) | 0x04, 0, NULL));
	tlv_free(docmd(sc, 0x00, 0xb2, 0x02, (0x01 << 3) | 0x04, 0, NULL));
//	tlv_free(docmd(sc, 0x00, 0xa4, 0x04, 0x00, sizeof(cmd2), cmd2));
//	tlv_free(docmd(sc, 0x00, 0xa4, 0x04, 0x00, sizeof(cmd3), cmd3));
	tlv_free(docmd(sc, 0x00, 0xa4, 0x04, 0x00, sizeof(cmd4), cmd4));
	tlv_free(docmd(sc, 0x80, 0xa8, 0x00, 0x00, sizeof(cmd5), cmd5));
	tlv_free(docmd(sc, 0x00, 0xb2, 0x01, 0x08 | 0x04, 0, NULL));
	tlv_free(docmd(sc, 0x00, 0xb2, 0x01, 0x30 | 0x04, 0, NULL));
	tlv_free(docmd(sc, 0x00, 0xb2, 0x01, 0x10 | 0x04, 0, NULL));
	tlv_free(docmd(sc, 0x00, 0xb2, 0x02, 0x10 | 0x04, 0, NULL));
	tlv_free(docmd(sc, 0x00, 0xb2, 0x03, 0x10 | 0x04, 0, NULL));
	tlv_free(docmd(sc, 0x00, 0xb2, 0x04, 0x10 | 0x04, 0, NULL));
	tlv_free(docmd(sc, 0x00, 0xb2, 0x05, 0x10 | 0x04, 0, NULL));
	tlv_free(docmd(sc, 0x00, 0xb2, 0x01, 0x18 | 0x04, 0, NULL));
	tlv_free(docmd(sc, 0x00, 0xb2, 0x02, 0x18 | 0x04, 0, NULL));


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
