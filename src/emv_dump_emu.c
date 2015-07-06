#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "openemv/scard.h"
#include "openemv/sc_helpers.h"
#include "openemv/tlv.h"
#include "openemv/dol.h"
#include "openemv/dump.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const struct {
	size_t name_len;
	const unsigned char name[16];
} apps[] = {
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, }},
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x10, }},
	{ 7, {0xa0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10, }},
	{ 0, {}},
};

const tlv_tag_t card_data[] = {
	0x9f13,
	0x9f17,
	0x9f36,
	0x9f4f,
	0,
};

static void write_property(FILE *f, const char *name, const unsigned char *buf, size_t len)
{
	fprintf(f, "\t%s = <", name);
	dump_buffer_simple(buf, len, f);
	fprintf(f, ">;\n");
}

int main(int argc, char **argv)
{
	FILE *f;
	int i, j, k;
	struct tlvdb *s;
	struct sc *sc;
	unsigned short sw;
	size_t outlen;
	unsigned char *outbuf;

	if (argc == 1 || !strcmp(argv[1], "-"))
		f = stdout;
	else
		f = fopen(argv[1], "w");
	if (!f) {
		perror("fopen");
		return 1;
	}

	sc = scard_init("pcsc");
	if (!sc) {
		printf("Cannot init scard\n");
		return 1;
	}

	scard_connect(sc, 0);
	if (scard_is_error(sc)) {
		printf("%s\n", scard_error(sc));
		return 1;
	}

	for (i = 0; apps[i].name_len != 0; i++) {
		outbuf = sc_command(sc, 0x00, 0xa4, 0x04, 0x00, apps[i].name_len, apps[i].name, &sw, &outlen);
		if (sw == 0x9000)
			break;
	}

	if (!apps[i].name_len)
		return 1;

	s = tlvdb_parse(outbuf, outlen);
	if (!s)
		return 1;

	struct tlv pdol_data_tlv;
	size_t pdol_data_len;
	unsigned char *pdol_data;

	pdol_data_tlv.tag = 0x83;
	pdol_data_tlv.value = dol_process(tlvdb_get(s, 0x9f38, NULL), s, &pdol_data_tlv.len);
	pdol_data = tlv_encode(&pdol_data_tlv, &pdol_data_len);
	if (!pdol_data)
		return 1;
	free((unsigned char *)pdol_data_tlv.value);

	tlvdb_free(s);

	fprintf(f, "{\n");

	write_property(f, "name", apps[i].name, apps[i].name_len);

	write_property(f, "fci", outbuf, outlen);
	free(outbuf);

	outbuf = sc_command(sc, 0x80, 0xa8, 0x00, 0x00, pdol_data_len, pdol_data, &sw, &outlen);
	free(pdol_data);
	if (sw != 0x9000)
		return 0;

	write_property(f, "gpo", outbuf, outlen);
	free(outbuf);

	fprintf(f, "\n");

	for (i = 1; i < 31; i++) {
		int last = 0;
		for (j = 1; j < 256; j++) {
			outbuf = sc_command(sc, 0x00, 0xb2, j, (i << 3) | 4, 0, NULL, &sw, &outlen);
			if (sw == 0x6985)
				continue;
			else if (sw != 0x9000)
				break;

			if (last == 0) {
				fprintf(f, "\tsfi%-2d = <", i);
				last++;
			}

			for (; last < j; last++)
				fprintf(f, ">,\n\t\t<");

			for (k = 0; k < outlen; k += 16) {
				dump_buffer_simple(outbuf + k,
						k + 16 < outlen ? 16 : outlen - k,
						f);
				if (k + 16 < outlen)
					fprintf(f, "\n\t\t ");
			}

			free(outbuf);
		}
		if (last != 0)
			fprintf(f, ">;\n");
	}

	fprintf(f, "\n");

	for (i = 0; card_data[i]; i++) {
		tlv_tag_t tag = card_data[i];
		outbuf = sc_command(sc, 0x80, 0xca, tag >> 8, tag & 0xff, 0, NULL, &sw, &outlen);
		if (sw != 0x9000)
			continue;

		fprintf(f, "\tdata%-4x = <", tag);
		dump_buffer_simple(outbuf, outlen, f);
		fprintf(f, ">;\n");

		free(outbuf);
	}

	fprintf(f, "};\n");

	fclose(f);

	scard_disconnect(sc);
	if (scard_is_error(sc)) {
		printf("%s\n", scard_error(sc));
		return 1;
	}
	scard_shutdown(sc);

	return 0;
}
