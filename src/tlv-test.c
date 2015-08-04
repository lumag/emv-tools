/*
 * emv-tools - a set of tools to work with EMV family of smart cards
 * Copyright (C) 2012, 2015 Dmitry Eremin-Solenikov
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "openemv/tlv.h"
#include "openemv/dump.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

static bool print_cb(void *data, const struct tlv *tlv)
{
	if (!tlv) {
		printf("NULL\n");
		return false;
	}
	printf("Tag %4hx %02zx:\n", tlv->tag, tlv->len);

	dump_buffer(tlv->value, tlv->len, stdout);

	return true;
}

static int parse_test(void) {
	struct {
		size_t len;
		const unsigned char buf[256];
		bool fail;
		tlv_tag_t tag;
		unsigned count;
	} tests[] = {
		{ 0x1c, {0x6f, 0x1a, 0x84, 0x0e, 0x31, 0x50, 0x41, 0x59, 0x2e, 0x53, 0x59, 0x53, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31, 0xa5, 0x08, 0x88, 0x01, 0x02, 0x5f, 0x2d, 0x02, 0x65, 0x6e}, false, 0x88, 1},
		{ 0x1b, {0x6f, 0x19, 0x84, 0x0e, 0x31, 0x50, 0x41, 0x59, 0x2e, 0x53, 0x59, 0x53, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31, 0xa5, 0x07, 0x88, 0x01, 0x02, 0x5f, 0x2d, 0x02, 0x65}, true, 0x88, 0},
		{ 0x1d, {0x6f, 0x1a, 0x84, 0x0e, 0x31, 0x50, 0x41, 0x59, 0x2e, 0x53, 0x59, 0x53, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31, 0xa5, 0x08, 0x88, 0x01, 0x02, 0x5f, 0x2d, 0x02, 0x65, 0x6e, 0x00}, true, 0x88, 0},
		{ 0x26, {0x6f, 0x24, 0x84, 0x0e, 0x31, 0x50, 0x41, 0x59, 0x2e, 0x53, 0x59, 0x53, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31, 0xa5, 0x08, 0x88, 0x01, 0x01, 0x5f, 0x2d, 0x02, 0x65, 0x6e, 0xa5, 0x08, 0x88, 0x01, 0x02, 0x5f, 0x2d, 0x02, 0x65, 0x6e}, false, 0x88, 2},
		{ 0x02, {0x70, 0x00}, false, 0x88, 0 },
		{ 0x02, {0x88, 0x00}, false, 0x88, 1 },
		{ 0x04, {0x9f, 0x02, 0x01, 0x01}, false, 0x9f02, 1},
	};
	struct tlvdb *t;
	const struct tlv *tlv;
	int i, j;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		printf("Test %d\n", i);
		t = tlvdb_parse(tests[i].buf, tests[i].len);
		if (tests[i].fail && t) {
			printf("Unexpected success\n");
			exit (1);
		}
		if (!tests[i].fail && !t) {
			printf("Unexpected failure\n");
			exit (1);
		}

		tlvdb_visit(t, print_cb, NULL);

		for (tlv = tlvdb_get(t, tests[i].tag, NULL), j = 0;
				tlv;
				tlv = tlvdb_get(t, tests[i].tag, tlv), j++) {
			print_cb(NULL, tlv);
		}
		if (j != tests[i].count) {
			printf("Unexpected amount of 0x%x tags (%d)\n", tests[i].tag, j);
			exit(1);
		}
		tlvdb_free(t);
	}

	return 0;
}

static int encode_test(void)
{
	struct {
		struct tlv tlv;
		size_t len;
		unsigned char *value;
	} tests[] = {
		{ {0x83, 0x00, NULL}, 2, (unsigned char *)"\x83\x00"},
		{ {0x83, 0x01, (unsigned char *)"Z"}, 3, (unsigned char *)"\x83\x01Z"},
		{ {0x83, 0x80, (unsigned char *)"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"}, 0x83, (unsigned char *)"\x83\x81\x80ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"},
		{ {0x9f02, 0x80, (unsigned char *)"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"}, 0x84, (unsigned char *)"\x9f\x02\x81\x80ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"},
	};

	int i;

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		printf("Encode Test %d\n", i);
		size_t len;
		unsigned char *out;

		out = tlv_encode(&tests[i].tlv, &len);
		if (len != tests[i].len) {
			printf("Len mismatch\n");
			exit(1);
		}

		if (memcmp(out, tests[i].value, len)) {
			printf("Data mismatch\n");
			exit(1);
		}

		free(out);
	}

	return 0;
}

int main(void)
{
	parse_test();
	encode_test();

	return 0;
}
