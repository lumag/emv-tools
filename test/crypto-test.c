/*
 * emv-tools - a set of tools to work with EMV family of smart cards
 * Copyright (C) 2015 Dmitry Eremin-Solenikov
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

#include "openemv/crypto.h"
#include "openemv/dump.h"

#include <stdlib.h>
#include <string.h>

static int test_genkey(unsigned int keylength, unsigned char *msg, size_t msg_len)
{
	int ret = 1;
	size_t tmp_len, tmp2_len;
	unsigned char *tmp, *tmp2;
	struct crypto_pk *pk;

	pk = crypto_pk_genkey(PK_RSA, 1, keylength, 3);
	if (!pk)
		goto out;

	tmp = crypto_pk_decrypt(pk, msg, msg_len, &tmp_len);
	if (!tmp)
		goto close;

	tmp2 = crypto_pk_encrypt(pk, tmp, tmp_len, &tmp2_len);
	if (!tmp2)
		goto free_tmp;

	if (tmp2_len == msg_len && !memcmp(tmp2, msg, tmp2_len))
		ret = 0;

	free(tmp2);
free_tmp:
	free(tmp);
close:
	crypto_pk_close(pk);

out:
	return ret;
}

static unsigned char message[4096 / 8] =
	"aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb"
	"ccccccccccccccccdddddddddddddddd"
	"eeeeeeeeeeeeeeeeffffffffffffffff"
	"gggggggggggggggghhhhhhhhhhhhhhhh"
	"iiiiiiiiiiiiiiiijjjjjjjjjjjjjjjj"
	"kkkkkkkkkkkkkkkkllllllllllllllll"
	"mmmmmmmmmmmmmmmmnnnnnnnnnnnnnnnn"
	"oooooooooooooooopppppppppppppppp"
	"qqqqqqqqqqqqqqqqrrrrrrrrrrrrrrrr"
	"sssssssssssssssstttttttttttttttt"
	"uuuuuuuuuuuuuuuuvvvvvvvvvvvvvvvv"
	"wwwwwwwwwwwwwwwwxxxxxxxxxxxxxxxx"
	"yyyyyyyyyyyyyyyyzzzzzzzzzzzzzzzz"
	"aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb"
	"ccccccccccccccccdddddddddddddddd"
	"eeeeeeeeeeeeeeeeffffffffffffffff"
	;

int main(void)
{
	unsigned int keylengths[] = {1024, 1152, 1408, 1984, 2048/*, 3072, 4096*/};
	int i;

	for (i = 0; i < sizeof(keylengths) / sizeof(keylengths[0]); i++) {
		unsigned int kl = keylengths[i];
		int ret;
		printf("Testing key length %d\n", kl);
		ret = test_genkey(kl, message, kl / 8);
		if (ret)
			return ret;
	}

	return 0;
}
