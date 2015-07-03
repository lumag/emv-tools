#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "openemv/pinpad.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static bool pin_skip_char(char c)
{
	return c == '\n' || c == '\r' || c == ' ' || c == '\t' || c == '\v';
}

unsigned char *pinpad_enter(size_t *plen)
{
	char inbuf[17];
	char *p;
	size_t len, i;
	unsigned char *out;

	printf("Enter PIN: ");
	p = fgets(inbuf, sizeof(inbuf), stdin);

	if (!p)
		goto err;

	while (*p && pin_skip_char(*p))
		p++;

	len = 0;
	while (p[len] && p[len] >= '0' && p[len] <= '9')
		len++;

	i = 0;
	while (p[len + i] && pin_skip_char(p[len + i]))
		i++;

	if (p[len + i])
		goto err;

	if (!len)
		goto err;

	if (len < 4 || len > 12)
		goto err;

	out = malloc(8);

	out[0] = 0x20 | len;
	for (i = 0; i < 14; i += 2) {
		unsigned char c = 0;

		if (i < len)
			c |= p[i] - '0';
		else
			c |= 0xf;

		c <<= 4;

		if (i+1 < len)
			c |= p[i+1] - '0';
		else
			c |= 0xf;

		out[i/2 + 1] = c;
	}

	memset(inbuf, 0xff, sizeof(inbuf));
	*plen = 8;

	return out;

err:
	memset(inbuf, 0xff, sizeof(inbuf));
	*plen = 0;

	goto err;
}
