#include <string.h>
#include <stdlib.h>

#include "scard.h"
#include "sc_helpers.h"

unsigned char *sc_command(struct sc *sc,
		unsigned char cla,
		unsigned char ins,
		unsigned char p1,
		unsigned char p2,
		size_t dlen,
	       	const unsigned char *data,
		unsigned short *psw,
		size_t *olen
		)
{
	unsigned char buf[4 + 1 + dlen];
	unsigned char cmdbuf[5] = {cla, ins, p1, p2, 0};
	unsigned short force_sw = 0;
	size_t opos = 0;
	size_t osize = 512;
	size_t ret;
	unsigned char *obuf;

	if ((dlen && !data) || !olen || !psw) {
		scard_raise_error(sc, SCARD_PARAMETER);
		*olen = 0;
		return NULL;
	}

	memcpy(buf, cmdbuf, 4);

	buf[4] = dlen;
	if (data != NULL) {
		memcpy(buf + 5, data, dlen);
	}

	obuf = malloc(osize);

	ret = scard_transmit(sc, buf, 5 + dlen, obuf + opos, osize - opos);
	if (scard_is_error(sc)) {
		free(obuf);
		*olen = 0;
		return NULL;
	}

	if (ret != 2) {
		scard_raise_error(sc, SCARD_CARD);
		free(obuf);
		*olen = 0;
		return NULL;
	}

	/* obuf + opos .. obuf + opos + ret - 1 contains last R-APDU with SW on the end */
	while (1) {
		unsigned short sw = (obuf[opos + ret - 2] << 8) |
				     obuf[opos + ret - 1];

		ret -= 2;
		opos += ret;

		if (sw == 0x9000) {
			*psw = force_sw ? : sw;
			*olen = opos;
			if (opos == 0) {
				free(obuf);
				obuf = NULL;
			}
			return obuf;
		}

		switch (sw & 0xff00) {
		case 0x6200:
		case 0x6300:
		case 0x9000 ... 0x9f00:
			force_sw = sw;
			sw = 0x6100;
			/* fallthrough */
		case 0x6100:
			cmdbuf[0] = 0x00;
			cmdbuf[1] = 0xc0;
			cmdbuf[2] = 0x00;
			cmdbuf[3] = 0x00;
			cmdbuf[4] = sw & 0xff;
			break;
		case 0x6c00:
			cmdbuf[4] = sw & 0xff;
			break;
		default:
			*olen = 0;
			*psw = sw;

			if (opos != 0) {
				scard_raise_error(sc, SCARD_CARD);
			}
			free(obuf);
			return NULL;
		}

		if (opos + cmdbuf[4] > osize) {
			scard_raise_error(sc, SCARD_CARD);
			free(obuf);
			*olen = 0;
			return NULL;
		}

		ret = scard_transmit(sc, cmdbuf, 5, obuf + opos, osize - opos);
		if (scard_is_error(sc)) {
			free(obuf);
			*olen = 0;
			return NULL;
		}
	}
}
