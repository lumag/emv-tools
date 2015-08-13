/*
 * libopenemv - a library to work with EMV family of smart cards
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

#include "openemv/scard.h"
#include "openemv/dump.h"

#include "scard_backend.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define T1_CMD_POWER_UP 0xf0
#define T1_CMD_POWER_DOWN 0xe0
#define T1_CMD_BLOCK 0x80

#define T1_I_SEQ 0x40
#define T1_I_MORE 0x20
#define T1_R_SEQ 0x10

struct sc_apduio_t1 {
	struct sc sc;
	int sd;
	unsigned char nad;
	size_t ifsc, ifsd;
	bool seqc, seqd;
};

static unsigned char compute_lrc(const unsigned char *buf, size_t len)
{
	size_t i;
	unsigned char lrc = 0;

	for (i = 0; i < len; i++)
		lrc ^= buf[i];

	return lrc;
}

static ssize_t apduio_t1_send(int sd, unsigned char cmd, const unsigned char *buf, size_t len)
{
	ssize_t ret;
	size_t tmplen, pos;
	unsigned char tmpbuf[len + 4];

	tmpbuf[0] = cmd;
	tmpbuf[1] = (len >> 8) & 0xff;
	tmpbuf[2] = len & 0xff;
	memcpy(tmpbuf + 3, buf, len);

	tmplen = len + 3;
	tmpbuf[tmplen] = compute_lrc(tmpbuf, tmplen);
	tmplen ++;

	for (pos = 0; pos < tmplen; pos += ret) {
		ret = send(sd, tmpbuf + pos, tmplen - pos, 0);
		if (ret < 0)
			return ret;

	}

	return pos;
}

static ssize_t apduio_t1_recv(int sd, unsigned char *cmd, unsigned char *buf, size_t len)
{
	unsigned char tmpbuf[4 + len];
	size_t blocklen;
	ssize_t tmplen, pos, ret;

	tmplen = recv(sd, tmpbuf, 3, 0);
	if (tmplen != 3) {
		errno = EPIPE;
		return -1;
	}

	blocklen = (tmpbuf[1] << 8) | tmpbuf[2];
	if (blocklen > len) {
		errno = E2BIG;
		return -1;
	}

	for (pos = 0; pos < blocklen + 1; pos += ret) {
		ret = recv(sd, tmpbuf + tmplen + pos, blocklen + 1 - pos, 0);
		if (ret < 0)
			return ret;
	}

	tmplen += pos;

	if (compute_lrc(tmpbuf, tmplen) != 0) {
		fprintf(stdout, "LRC error!\n");
		errno = EIO;
		return -1;
	}

	*cmd = tmpbuf[0];
	if (blocklen > len) {
		errno = E2BIG;
		return -1;
	}

	memcpy(buf, tmpbuf + 3, blocklen);

	return blocklen;
}

static ssize_t block_t1_send(int sd, unsigned char NAD, unsigned char PCB, const unsigned char *buf, size_t len)
{
	unsigned char tmpbuf[len+4];
	size_t tmplen;

	tmpbuf[0] = NAD;
	tmpbuf[1] = PCB;
	tmpbuf[2] = len & 0xff;

	memcpy(tmpbuf + 3, buf, len);
	tmplen = len + 3;

	tmpbuf[tmplen] = compute_lrc(tmpbuf, tmplen);
	tmplen ++;

	return apduio_t1_send(sd, T1_CMD_BLOCK, tmpbuf, tmplen);
}

static ssize_t block_t1_recv(int sd, unsigned char *NAD, unsigned char *PCB, unsigned char *buf, size_t len)
{
	unsigned char tmpbuf[259];
	ssize_t tmplen;
	unsigned char cmd;

	tmplen = apduio_t1_recv(sd, &cmd, tmpbuf, sizeof(tmpbuf));
	if (tmplen < 0)
		return tmplen;

	if (compute_lrc(tmpbuf, tmplen) != 0) {
		fprintf(stdout, "LRC error!\n");
		errno = EIO;
		return -1;
	}

	*NAD = tmpbuf[0];
	*PCB = tmpbuf[1];
	if (len < tmpbuf[2]) {
		errno = E2BIG;
		return -1;
	}
	memcpy(buf, tmpbuf + 3, tmpbuf[2]);

	return tmpbuf[2];
}

static void scard_apduio_t1_connect(struct sc *_sc, unsigned idx)
{
	struct sc_apduio_t1 *sc = container_of(_sc, struct sc_apduio_t1, sc);
	struct sockaddr_in sa;
	int ret;
	unsigned char buf[258];
	unsigned char cmd;

	if (idx || sc->sd != -1) {
		scard_raise_error(_sc, SCARD_PARAMETER);
		return;
	}

	sc->sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sc->sd < 0) {
		perror("socket");
		scard_raise_error(_sc, SCARD_CARD);
		return;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(9025);
	ret = inet_aton("127.0.0.1", &sa.sin_addr);
	if (ret != 1) {
		fprintf(stderr, "inet_aton: unknown error\n");
		scard_raise_error(_sc, SCARD_CARD);
		return;
	}

	ret = connect(sc->sd, (struct sockaddr *)&sa, sizeof(sa));
	if (ret) {
		perror("connect");
		scard_raise_error(_sc, SCARD_CARD);
		return;
	}

	sc->nad = 0;
	sc->ifsc = sc->ifsd = 32;
	sc->seqc = sc->seqd = 0;

	ret = apduio_t1_send(sc->sd, T1_CMD_POWER_UP, NULL, 0);
	if (ret < 0) {
		perror("send");
		scard_raise_error(_sc, SCARD_CARD);
		return;
	}

	ret = apduio_t1_recv(sc->sd, &cmd, buf, sizeof(buf));
	if (ret < 0) {
		perror("recv");
		scard_raise_error(_sc, SCARD_CARD);
		return;
	}

	/* We ignore ATR for now. */

	_sc->proto = SCARD_PROTO_T1;
	_sc->error = SCARD_NO_ERROR;
}

static void scard_apduio_t1_disconnect(struct sc *_sc)
{
	struct sc_apduio_t1 *sc = container_of(_sc, struct sc_apduio_t1, sc);
	int ret;

	_sc->proto = SCARD_PROTO_INVALID;
	_sc->error = SCARD_NO_ERROR;

	ret = apduio_t1_send(sc->sd, T1_CMD_POWER_DOWN, NULL, 0);
	if (ret < 0) {
		perror("send");
		scard_raise_error(_sc, SCARD_CARD);
		return;
	}

	shutdown(sc->sd, SHUT_RDWR);
	close(sc->sd);
	sc->sd = -1;
}

static void scard_apduio_t1_shutdown(struct sc *_sc)
{
	struct sc_apduio_t1 *sc = container_of(_sc, struct sc_apduio_t1, sc);

	if (sc->sd != -1)
		scard_apduio_t1_disconnect(_sc);
	free(sc);
}

static size_t scard_apduio_t1_transmit(struct sc *_sc,
		const unsigned char *inbuf, size_t inlen,
		unsigned char *outbuf, size_t outlen)
{
	struct sc_apduio_t1 *sc = container_of(_sc, struct sc_apduio_t1, sc);

	if (outlen < 2 || inlen < 4) {
		scard_raise_error(_sc, SCARD_PARAMETER);
		return 0;
	}

	if (sc->sd == -1) {
		scard_raise_error(_sc, SCARD_PARAMETER);
		return 0;
	}

	size_t pos = 0, opos = 0;
	size_t tmplen = 258;
	unsigned char tmpbuf[tmplen];

	enum { T1_BLOCK_I, T1_BLOCK_R, T1_BLOCK_S } next_block = T1_BLOCK_I;
	unsigned char pcb;
	size_t tlen;
	const unsigned char *tbuf;

	while (1) {
		ssize_t ret;
		unsigned char rnad;

		if (next_block == T1_BLOCK_I) {
			pcb = (sc->seqd ? T1_I_SEQ : 0) | (pos + sc->ifsc < inlen ? T1_I_MORE : 0);
			tlen = (pos + sc->ifsc < inlen) ? sc->ifsc : (inlen - pos);
			tbuf = inbuf + pos;
		} else if (next_block == T1_BLOCK_R) {
			pcb = 0x80 | (sc->seqc ? T1_R_SEQ : 0);
			tlen = 0;
			tbuf = NULL;
		}

		ret = block_t1_send(sc->sd, sc->nad, pcb, tbuf, tlen);
		if (ret < 0) {
			perror("send");
			scard_raise_error(&sc->sc, SCARD_CARD);
			return 0;
		}

		ret = block_t1_recv(sc->sd, &rnad, &pcb, tmpbuf, tmplen);
		if (ret < 0) {
			perror("recv");
			scard_raise_error(&sc->sc, SCARD_CARD);
			return 0;
		}

		if (rnad != sc->nad) {
			fprintf(stdout, "Wrong NAD!\n");
			scard_raise_error(&sc->sc, SCARD_CARD);
			return 0;
		}

		if (pcb & 0x80) {
			if (pcb & 0x40) {
				/* S-Block */
				fprintf(stdout, "Ignoring S-block!\n");

				next_block = T1_BLOCK_S;
				pcb |= 0x20;
				tbuf = tmpbuf;
				tlen = ret;
			} else  {
				/* R-Block */
				next_block = T1_BLOCK_I;

				if (!(pcb & T1_R_SEQ) != !sc->seqd) {
					pos += tlen;
					sc->seqd = !sc->seqd;
				}
			}
		} else {
			/* I-Block */
			next_block = T1_BLOCK_R;

			if (!(pcb & T1_I_SEQ) == !sc->seqc) {
				pos += tlen;
				sc->seqc = !sc->seqc;

				if (opos + ret > outlen) {
					fprintf(stdout, "Overflow!\n");
					ret = outlen - opos;
				}
				memcpy(outbuf + opos, tmpbuf, ret);
				opos += ret;

				if (!(pcb & T1_I_MORE)) {
					sc->seqd = !sc->seqd;

					return opos;
				}
			}
		}
	}
}

struct sc *scard_apduio_t1_init(void)
{
	struct sc_apduio_t1 *sc = malloc(sizeof(*sc));

	sc->sd = -1;
	sc->sc.proto = SCARD_PROTO_INVALID;
	sc->sc.shutdown = scard_apduio_t1_shutdown;
	sc->sc.connect = scard_apduio_t1_connect;
	sc->sc.disconnect = scard_apduio_t1_disconnect;
	sc->sc.transmit = scard_apduio_t1_transmit;

	return &sc->sc;
}
