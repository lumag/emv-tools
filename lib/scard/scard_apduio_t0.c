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

#define TLP224_EOT	0x03
#define TLP224_ACK	0x60

#define TLP224_CMD_POWER_UP 0x6e
#define TLP224_CMD_POWER_DOWN 0x4d
#define TLP224_CMD_ISO_INPUT 0xda
#define TLP224_CMD_ISO_OUTPUT 0xdb

#define TLP224_STATUS_OK 0x00
#define TLP224_STATUS_SW 0xE7

static unsigned char dig_to_hex(unsigned char d)
{
	return d < 10 ? d + '0' : d - 10 + 'A';
}

#define tlp224_put(c) 					\
	do {						\
		unsigned char __tmp = (c);		\
		lrc ^= __tmp;				\
		tmpbuf[i++] = dig_to_hex(__tmp >> 4);		\
		tmpbuf[i++] = dig_to_hex(__tmp & 0xf);		\
	} while (0)

static ssize_t tlp224_send(int sd, unsigned char cmd, const unsigned char *buf, size_t len)
{
	unsigned char tmpbuf[2 * (len + 3) + 1];
	unsigned char lrc = 0x0;
	int i = 0, j;

	if (len > 255) {
		errno = -E2BIG;
		return -1;
	}

	tlp224_put(TLP224_ACK);
	tlp224_put((unsigned char) (len + 1));
	tlp224_put(cmd);
	for (j = 0; j < len; j++)
		tlp224_put(buf[j]);
	tlp224_put(lrc);
	tmpbuf[i++] = TLP224_EOT;

	return send(sd, tmpbuf, i, 0);
}

static ssize_t tlp224_recv(int sd, unsigned char *status, unsigned char *buf, size_t len)
{
	unsigned char tmpbuf[2 * (258 + 4) +1];
	ssize_t tmplen;
	unsigned char lrc = 0;
	int i;

	tmplen = recv(sd, tmpbuf, sizeof(tmpbuf), 0);
	if (tmplen < 0)
		return tmplen;

	if (tmpbuf[tmplen-1] != TLP224_EOT || tmplen % 2 != 1) {
		errno = -EINVAL;
		return -1;
	}

	tmplen --;
	for (i = 0; i < tmplen / 2; i++) {
		unsigned char c;
		unsigned char d = 0;

		c = tmpbuf[2 * i];
		if (c >= 'A' && c <= 'F')
			d |= c - 'A' + 10;
		else if (c >= 'a' && c <= 'f')
			d |= c - 'a' + 10;
		else if (c >= '0' && c <= '9')
			d |= c - '0';
		else {
			errno = -EINVAL;
			return -1;
		}

		d <<= 4;

		c = tmpbuf[2 * i + 1];
		if (c >= 'A' && c <= 'F')
			d |= c - 'A' + 10;
		else if (c >= 'a' && c <= 'f')
			d |= c - 'a' + 10;
		else if (c >= '0' && c <= '9')
			d |= c - '0';
		else {
			errno = -EINVAL;
			return -1;
		}

		tmpbuf[i] = d;
	}
	tmplen /= 2;
	for (i = 0; i < tmplen; i++)
		lrc ^= tmpbuf[i];

	if (tmpbuf[0] != TLP224_ACK || tmplen != tmpbuf[1] + 3 || lrc != 0) {
		errno = -EIO;
		return -1;
	}

	tmplen -= 4;
	if (tmplen > len) {
		errno = -E2BIG;
		return -1;
	}

	*status = tmpbuf[2];

	if (buf)
		memcpy(buf, tmpbuf + 3, tmplen);

	return tmplen;
}


struct sc_apduio_t0 {
	struct sc sc;
	int sd;
};

static void scard_apduio_t0_connect(struct sc *_sc, unsigned idx)
{
	struct sc_apduio_t0 *sc = container_of(_sc, struct sc_apduio_t0, sc);
	struct sockaddr_in sa;
	int ret;
	unsigned char status;
	unsigned char buf[258];
	size_t i;

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

	i = 0;
	buf[i++] = 0;
	buf[i++] = 0;
	buf[i++] = 0;
	ret = tlp224_send(sc->sd, TLP224_CMD_POWER_UP, buf, i);
	if (ret < 0) {
		perror("tlp224_send");
		scard_raise_error(_sc, SCARD_CARD);
		return;
	}

	ret = tlp224_recv(sc->sd, &status, buf, sizeof(buf));
	if (ret < 0) {
		perror("tlp224_recv");
		scard_raise_error(_sc, SCARD_CARD);
		return;
	}

	if (ret < 3 || status != TLP224_STATUS_OK) {
		scard_raise_error(_sc, SCARD_CARD);
		return;
	}

	/* We ignore ATR for now -- it comes after 3 additional bytes,
	 * with third of them being ATR length. */

	_sc->proto = SCARD_PROTO_T0;
	_sc->error = SCARD_NO_ERROR;
}

static void scard_apduio_t0_disconnect(struct sc *_sc)
{
	struct sc_apduio_t0 *sc = container_of(_sc, struct sc_apduio_t0, sc);
	int ret;
	unsigned char status;

	_sc->proto = SCARD_PROTO_INVALID;
	_sc->error = SCARD_NO_ERROR;

	ret = tlp224_send(sc->sd, TLP224_CMD_POWER_DOWN, NULL, 0);
	if (ret < 0) {
		perror("tlp224_send");
		scard_raise_error(_sc, SCARD_CARD);
		return;
	}

	ret = tlp224_recv(sc->sd, &status, NULL, 0);
	if (ret < 0) {
		perror("tlp224_recv");
		scard_raise_error(_sc, SCARD_CARD);
		return;
	}

	if (status != TLP224_STATUS_OK) {
		scard_raise_error(_sc, SCARD_CARD);
		return;
	}

	shutdown(sc->sd, SHUT_RDWR);
	close(sc->sd);
	sc->sd = -1;
}

static void scard_apduio_t0_shutdown(struct sc *_sc)
{
	struct sc_apduio_t0 *sc = container_of(_sc, struct sc_apduio_t0, sc);

	if (sc->sd != -1)
		scard_apduio_t0_disconnect(_sc);
	free(sc);
}

static size_t scard_apduio_t0_transmit(struct sc *_sc,
		const unsigned char *inbuf, size_t inlen,
		unsigned char *outbuf, size_t outlen)
{
	struct sc_apduio_t0 *sc = container_of(_sc, struct sc_apduio_t0, sc);
	ssize_t ret;

	if (outlen < 2 || inlen < 4) {
		scard_raise_error(_sc, SCARD_PARAMETER);
		return 0;
	}

	if (sc->sd == -1) {
		scard_raise_error(_sc, SCARD_PARAMETER);
		return 0;
	}

	ret = tlp224_send(sc->sd, inlen > 5 ? TLP224_CMD_ISO_INPUT : TLP224_CMD_ISO_OUTPUT, inbuf, inlen);
	if (ret < 0) {
		perror("tlp224_send");
		scard_raise_error(_sc, SCARD_CARD);
		return 0;
	}

	unsigned char status;

	ret = tlp224_recv(sc->sd, &status, outbuf, outlen);
	if (ret < 0) {
		perror("recv");
		return 0;
	}

	return ret;
}

struct sc *scard_apduio_t0_init(void)
{
	struct sc_apduio_t0 *sc = malloc(sizeof(*sc));

	sc->sd = -1;
	sc->sc.proto = SCARD_PROTO_INVALID;
	sc->sc.shutdown = scard_apduio_t0_shutdown;
	sc->sc.connect = scard_apduio_t0_connect;
	sc->sc.disconnect = scard_apduio_t0_disconnect;
	sc->sc.transmit = scard_apduio_t0_transmit;

	return &sc->sc;
}
