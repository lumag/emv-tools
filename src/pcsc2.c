#include <stdio.h>
#include <stdlib.h>

#include "scard.h"

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

int main(void)
{
	struct sc *sc;
	unsigned char pbRecvBuffer[256];
	unsigned char cmd1[] = {
	       0x00, 0xa4, 0x04, 0x00,
	       0x0e,
	       0x31, 0x50, 0x41, 0x59, 0x2e, 0x53, 0x59, 0x53, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31,
	       0x00,
	};
	unsigned char cmd2[] = {
	       0x00, 0xa4, 0x04, 0x00,
	       0x07,
	       0xa0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10,
	       0x00,
	};
	size_t outlen;

	unsigned int i;

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

	outlen = scard_transmit(sc, cmd1, sizeof(cmd1), pbRecvBuffer, sizeof(pbRecvBuffer));
	if (scard_is_error(sc)) {
		printf(scard_error(sc));
		return 1;
	}
	printf("response: ");
	for(i=0; i<outlen; i++)
		printf("%02X ", pbRecvBuffer[i]);
	printf("\n");

	outlen = scard_transmit(sc, cmd2, sizeof(cmd2), pbRecvBuffer, sizeof(pbRecvBuffer));
	if (scard_is_error(sc)) {
		printf(scard_error(sc));
		return 1;
	}
	printf("response: ");
	for(i=0; i<outlen; i++)
		printf("%02X ", pbRecvBuffer[i]);
	printf("\n");

#if 0
	outlen = scard_transmit(sc, cmd3, sizeof(cmd3), pbRecvBuffer, sizeof(pbRecvBuffer));
	if (scard_is_error(sc)) {
		printf(scard_error(sc));
		return 1;
	}
	printf("response: ");
	for(i=0; i<outlen; i++)
		printf("%02X ", pbRecvBuffer[i]);
	printf("\n");
#endif

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
