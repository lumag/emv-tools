#ifndef SC_HELPERS_H
#define SC_HELPERS_H

unsigned char *sc_command(struct sc *sc,
		unsigned char cla,
		unsigned char ins,
		unsigned char p1,
		unsigned char p2,
		size_t dlen,
		const unsigned char *data,
		unsigned short *psw,
		size_t *olen
		);

#endif
