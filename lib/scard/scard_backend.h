#ifndef SCARD_BACKEND_H
#define SCARD_BACKEND_H

struct sc {
	void (*shutdown)(struct sc *sc);
	void (*connect)(struct sc *sc, unsigned idx);
	void (*disconnect)(struct sc *sc);
	size_t (*transmit)(struct sc *sc,
		const unsigned char *inbuf, size_t inlen,
		unsigned char *outbuf, size_t outlen);

	enum scard_proto proto;
	enum scard_error error;
};

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
        (type *)( (char *)__mptr - offsetof(type,member) );})

struct sc *scard_pcsc_init(void);

#endif
