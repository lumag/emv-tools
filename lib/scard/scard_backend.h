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

#ifdef ENABLE_SCARD_PCSC
struct sc *scard_pcsc_init(void);
#else
static inline struct sc *scard_pcsc_init(void)
{
	return NULL;
}
#endif

#ifdef ENABLE_SCARD_EMU
struct sc *scard_emu_init(void);
#else
static inline struct sc *scard_emu_init(void)
{
	return NULL;
}
#endif

#ifdef ENABLE_SCARD_APDUIO
struct sc *scard_apduio_t0_init(void);
#else
static inline struct sc *scard_apduio_t0_init(void)
{
	return NULL;
}
#endif

#endif
