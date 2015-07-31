#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "openemv/config.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <libconfig.h>

static config_t *_openemv_config;

static void openemv_init_config(void)
{
	config_t *config;
	int ret;
	const char *fname;

	config = malloc(sizeof(*_openemv_config));
	config_init(config);
	fname = getenv("OPENEMV_CONFIG");
	if (!fname)
		fname = OPENEMV_CONFIG_DIR "config.txt";
	ret = config_read_file(config, fname);
	if (ret != CONFIG_TRUE) {
		fprintf(stderr, "%s:%d: %s\n",
				config_error_file(config),
				config_error_line(config),
				config_error_text(config));
		config_destroy(config);
		free(config);
	} else
		_openemv_config = config;
}

const char *openemv_config_get(const char *path)
{
	const char *value;
	int ret;

	if (!_openemv_config)
		openemv_init_config();

	if (!_openemv_config)
		return NULL;

	ret = config_lookup_string(_openemv_config, path, &value);

	if (ret != CONFIG_TRUE)
		return NULL;

	return value;
}
