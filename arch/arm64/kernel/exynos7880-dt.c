/* SPDX-License-Identifier: GPL-2.0 */
/* Early A5/A7 identification using the bootloader's original /chosen. */
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/libfdt.h>
#include <linux/string.h>

#include "exynos7880-dt.h"

struct boot_value {
	const char *data;
	unsigned int length;
};

/* Reject duplicate identity arguments instead of choosing an arbitrary one. */
static int __init find_boot_value(const char *args, const char *key,
				 struct boot_value *value)
{
	unsigned int key_len = strlen(key);
	const char *start;

	value->data = NULL;
	while (*args) {
		while (isspace(*args))
			args++;
		start = args;
		while (*args && !isspace(*args))
			args++;
		if (args - start <= key_len ||
		    strncmp(start, key, key_len) || start[key_len] != '=')
			continue;
		if (value->data)
			return -EINVAL;
		value->data = start + key_len + 1;
		value->length = args - value->data;
	}

	return value->data && value->length ? 0 : -EINVAL;
}

static int __init parse_bootloader(const struct boot_value *value,
				  struct exynos7880_dt_board *board)
{
	unsigned int i;

	/* Family, regional suffix, then the alphanumeric firmware identifier. */
	if (value->length < 5 || value->length > 32)
		return -EINVAL;
	for (i = 0; i < value->length; i++)
		if (!isupper(value->data[i]) && !isdigit(value->data[i]))
			return -EINVAL;

	board->variant = value->data[4];
	if (!strncmp(value->data, "A520", 4) &&
	    strchr("FWKLS", board->variant))
		board->model = "a5y17lte";
	else if (!strncmp(value->data, "A720", 4) &&
		 strchr("FS", board->variant))
		board->model = "a7y17lte";
	else
		return -ENODEV;

	return 0;
}

static int __init parse_revision(const struct boot_value *value,
				unsigned int *revision)
{
	unsigned int i, number = 0;

	if (!value->length || value->length > 3)
		return -EINVAL;
	for (i = 0; i < value->length; i++) {
		if (!isdigit(value->data[i]))
			return -EINVAL;
		number = number * 10 + value->data[i] - '0';
	}
	if (number > 255)
		return -ERANGE;
	*revision = number;
	return 0;
}

/*
 * Return 1 for an identified bootstrap, 0 for an ordinary board DT, or a
 * negative error for an invalid bootstrap identity. Do not modify the FDT:
 * memory, initrd, reservations and other firmware changes remain intact.
 */
int __init exynos7880_dt_identify(const void *fdt,
				struct exynos7880_dt_board *board)
{
	struct exynos7880_dt_board identified;
	struct boot_value bootloader, revision;
	const char *args;
	int chosen, length, ret;

	ret = fdt_check_header(fdt);
	if (ret)
		return -EINVAL;
	ret = fdt_node_check_compatible(fdt, 0, "samsung,exynos7880-bootstrap");
	if (ret == 1 || ret == -FDT_ERR_NOTFOUND)
		return 0;
	if (ret)
		return -EINVAL;

	chosen = fdt_path_offset(fdt, "/chosen");
	if (chosen == -FDT_ERR_NOTFOUND)
		chosen = fdt_path_offset(fdt, "/chosen@0");
	if (chosen < 0)
		return -EINVAL;
	args = fdt_getprop(fdt, chosen, "bootargs", &length);
	if (!args || length <= 0 ||
	    strnlen(args, length) != length - 1)
		return -EINVAL;

	ret = find_boot_value(args, "androidboot.bootloader", &bootloader);
	if (ret)
		return ret;
	ret = find_boot_value(args, "androidboot.hw_rev", &revision);
	if (ret)
		return ret;
	ret = parse_bootloader(&bootloader, &identified);
	if (ret)
		return ret;
	ret = parse_revision(&revision, &identified.revision);
	if (ret)
		return ret;

	*board = identified;
	return 1;
}
