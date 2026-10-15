/* sec_bsp.c
 *
 * Copyright (C) 2016 Samsung Electronics
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

/* sec_debug supplies this symbol when SEC_HW_REV is enabled. */
#ifndef CONFIG_SEC_HW_REV
int board_id;
EXPORT_SYMBOL(board_id);

static int board_id_setup(char *str)
{
	int n;
	if (!get_option(&str, &n))
		return 0;
	board_id = n;

	return 1;
}
__setup("androidboot.revision=", board_id_setup);
#endif
