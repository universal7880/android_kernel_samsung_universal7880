/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __S6E3FA3_PANEL_H__
#define __S6E3FA3_PANEL_H__

#include "s6e3fa3_param.h"

struct mdnie_tune;

struct s6e3fa3_panel_seq {
	const unsigned char *cmd;
	unsigned int len;
};

struct s6e3fa3_panel_data {
	const char *model;
	const int (*m_gray)[IV_MAX];
	const int (*offset_color)[CI_MAX * IV_MAX];
	unsigned char (*elvss)[3];
	unsigned char (*aor)[AID_CMD_CNT];
	struct s6e3fa3_panel_seq hlpm_60;
	struct s6e3fa3_panel_seq hlpm_02;
	struct s6e3fa3_panel_seq alpm_60;
	struct s6e3fa3_panel_seq alpm_02;
	struct mdnie_tune *mdnie;
};

extern const struct s6e3fa3_panel_data s6e3fa3_a5y17_panel;
extern const struct s6e3fa3_panel_data s6e3fa3_a7y17_panel;

#endif
