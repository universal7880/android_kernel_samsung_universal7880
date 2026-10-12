/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __S6E3FA3_PARAM_H__
#define __S6E3FA3_PARAM_H__

#include <linux/types.h>
#include <linux/bug.h>
#include <linux/kernel.h>
#include "dynamic_aid_s6e3fa3.h"

#define EXTEND_BRIGHTNESS	365
#define UI_MAX_BRIGHTNESS	255
#define UI_DEFAULT_BRIGHTNESS	128
#define NORMAL_TEMPERATURE	25	/* 25 degrees Celsius */

#define GAMMA_CMD_CNT	36
#define ACL_CMD_CNT	2
#define OPR_CMD_CNT	5
#define ELVSS_CMD_CNT	24
#define AID_CMD_CNT	3
#define TSET_CMD_CNT	2
#define LDI_REG_ELVSS				0xB6
#define LDI_REG_COORDINATE			0xA1
#define LDI_REG_DATE				LDI_REG_MTP
#define LDI_REG_ID					0x04
#define LDI_REG_CHIP_ID				0xD6
#define LDI_REG_MTP					0xC8
#define LDI_REG_HBM					0xB4
#define LDI_REG_RDDPM				0x0A
#define LDI_REG_RDDSM				0x0E
#define LDI_REG_ESDERR				0xEE
#define LDI_REG_MANUFACTURE_INFO	0xC9

/* len is read length */
#define LDI_LEN_ELVSS				(ELVSS_CMD_CNT - 1)
#define LDI_LEN_COORDINATE			4
#define LDI_LEN_DATE				7
#define LDI_LEN_ID					3
#define LDI_LEN_CHIP_ID				5
#define LDI_LEN_MTP					35
#define LDI_LEN_HBM					28
#define LDI_LEN_RDDPM				1
#define LDI_LEN_RDDSM				1
#define LDI_LEN_ESDERR				1
#define LDI_LEN_MANUFACTURE_INFO	20

/* offset is position including addr, not only para */
#define LDI_OFFSET_AOR_1	1
#define LDI_OFFSET_AOR_2	2

#define LDI_OFFSET_ELVSS_1	1	/* B6h 1st Para: MPS_CON */
#define LDI_OFFSET_ELVSS_2	2	/* B6h 2nd Para: ELVSS_Dim_offset */
#define LDI_OFFSET_ELVSS_3	22	/* B6h 22nd Para: ELVSS Temp Compensation */

#define LDI_OFFSET_OPR_1	1	/* B5h 1st Para: Frame Avg. */
#define LDI_OFFSET_OPR_2	2	/* B5h 2nd Para: Start Point */
#define LDI_OFFSET_OPR_3	4	/* B5h 22nd Para: ACL Percent */

#define LDI_OFFSET_ACL		1
#define LDI_OFFSET_TSET		1

#define LDI_GPARA_DATE		40	/* 0xC8 41st Para */
#define LDI_GPARA_HBM_ELVSS	22	/* 0xB6 23th para */
#define LDI_GPARA_MANUFACTURE_INFO	1	/* C9h 2nd Para */

struct lcd_seq_info {
	unsigned char	*cmd;
	unsigned int	len;
	unsigned int	sleep;
};

#ifdef CONFIG_LCD_DOZE_MODE
enum {
	ALPM_OFF,
	ALPM_ON_LOW,	/* ALPM 2 NIT */
	HLPM_ON_LOW,	/* HLPM 2 NIT */
	ALPM_ON_HIGH,	/* ALPM 60 NIT */
	HLPM_ON_HIGH,	/* HLPM 60 NIT */
	ALPM_MODE_MAX
};

#endif

enum {
	ACL_STATUS_OFF,
	ACL_STATUS_ON,
	ACL_STATUS_MAX
};

enum {
	OPR_STATUS_OFF,
	OPR_STATUS_08P,
	OPR_STATUS_15P,
	OPR_STATUS_MAX
};

enum {
	CAPS_OFF,
	CAPS_ON,
	CAPS_MAX
};

enum {
	TEMP_ABOVE_MINUS_00_DEGREE,	/* T > 0 */
	TEMP_ABOVE_MINUS_15_DEGREE,	/* -15 < T <= 0 */
	TEMP_BELOW_MINUS_15_DEGREE,	/* T <= -15 */
	TEMP_MAX
};

/* platform brightness <-> acl opr and percent */

/* platform brightness <-> gamma level */

#endif /* __S6E3FA3_PARAM_H__ */
