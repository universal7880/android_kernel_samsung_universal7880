/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __S6E3FA3_PANEL_PARAMS_H__
#define __S6E3FA3_PANEL_PARAMS_H__

#include "s6e3fa3_param.h"
#include "dynamic_aid_s6e3fa3_data.h"

static unsigned char SEQ_SLEEP_OUT[] = {
	0x11
};

static unsigned char SEQ_SLEEP_IN[] = {
	0x10
};

static unsigned char SEQ_DISPLAY_ON[] = {
	0x29
};

static unsigned char SEQ_DISPLAY_OFF[] = {
	0x28
};

static unsigned char SEQ_TEST_KEY_ON_F0[] = {
	0xF0,
	0x5A, 0x5A
};

static unsigned char SEQ_TEST_KEY_OFF_F0[] = {
	0xF0,
	0xA5, 0xA5
};

static unsigned char SEQ_TEST_KEY_ON_FC[] = {
	0xFC,
	0x5A, 0x5A
};

static unsigned char SEQ_TEST_KEY_OFF_FC[] = {
	0xFC,
	0xA5, 0xA5
};

static unsigned char SEQ_TE_ON[] = {
	0x35,
	0x00
};

static unsigned char SEQ_PCD_SET_DET_LOW[] = {
	0xCC,
	0x5C
};

static unsigned char SEQ_ERR_FG_SETTING[] = {
	0xED,
	0x44
};

static unsigned char SEQ_AVC_SETTING[] = {
	0xFD,
	0xA1, 0x20, 0x08, 0x04, 0x44, 0x00, 0x0C, 0x07,
	0x00, 0x00, 0xFF, 0x00, 0x0A, 0xAA, 0x0A, 0xAA,
	0x0A, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x5A, 0x80, 0x57, 0x65,
	0xA8			/* AVC -6.4V Setting */
};

static unsigned char SEQ_PARTIAL_MODE_ON[] = {
	0x12
};

static unsigned char SEQ_NORMAL_MODE_ON[] = {
	0x13
};

static unsigned char SEQ_PARTIAL_AREA_SETTING[] = {
	0x30,
	0x07, 0x7E, 0x07, 0x7F
};

static unsigned char SEQ_GAMMA_CONDITION_SET[] = {
	0xCA,
	0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0x00, 0x00, 0x00, 0x00, 0x00
};

static unsigned char SEQ_AID_SETTING[] = {
	0xB2,
	0x00, 0x14
};

static unsigned char SEQ_ELVSS_SET[] = {
	0xB6,
	0xBC,	/* B6h 1st Para: MPS_CON */
	0x0A,	/* B6h 2nd Para: ELVSS_Dim_offset */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00,
	0x00,	/* B6h 22nd Para: ELVSS Temp Compensation */
	0x00	/* B6h 23rd Para: OTP for B6h 22nd Para of HBM Interpolation */
};

static unsigned char SEQ_GAMMA_UPDATE[] = {
	0xF7,
	0x03
};

static unsigned char SEQ_ACL_OPR_OFF[] = {
	0xB5,
	0x40,	/* 16 Frame Avg. at ACL Off */
	0x7F,	/* Start Point 50% */
	0x14,
	0x14	/* ACL 15% */
};

static unsigned char SEQ_ACL_OPR_08P[] = {
	0xB5,
	0x50,	/* 32 Frame Avg. at ACL On */
	0x99,	/* Start Point 60% */
	0x14,
	0x0A	/* ACL 8% */
};

static unsigned char SEQ_ACL_OPR_15P[] = {
	0xB5,
	0x50,	/* 32 Frame Avg. at ACL On */
	0x7F,	/* Start Point 50% */
	0x14,
	0x14	/* ACL 15% */
};

static unsigned char SEQ_ACL_OFF[] = {
	0x55,
	0x00
};

static unsigned char SEQ_ACL_ON[] = {
	0x55,
	0x02	/* 0x02 : ACL 8% (Default) */
};

static unsigned char SEQ_TSET_SETTING[] = {
	0xB8,
	0x19	/* (ex) 25 degree : 0x19 */
};

static unsigned char SEQ_OSC_FREQ_ADJ[] = {
	0xCE,
	0x29, 0xD0, 0x4B, 0x4C,	/* 0x4B, 0x4C : 60.0Hz */
	0x4B, 0x38, 0x06, 0x03,
	0x00, 0xFF, 0x0A, 0x3F,
	0x3F, 0x3F, 0x3F
};

static const unsigned char SEQ_SELECT_60NIT_ON[] = {
	0x53,
	0x02			/* 0x02 : HLPM/ALPM 60nit On */
};

static const unsigned char SEQ_SELECT_02NIT_ON[] = {
	0x53,
	0x03			/* 0x03 : HLPM/ALPM 2nit On */
};

static const unsigned char SEQ_SRC_LOAD_EN_HLPM[] = {
	0xFD,
	0xA1, 0x20, 0x08, 0x04, 0x44, 0x00,
	0x8C,			/* 0x8C : HLPM */
	0x07, 0x00, 0x00, 0xFF, 0x00, 0x0A, 0xAA, 0x0A,
	0xAA, 0x0A, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x5A, 0x80, 0x57, 0x65, 0xA8,
	0x95, 0xA5, 0x04, 0x55, 0x05, 0x01, 0x01, 0x01
};

static const unsigned char SEQ_SRC_LOAD_EN_ALPM[] = {
	0xFD,
	0xA1, 0x20, 0x08, 0x04, 0x44, 0x00,
	0x0C,			/* 0x0C : ALPM */
	0x07, 0x00, 0x00, 0xFF, 0x00, 0x0A, 0xAA, 0x0A,
	0xAA, 0x0A, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x5A, 0x80, 0x57, 0x65, 0xA8,
	0x95, 0xA5, 0x04, 0x55, 0x05, 0x01, 0x01, 0x01
};

static const unsigned char SEQ_ALPM_OFF[] = {
	0x53,
	0x00
};

static const unsigned char SEQ_SRC_LOAD_EN_NORMAL[] = {
	0xFD,
	0xA1, 0x20, 0x08, 0x04, 0x44, 0x00,
	0x0C
};

static unsigned char *ACL_TABLE[ACL_STATUS_MAX] = {SEQ_ACL_OFF, SEQ_ACL_ON};

static unsigned char *OPR_TABLE[OPR_STATUS_MAX] = {SEQ_ACL_OPR_OFF, SEQ_ACL_OPR_08P, SEQ_ACL_OPR_15P};

static unsigned int brightness_opr_table[ACL_STATUS_MAX][EXTEND_BRIGHTNESS + 1] = {
	{
		[0 ... EXTEND_BRIGHTNESS]			= OPR_STATUS_OFF,
	}, {
		[0 ... 281]					= OPR_STATUS_15P,
		[282 ... EXTEND_BRIGHTNESS]			= OPR_STATUS_08P
	}
};

static unsigned int brightness_table[EXTEND_BRIGHTNESS + 1] = {
	[0 ... 0] =		IBRIGHTNESS_002NIT,
	[1 ... 4] =		IBRIGHTNESS_003NIT,
	[5 ... 8] =		IBRIGHTNESS_004NIT,
	[9 ... 12] =		IBRIGHTNESS_005NIT,
	[13 ... 16] =		IBRIGHTNESS_006NIT,
	[17 ... 20] =		IBRIGHTNESS_007NIT,
	[21 ... 24] =		IBRIGHTNESS_008NIT,
	[25 ... 28] =		IBRIGHTNESS_009NIT,
	[29 ... 32] =		IBRIGHTNESS_010NIT,
	[33 ... 36] =		IBRIGHTNESS_011NIT,
	[37 ... 40] =		IBRIGHTNESS_012NIT,
	[41 ... 43] =		IBRIGHTNESS_013NIT,
	[44 ... 46] =		IBRIGHTNESS_014NIT,
	[47 ... 48] =		IBRIGHTNESS_015NIT,
	[49 ... 50] =		IBRIGHTNESS_016NIT,
	[51 ... 52] =		IBRIGHTNESS_017NIT,
	[53 ... 54] =		IBRIGHTNESS_019NIT,
	[55 ... 56] =		IBRIGHTNESS_020NIT,
	[57 ... 58] =		IBRIGHTNESS_021NIT,
	[59 ... 60] =		IBRIGHTNESS_022NIT,
	[61 ... 62] =		IBRIGHTNESS_024NIT,
	[63 ... 64] =		IBRIGHTNESS_025NIT,
	[65 ... 66] =		IBRIGHTNESS_027NIT,
	[67 ... 68] =		IBRIGHTNESS_029NIT,
	[69 ... 70] =		IBRIGHTNESS_030NIT,
	[71 ... 72] =		IBRIGHTNESS_032NIT,
	[73 ... 74] =		IBRIGHTNESS_034NIT,
	[75 ... 76] =		IBRIGHTNESS_037NIT,
	[77 ... 78] =		IBRIGHTNESS_039NIT,
	[79 ... 80] =		IBRIGHTNESS_041NIT,
	[81 ... 82] =		IBRIGHTNESS_044NIT,
	[83 ... 84] =		IBRIGHTNESS_047NIT,
	[85 ... 86] =		IBRIGHTNESS_050NIT,
	[87 ... 88] =		IBRIGHTNESS_053NIT,
	[89 ... 90] =		IBRIGHTNESS_056NIT,
	[91 ... 92] =		IBRIGHTNESS_060NIT,
	[93 ... 94] =		IBRIGHTNESS_064NIT,
	[95 ... 96] =		IBRIGHTNESS_068NIT,
	[97 ... 98] =		IBRIGHTNESS_072NIT,
	[99 ... 100] =		IBRIGHTNESS_077NIT,
	[101 ... 102] =		IBRIGHTNESS_082NIT,
	[103 ... 104] =		IBRIGHTNESS_087NIT,
	[105 ... 106] =		IBRIGHTNESS_093NIT,
	[107 ... 108] =		IBRIGHTNESS_098NIT,
	[109 ... 110] =		IBRIGHTNESS_105NIT,
	[111 ... 112] =		IBRIGHTNESS_111NIT,
	[113 ... 114] =		IBRIGHTNESS_119NIT,
	[115 ... 116] =		IBRIGHTNESS_126NIT,
	[117 ... 118] =		IBRIGHTNESS_134NIT,
	[119 ... 120] =		IBRIGHTNESS_143NIT,
	[121 ... 122] =		IBRIGHTNESS_152NIT,
	[123 ... 124] =		IBRIGHTNESS_162NIT,
	[125 ... 126] =		IBRIGHTNESS_172NIT,
	[127 ... 128] =		IBRIGHTNESS_183NIT,
	[129 ... 135] =		IBRIGHTNESS_195NIT,
	[136 ... 142] =		IBRIGHTNESS_207NIT,
	[143 ... 149] =		IBRIGHTNESS_220NIT,
	[150 ... 157] =		IBRIGHTNESS_234NIT,
	[158 ... 165] =		IBRIGHTNESS_249NIT,
	[166 ... 174] =		IBRIGHTNESS_265NIT,
	[175 ... 183] =		IBRIGHTNESS_282NIT,
	[184 ... 193] =		IBRIGHTNESS_300NIT,
	[194 ... 201] =		IBRIGHTNESS_316NIT,
	[202 ... 210] =		IBRIGHTNESS_333NIT,
	[211 ... 219] =		IBRIGHTNESS_350NIT,
	[220 ... 223] =		IBRIGHTNESS_357NIT,
	[224 ... 227] =		IBRIGHTNESS_365NIT,
	[228 ... 230] =		IBRIGHTNESS_372NIT,
	[231 ... 234] =		IBRIGHTNESS_380NIT,
	[235 ... 238] =		IBRIGHTNESS_387NIT,
	[239 ... 242] =		IBRIGHTNESS_395NIT,
	[243 ... 246] =		IBRIGHTNESS_403NIT,
	[247 ... 250] =		IBRIGHTNESS_412NIT,
	[251 ... 281] =		IBRIGHTNESS_420NIT,
	[282 ... 295] =		IBRIGHTNESS_465NIT,
	[296 ... 309] =		IBRIGHTNESS_488NIT,
	[310 ... 323] =		IBRIGHTNESS_510NIT,
	[324 ... 336] =		IBRIGHTNESS_533NIT,
	[337 ... 350] =		IBRIGHTNESS_555NIT,
	[351 ... 364] =		IBRIGHTNESS_578NIT,
	[EXTEND_BRIGHTNESS ... EXTEND_BRIGHTNESS] =		IBRIGHTNESS_600NIT
};

#endif
