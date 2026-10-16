/*
 * Samsung Exynos5 SoC series Sensor driver
 *
 *
 * Copyright (c) 2016 Samsung Electronics Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define MAX_3P8_SETPIN_CNT 2

enum sensor_module_3p8_actuator {
	SENSOR_MODULE_3P8_WITHOUT_ACTUATOR = 0,
	SENSOR_MODULE_3P8_WITH_ACTUATOR = 1,
};

static int sensor_module_3p8_power_setpin_with_af(struct platform_device *pdev,
	struct exynos_platform_fimc_is_module *pdata)
{
	struct device *dev;
	struct device_node *dnode;
	int gpio_reset = 0;
	int gpio_mclk = 0;
	int gpio_none = 0;
	int gpio_core_en = 0;
	int gpio_cam_avdd_en = 0;
	int gpio_cam_af_en = 0;
	int gpio_cam_io_en = 0;

#if defined (CONFIG_OIS_USE)
	int gpio_ois_reset = 0;
	int gpio_ois_core_en = 0;
	int gpio_ois_io_en = 0;
#endif

	BUG_ON(!pdev);

	dev = &pdev->dev;
	dnode = dev->of_node;

	dev_info(dev, "%s E v4\n", __func__);

	gpio_reset = of_get_named_gpio(dnode, "gpio_reset", 0);
	if (!gpio_is_valid(gpio_reset)) {
		dev_err(dev, "failed to get PIN_RESET\n");
		return -EINVAL;
	} else {
		gpio_request_one(gpio_reset, GPIOF_OUT_INIT_LOW, "CAM_GPIO_OUTPUT_LOW");
		gpio_free(gpio_reset);
	}

	gpio_core_en = of_get_named_gpio(dnode, "gpio_core_en", 0);
	if (!gpio_is_valid(gpio_core_en)) {
		dev_err(dev, "failed to get gpio_core_en\n");
	} else {
		gpio_request_one(gpio_core_en, GPIOF_OUT_INIT_LOW, "CAM_GPIO_OUTPUT_LOW");
		gpio_free(gpio_core_en);
	}

	gpio_mclk = of_get_named_gpio(dnode, "gpio_mclk", 0);
	if (!gpio_is_valid(gpio_mclk)) {
		dev_err(dev, "failed to get gpio_mclk\n");
		return -EINVAL;
	} else {
		gpio_request_one(gpio_mclk, GPIOF_OUT_INIT_LOW, "CAM_MCLK_OUTPUT_LOW");
		gpio_free(gpio_mclk);
	}

	gpio_cam_avdd_en = of_get_named_gpio(dnode, "gpio_cam_avdd_en", 0);
	if (!gpio_is_valid(gpio_cam_avdd_en)) {
		dev_err(dev, "failed to get gpio_cam_avdd_en\n");
	} else {
		gpio_request_one(gpio_cam_avdd_en, GPIOF_OUT_INIT_LOW, "CAM_GPIO_OUTPUT_LOW");
		gpio_free(gpio_cam_avdd_en);
	}

	gpio_cam_af_en = of_get_named_gpio(dnode, "gpio_cam_af_en", 0);
	if (!gpio_is_valid(gpio_cam_af_en)) {
		dev_err(dev,"failed to get gpio_cam_af_en\n");
	} else {
		gpio_request_one(gpio_cam_af_en, GPIOF_OUT_INIT_LOW, "CAM_GPIO_OUTPUT_LOW");
		gpio_free(gpio_cam_af_en);
	}

	gpio_cam_io_en = of_get_named_gpio(dnode, "gpio_cam_io_en", 0);
	if (!gpio_is_valid(gpio_cam_io_en)) {
		dev_err(dev, "failed to get gpio_cam_io_en\n");
	} else {
		gpio_request_one(gpio_cam_io_en, GPIOF_OUT_INIT_LOW, "CAM_GPIO_OUTPUT_LOW");
		gpio_free(gpio_cam_io_en);
	}

#if defined (CONFIG_OIS_USE)
	gpio_ois_reset = of_get_named_gpio(dnode, "gpio_ois_reset", 0);
	if (!gpio_is_valid(gpio_ois_reset)) {
		dev_err(dev, "failed to get gpio_ois_reset\n");
		return -EINVAL;
	} else {
		gpio_request_one(gpio_ois_reset, GPIOF_OUT_INIT_LOW, "CAM_GPIO_OUTPUT_LOW");
		gpio_free(gpio_ois_reset);
	}

	gpio_ois_core_en = of_get_named_gpio(dnode, "gpio_ois_core_en", 0);
	if (!gpio_is_valid(gpio_ois_core_en)) {
		dev_err(dev, "failed to get gpio_ois_core_en\n");
		return -EINVAL;
	} else {
		gpio_request_one(gpio_ois_core_en, GPIOF_OUT_INIT_LOW, "CAM_GPIO_OUTPUT_LOW");
		gpio_free(gpio_ois_core_en);
	}

	gpio_ois_io_en = of_get_named_gpio(dnode, "gpio_ois_io_en", 0);
	if (!gpio_is_valid(gpio_ois_io_en)) {
		dev_err(dev, "failed to get gpio_ois_io_en\n");
		return -EINVAL;
	} else {
		gpio_request_one(gpio_ois_io_en, GPIOF_OUT_INIT_LOW, "CAM_GPIO_OUTPUT_LOW");
		gpio_free(gpio_ois_io_en);
	}
#endif

	SET_PIN_INIT(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON);
	SET_PIN_INIT(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF);

	SET_PIN_INIT(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_ON);
	SET_PIN_INIT(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_OFF);

#if defined (CONFIG_OIS_USE)
	SET_PIN_INIT(pdata, SENSOR_SCENARIO_OIS_FACTORY, GPIO_SCENARIO_ON);
	SET_PIN_INIT(pdata, SENSOR_SCENARIO_OIS_FACTORY, GPIO_SCENARIO_OFF);
#endif

	/* BACK CAMERA - POWER ON */
	SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_reset, "pdaf sen_rst low", PIN_OUTPUT, 0, 0);

	if (gpio_is_valid(gpio_cam_avdd_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_cam_avdd_en, "pdaf gpio_cam_avdd_en", PIN_OUTPUT, 1, 200);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_none, "VDDA_2.8V_CAM", PIN_REGULATOR, 1, 200);
	}

#if defined (CONFIG_OIS_USE)
	if (gpio_is_valid(gpio_ois_core_en)) {  /* VDD_OIS_2P8 */
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_ois_core_en, "pdaf gpio_ois_core_en", PIN_OUTPUT, 1, 0);
	}
	if (gpio_is_valid(gpio_ois_io_en)) {  /* VDD_OIS_IO_1P8 */
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_ois_io_en, "pdaf gpio_ois_io_en", PIN_OUTPUT, 1, 2000);
	}
#endif

	if (gpio_is_valid(gpio_core_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_core_en, "pdaf gpio_core_en", PIN_OUTPUT, 1, 200);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_none, "VDDD_1.2V_CAM", PIN_REGULATOR, 1, 200);
	}

	if (gpio_is_valid(gpio_cam_af_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_cam_af_en, "pdaf gpio_cam_af_en", PIN_OUTPUT, 1, 7000);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_none, "VDD_CAM_AF_2P8", PIN_REGULATOR, 1, 7000);
	}

	if (gpio_is_valid(gpio_cam_io_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_cam_io_en, "pdaf gpio_cam_io_en", PIN_OUTPUT, 1, 3000);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_none, "VDDIO_1.8V_CAM", PIN_REGULATOR, 1, 3000);
	}

#if defined (CONFIG_OIS_USE)
	if (gpio_is_valid(gpio_ois_reset)) {  /* OIS_RESET */
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_ois_reset, "pdaf gpio_ois_reset", PIN_OUTPUT, 1, 0);
	}
#endif

	SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_reset, "pdaf sen_rst high", PIN_OUTPUT, 1, 500);
	SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_none, "pin", PIN_FUNCTION, 2, 0);

	/* BACK CAEMRA - POWER OFF */
	if (gpio_is_valid(gpio_cam_af_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_cam_af_en, "pdaf gpio_cam_af_en", PIN_OUTPUT, 0, 200);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_none, "VDDAF_2.8V_CAM", PIN_REGULATOR, 0, 200);
	}

	SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_none, "pin", PIN_FUNCTION, 1, 0);
	SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_none, "pin_none", PIN_NONE, 1, 500);
	SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_reset, "pdaf sen_rst", PIN_OUTPUT, 0, 200);

#if defined (CONFIG_OIS_USE)
	if (gpio_is_valid(gpio_ois_reset)) {  /* OIS_RESET */
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_ois_reset, "pdaf gpio_ois_reset", PIN_OUTPUT, 0, 0);
	}
#endif

	if (gpio_is_valid(gpio_cam_io_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_cam_io_en, "pdaf gpio_cam_io_en", PIN_OUTPUT, 0, 100);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_none, "VDDIO_1.8V_CAM", PIN_REGULATOR, 0, 100);
	}

#if defined (CONFIG_OIS_USE)
	if (gpio_is_valid(gpio_ois_core_en)) {  /* VDD_OIS_2P8 */
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_ois_core_en, "pdaf gpio_ois_core_en", PIN_OUTPUT, 0, 0);
	}
	if (gpio_is_valid(gpio_ois_io_en)) {  /* VDD_OIS_IO_1P8 */
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_ois_io_en, "pdaf gpio_ois_io_en", PIN_OUTPUT, 0, 0);
	}
#endif

	if (gpio_is_valid(gpio_core_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_core_en, "pdaf gpio_core_en", PIN_OUTPUT, 0, 100);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_none, "VDDD_1.2V_CAM", PIN_REGULATOR, 0, 100);
	}

	if (gpio_is_valid(gpio_cam_avdd_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_cam_avdd_en, "pdaf gpio_cam_avdd_en", PIN_OUTPUT, 0, 100);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_none, "VDDA_2.8V_CAM", PIN_REGULATOR, 0, 100);
	}

	/* READ_ROM - POWER ON */
#if defined(USE_AF_PWR_READ_EEPROM)
	if (gpio_is_valid(gpio_cam_af_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_ON, gpio_cam_af_en, "pdaf gpio_cam_af_en", PIN_OUTPUT, 1, 2000);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_ON, gpio_none, "VDD_CAM_AF_2P8", PIN_REGULATOR, 1, 2000);
	}
#endif
	if (gpio_is_valid(gpio_cam_io_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_ON, gpio_cam_io_en, "pdaf gpio_cam_io_en", PIN_OUTPUT, 1, 2000);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_ON, gpio_none, "VDDIO_1.8V_CAM", PIN_REGULATOR, 1, 2000);
	}

#if defined (CONFIG_OIS_USE)
	if (gpio_is_valid(gpio_ois_core_en)) {  /* VDD_OIS_2P8 */
		SET_PIN(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_ON, gpio_ois_core_en, "pdaf gpio_ois_core_en", PIN_OUTPUT, 1, 0);
	}
	if (gpio_is_valid(gpio_ois_io_en)) {  /* VDD_OIS_IO_1P8 */
		SET_PIN(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_ON, gpio_ois_io_en, "pdaf gpio_ois_io_en", PIN_OUTPUT, 1, 2000);
	}
	if (gpio_is_valid(gpio_ois_reset)) {  /* OIS_RESET */
		SET_PIN(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_ON, gpio_ois_reset, "pdaf gpio_ois_reset", PIN_OUTPUT, 1, 2000);
	}
#endif

	/* READ_ROM - POWER OFF */
#if defined(USE_AF_PWR_READ_EEPROM)
	if (gpio_is_valid(gpio_cam_af_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_OFF, gpio_cam_af_en, "pdaf gpio_cam_af_en", PIN_OUTPUT, 0, 10);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_OFF, gpio_none, "VDD_CAM_AF_2P8", PIN_REGULATOR, 0, 10);
	}
#endif
	if (gpio_is_valid(gpio_cam_io_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_OFF, gpio_cam_io_en, "pdaf gpio_cam_io_en", PIN_OUTPUT, 0, 0);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_OFF, gpio_none, "VDDIO_1.8V_CAM", PIN_REGULATOR, 0, 0);
	}

#if defined (CONFIG_OIS_USE)
	if (gpio_is_valid(gpio_ois_reset)) {  /* OIS_RESET */
		SET_PIN(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_OFF, gpio_ois_reset, "pdaf gpio_ois_reset", PIN_OUTPUT, 0, 10);
	}
	if (gpio_is_valid(gpio_ois_core_en)) {  /* VDD_OIS_2P8 */
		SET_PIN(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_OFF, gpio_ois_core_en, "pdaf gpio_ois_core_en", PIN_OUTPUT, 0, 0);
	}
	if (gpio_is_valid(gpio_ois_io_en)) {  /* VDD_OIS_IO_1P8 */
		SET_PIN(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_OFF, gpio_ois_io_en, "pdaf gpio_ois_io_en", PIN_OUTPUT, 0, 10);
	}
#endif

#if defined(CONFIG_OIS_USE)
	/* BACK CAMERA - OIS FACTORY ON */
	if (gpio_is_valid(gpio_ois_core_en)) {  /* VDD_OIS_2P8 */
		SET_PIN(pdata, SENSOR_SCENARIO_OIS_FACTORY, GPIO_SCENARIO_ON, gpio_ois_core_en, "pdaf gpio_ois_core_en", PIN_OUTPUT, 1, 0);
	}

	if (gpio_is_valid(gpio_ois_io_en)) {  /* VDD_OIS_IO_1P8 */
		SET_PIN(pdata, SENSOR_SCENARIO_OIS_FACTORY, GPIO_SCENARIO_ON, gpio_ois_io_en, "pdaf gpio_ois_io_en", PIN_OUTPUT, 1, 2000);
	}

	if (gpio_is_valid(gpio_cam_af_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_OIS_FACTORY, GPIO_SCENARIO_ON, gpio_cam_af_en, "pdaf gpio_cam_af_en", PIN_OUTPUT, 1, 2000);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_OIS_FACTORY, GPIO_SCENARIO_ON, gpio_none, "VDD_CAM_AF_2P8", PIN_REGULATOR, 1, 2000);
	}

	if (gpio_is_valid(gpio_cam_io_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_OIS_FACTORY, GPIO_SCENARIO_ON, gpio_cam_io_en, "pdaf gpio_cam_io_en", PIN_OUTPUT, 1, 2000);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_OIS_FACTORY, GPIO_SCENARIO_ON, gpio_none, "VDDIO_1.8V_CAM", PIN_REGULATOR, 1, 2000);
	}

	if (gpio_is_valid(gpio_ois_reset)) {  /* OIS_RESET */
		SET_PIN(pdata, SENSOR_SCENARIO_OIS_FACTORY, GPIO_SCENARIO_ON, gpio_ois_reset, "pdaf gpio_ois_reset", PIN_OUTPUT, 1, 2000);
	}

	/* BACK CAMERA - OIS FACTORY OFF */
	if (gpio_is_valid(gpio_cam_af_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_OIS_FACTORY, GPIO_SCENARIO_OFF, gpio_cam_af_en, "pdaf gpio_cam_af_en", PIN_OUTPUT, 0, 10);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_OIS_FACTORY, GPIO_SCENARIO_OFF, gpio_none, "VDD_CAM_AF_2P8", PIN_REGULATOR, 0, 10);
	}

	if (gpio_is_valid(gpio_ois_reset)) {  /* OIS_RESET */
		SET_PIN(pdata, SENSOR_SCENARIO_OIS_FACTORY, GPIO_SCENARIO_OFF, gpio_ois_reset, "pdaf gpio_ois_reset", PIN_OUTPUT, 0, 10);
	}

	if (gpio_is_valid(gpio_cam_io_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_OIS_FACTORY, GPIO_SCENARIO_OFF, gpio_cam_io_en, "pdaf gpio_cam_io_en", PIN_OUTPUT, 0, 2000);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_OIS_FACTORY, GPIO_SCENARIO_OFF, gpio_none, "VDDIO_1.8V_CAM", PIN_REGULATOR, 0, 2000);
	}

	if (gpio_is_valid(gpio_ois_core_en)) {  /* VDD_OIS_2P8 */
		SET_PIN(pdata, SENSOR_SCENARIO_OIS_FACTORY, GPIO_SCENARIO_OFF, gpio_ois_core_en, "pdaf gpio_ois_core_en", PIN_OUTPUT, 0, 0);
	}
	if (gpio_is_valid(gpio_ois_io_en)) {  /* VDD_OIS_IO_1P8 */
		SET_PIN(pdata, SENSOR_SCENARIO_OIS_FACTORY, GPIO_SCENARIO_OFF, gpio_ois_io_en, "pdaf gpio_ois_io_en", PIN_OUTPUT, 0, 10);
	}
#endif

	dev_info(dev, "%s X v4\n", __func__);

	return 0;
}

static int sensor_module_3p8_power_setpin(struct platform_device *pdev,
	struct exynos_platform_fimc_is_module *pdata)
{
	struct device *dev;
	struct device_node *dnode;
	int gpio_reset = 0;
	int gpio_mclk = 0;
	int gpio_none = 0;
	int gpio_core_en = 0;
	int gpio_cam_avdd_en = 0;
	int gpio_cam_io_en = 0;

	BUG_ON(!pdev);

	dev = &pdev->dev;
	dnode = dev->of_node;

	dev_info(dev, "%s E v4\n", __func__);

	gpio_reset = of_get_named_gpio(dnode, "gpio_reset", 0);
	if (!gpio_is_valid(gpio_reset)) {
		dev_err(dev, "failed to get PIN_RESET\n");
		return -EINVAL;
	} else {
		gpio_request_one(gpio_reset, GPIOF_OUT_INIT_LOW, "CAM_GPIO_OUTPUT_LOW");
		gpio_free(gpio_reset);
	}

	gpio_core_en = of_get_named_gpio(dnode, "gpio_core_en", 0);
	if (!gpio_is_valid(gpio_core_en)) {
		dev_err(dev, "failed to get gpio_core_en\n");
	} else {
		gpio_request_one(gpio_core_en, GPIOF_OUT_INIT_LOW, "CAM_GPIO_OUTPUT_LOW");
		gpio_free(gpio_core_en);
	}

	gpio_mclk = of_get_named_gpio(dnode, "gpio_mclk", 0);
	if (!gpio_is_valid(gpio_mclk)) {
		dev_err(dev, "failed to get gpio_mclk\n");
		return -EINVAL;
	} else {
		gpio_request_one(gpio_mclk, GPIOF_OUT_INIT_LOW, "CAM_MCLK_OUTPUT_LOW");
		gpio_free(gpio_mclk);
	}

	gpio_cam_avdd_en = of_get_named_gpio(dnode, "gpio_cam_avdd_en", 0);
	if (!gpio_is_valid(gpio_cam_avdd_en)) {
		dev_err(dev, "failed to get gpio_cam_avdd_en\n");
	} else {
		gpio_request_one(gpio_cam_avdd_en, GPIOF_OUT_INIT_LOW, "CAM_GPIO_OUTPUT_LOW");
		gpio_free(gpio_cam_avdd_en);
	}

	gpio_cam_io_en = of_get_named_gpio(dnode, "gpio_cam_io_en", 0);
	if (!gpio_is_valid(gpio_cam_io_en)) {
		dev_err(dev, "failed to get gpio_cam_io_en\n");
	} else {
		gpio_request_one(gpio_cam_io_en, GPIOF_OUT_INIT_LOW, "CAM_GPIO_OUTPUT_LOW");
		gpio_free(gpio_cam_io_en);
	}

	SET_PIN_INIT(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON);
	SET_PIN_INIT(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF);

	SET_PIN_INIT(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_ON);
	SET_PIN_INIT(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_OFF);

	/* BACK CAMERA - POWER ON */
	SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_reset, "sen_rst low", PIN_OUTPUT, 0, 0);

	if (gpio_is_valid(gpio_cam_avdd_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_cam_avdd_en, "gpio_cam_avdd_en", PIN_OUTPUT, 1, 200);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_none, "VDDA_2.8V_CAM", PIN_REGULATOR, 1, 200);
	}

	if (gpio_is_valid(gpio_core_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_core_en, "gpio_core_en", PIN_OUTPUT, 1, 200);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_none, "VDDD_1.2V_CAM", PIN_REGULATOR, 1, 200);
	}

	if (gpio_is_valid(gpio_cam_io_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_cam_io_en, "gpio_cam_io_en", PIN_OUTPUT, 1, 1000);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_none, "VDDIO_1.8V_CAM", PIN_REGULATOR, 1, 1000);
	}

	SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_reset, "sen_rst high", PIN_OUTPUT, 1, 500);
	SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_ON, gpio_none, "pin", PIN_FUNCTION, 2, 0);

    /* BACK CAEMRA - POWER OFF */
	SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_none, "pin", PIN_FUNCTION, 1, 0);
	SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_none, "pin_none", PIN_NONE, 1, 500);
	SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_reset, "sen_rst", PIN_OUTPUT, 0, 200);

	if (gpio_is_valid(gpio_cam_io_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_cam_io_en, "gpio_cam_io_en", PIN_OUTPUT, 0, 100);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_none, "VDDIO_1.8V_CAM", PIN_REGULATOR, 0, 100);
	}

	if (gpio_is_valid(gpio_core_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_core_en, "gpio_core_en", PIN_OUTPUT, 0, 100);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_none, "VDDD_1.2V_CAM", PIN_REGULATOR, 0, 100);
	}

	if (gpio_is_valid(gpio_cam_avdd_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_cam_avdd_en, "gpio_cam_avdd_en", PIN_OUTPUT, 0, 100);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_NORMAL, GPIO_SCENARIO_OFF, gpio_none, "VDDA_2.8V_CAM", PIN_REGULATOR, 0, 100);
	}

	/* READ_ROM - POWER ON */
	if (gpio_is_valid(gpio_cam_io_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_ON, gpio_cam_io_en, "gpio_cam_io_en", PIN_OUTPUT, 1, 2000);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_ON, gpio_none, "VDDIO_1.8V_CAM", PIN_REGULATOR, 1, 2000);
	}

	/* READ_ROM - POWER OFF */
	if (gpio_is_valid(gpio_cam_io_en)) {
		SET_PIN(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_OFF, gpio_cam_io_en, "gpio_cam_io_en", PIN_OUTPUT, 0, 0);
	} else {
		SET_PIN(pdata, SENSOR_SCENARIO_READ_ROM, GPIO_SCENARIO_OFF, gpio_none, "VDDIO_1.8V_CAM", PIN_REGULATOR, 0, 0);
	}

	dev_info(dev, "%s X v4\n", __func__);

	return 0;
}

static int (* module_3p8_power_setpin[MAX_3P8_SETPIN_CNT])(struct platform_device *pdev,
	struct exynos_platform_fimc_is_module *pdata) = {
	sensor_module_3p8_power_setpin,
	sensor_module_3p8_power_setpin_with_af
};

