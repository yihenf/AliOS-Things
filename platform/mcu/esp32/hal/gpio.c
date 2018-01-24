/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */

#include <stdio.h>
#include <stdint.h>
#include <aos/aos.h>

#define gpio_dev_t aos_gpio_dev_t
#define gpio_config_t aos_gpio_config_t
#include <hal/soc/gpio.h>
#undef gpio_dev_t
#undef gpio_config_t

#include <driver/gpio.h>
#include <driver/rtc_io.h>

#define ESP_INTR_FLAG_DEFAULT 0

int32_t hal_gpio_init(aos_gpio_dev_t *gpio)
{
    int32_t ret = -1;
    gpio_config_t io_conf;

    /* disable interrupt */
    io_conf.intr_type = GPIO_PIN_INTR_DISABLE;
    /* set mode */
    if (gpio->config == OUTPUT_PUSH_PULL)
    {
        io_conf.mode = GPIO_MODE_OUTPUT;
    }
    else if ((gpio->config == OUTPUT_OPEN_DRAIN_NO_PULL) || 
            (gpio->config == OUTPUT_OPEN_DRAIN_PULL_UP))
    {
        io_conf.mode = GPIO_MODE_OUTPUT_OD;
    }
    else if ((gpio->config == INPUT_PULL_UP) || 
             (gpio->config == INPUT_PULL_DOWN) || 
             (gpio->config == INPUT_HIGH_IMPEDANCE))
    {
        io_conf.mode = GPIO_MODE_INPUT;
    }
    else if (gpio->config == IRQ_MODE)
    {
        io_conf.mode = GPIO_MODE_INPUT;
        gpio_install_isr_service(ESP_INTR_FLAG_DEFAULT);
    }
    else if (gpio->config == ANALOG_MODE)
    {
        io_conf.mode = GPIO_MODE_INPUT_OUTPUT;
        rtc_gpio_init(gpio->port);
    }
    /* bit mask of the pins */
    io_conf.pin_bit_mask = (1ULL << (gpio->port));
    /* set pull-down mode */
    io_conf.pull_down_en = (gpio->config == INPUT_PULL_DOWN) ? 1 : 0;
    /* set pull-up mode */
    io_conf.pull_up_en = ((gpio->config == INPUT_PULL_UP) || 
                          (gpio->config == OUTPUT_OPEN_DRAIN_PULL_UP)) ? 1 : 0;
    /* configure GPIO with the given settings */
    ret = gpio_config(&io_conf);

    return ret;
}

int32_t hal_gpio_output_high(aos_gpio_dev_t *gpio)
{
    int32_t ret = -1;

	ret = gpio_set_level(gpio->port, 1);
	
    return ret;
}

int32_t hal_gpio_output_low(aos_gpio_dev_t *gpio)
{
    int32_t ret = -1;

	ret = gpio_set_level(gpio->port, 0);
	
    return ret;
}

int32_t hal_gpio_output_toggle(aos_gpio_dev_t *gpio)
{
    // TODO
    
    return 0;
}

int32_t hal_gpio_input_get(aos_gpio_dev_t *gpio, uint32_t *value)
{
    *value = gpio_get_level(gpio->port);

    return 0;
}

int32_t hal_gpio_enable_irq(aos_gpio_dev_t *gpio, gpio_irq_trigger_t trigger,
                                     gpio_irq_handler_t handler, void *arg)
{
    int32_t ret = -1;

    gpio_set_intr_type(gpio->port, (gpio_int_type_t)trigger);
    ret = gpio_isr_handler_add(gpio->port, handler, arg);
    
    return ret;
}

int32_t hal_gpio_disable_irq(aos_gpio_dev_t *gpio)
{
    int32_t ret = -1;

    ret =  gpio_intr_disable(gpio->port);

    return ret;
}

int32_t hal_gpio_clear_irq(aos_gpio_dev_t *gpio)
{
    int32_t ret = -1;

    gpio_intr_disable(gpio->port);
    gpio_set_intr_type(gpio->port, GPIO_INTR_DISABLE);
    ret = gpio_isr_handler_remove(gpio->port);
    
    return ret;
}

int32_t hal_gpio_finalize(aos_gpio_dev_t *gpio)
{
    int32_t ret = -1;
	gpio_config_t io_conf;

    /* disable interrupt */
    io_conf.intr_type = GPIO_PIN_INTR_DISABLE;
    /* disable output */
    io_conf.mode = GPIO_MODE_INPUT;
    /* bit mask of the pins */
    io_conf.pin_bit_mask = (1ULL << (gpio->port));
    /* disable pull-down mode */
    io_conf.pull_down_en = 0;
    /* disable pull-up mode */
    io_conf.pull_up_en = 0;
    //configure GPIO with the given settings
    ret = gpio_config(&io_conf);

    return ret;
}
