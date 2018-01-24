/**
******************************************************************************
* @file    crt0_IAR.h 
* @author  William Xu
* @version V1.0.0
* @date    16-Sep-2014
* @brief   __low_level_init called by IAR before main.
******************************************************************************
*
*  The MIT License
*  Copyright (c) 2014 MXCHIP Inc.
*
*  Permission is hereby granted, free of charge, to any person obtaining a copy 
*  of this software and associated documentation files (the "Software"), to deal
*  in the Software without restriction, including without limitation the rights 
*  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
*  copies of the Software, and to permit persons to whom the Software is furnished
*  to do so, subject to the following conditions:
*
*  The above copyright notice and this permission notice shall be included in
*  all copies or substantial portions of the Software.
*
*  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
*  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
*  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
*  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
*  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR 
*  IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
******************************************************************************
*/

#include "gpio.h"
#include "uart.h"
#include "irqs.h"
#include "clk.h"
#include "uart.h"
#include "gpio.h"
#include "spi_flash.h"
#include "watchdog.h"
#include "timeout.h"
#include "cache.h"
#include "delay.h"
#include "wakeup.h"
#include "rtc.h"

#include <aos/aos.h>
#include <k_api.h>
#include <aos/kernel.h>

#define MCU_CLOCK_HZ            (96000000)

#define SCB_VTOR_ADDRESS         ( ( volatile unsigned long* ) 0xE000ED08 )

ktask_t *g_aos_init;

extern int application_start(int argc, char **argv);

void fuart_init(void )
{
	ClkModuleEn( FUART_CLK_EN );

	GpioFuartTxIoConfig(1);
	GpioFuartRxIoConfig(1);

	FuartInit(115200, 8, 0, 1);
	FuartIOctl(UART_IOCTL_RXINT_SET, 1);
}

void fuart_send(const uint8_t *buf, uint32_t size )
{
	FuartSend((uint8_t *)buf, size);
}

int main( void )
{
	/* Setup the interrupt vectors address */
	*SCB_VTOR_ADDRESS = 0xB000;
	
	//  /* Configure Clocks */
	ClkModuleDis(ALL_MODULE_CLK_SWITCH &(~(FSHC_CLK_EN)));	
	ClkModuleEn( FSHC_CLK_EN );
	//ClkModuleEn( FSHC_CLK_EN | FUART_CLK_EN | SD_CLK_EN | BUART_CLK_EN );	//enable Fuart clock for debugging
	ClkModuleGateEn( ALL_MODULE_CLK_GATE_SWITCH );        //open all clk gating  

	ClkPorRcToDpll(0);              //clock src is 32768hz OSC
	ClkDpllClkGatingEn(1);

	CacheInit();

	//Disable Watchdog
	WdgDis();
	
	NVIC_SetPriorityGrouping(__NVIC_PRIO_BITS + 1);
	NVIC_SetPriority(FUART_IRQn,  FUART_IRQn_PRIO);
	NVIC_SetPriority(BUART_IRQn,  BUART_IRQn_PRIO);
	
	fuart_init();
	printf("Hello world\r\n");
	printf("Built at %s, %s\r\n",__DATE__,__TIME__);

	SysTick_Config(MCU_CLOCK_HZ/1000);
	
	aos_init();
	krhino_task_dyn_create(&g_aos_init, "aos app", 0, AOS_DEFAULT_APP_PRI, 0, 512, (task_entry_t)application_start, 1);
	aos_start();

	/* Should never get here, unless there is an error in vTaskStartScheduler */
	for(;;);

	return 0;
}

#include <hal/soc/soc.h>

uart_dev_t uart_0;

int32_t hal_uart_send(uart_dev_t *uart, const void *data, uint32_t size, uint32_t timeout)
{
	fuart_send(data, size);
    return 0;
}

int _write( int file, char *ptr, int len )
{
	hal_uart_send(&uart_0, ptr, len, 0xFFFFFFFF);
	return len;
}

void SysTick_Handler(void)
{
	static uint32_t tick = 0;
	tick++;

	if (0 == tick % 10) 
	{
		krhino_intrpt_enter();
		krhino_tick_proc();
		krhino_intrpt_exit();
	}
}
