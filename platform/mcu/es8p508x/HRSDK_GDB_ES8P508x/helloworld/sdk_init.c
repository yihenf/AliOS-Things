/*********************************************************
*Copyright (C), 2017, Shanghai Eastsoft Microelectronics Co., Ltd.
*�ļ���:  sdk_init.c
*��  ��:  essemi
*��  ��:  V1.00
*��  ��:  2017/12/22
*��  ��:  ���������ʾ������
*��  ע:  ������HRSDK-GDB-ES8P508x        
          ���������ѧϰ����ʾʹ�ã����û�ֱ�����ô����������ķ��ջ������е��κη������Ρ�
**********************************************************/

/* Includes ------------------------------------------------------------------*/
#include "sdk_init.h"
#include "k_config.h"
#include "lib_config.h"

#if defined (__CC_ARM) && defined(__MICROLIB)
void __aeabi_assert(const char *expr, const char *file, int line)
{
    while (1);
}
#endif


void SystemTick_Config(void);
static void UARTInit(void);
static void LEDInit(void);
static void KeyInit(void);

void sdk_init(void)
{
    SystemClockConfig();                //����ʱ��    
    DeviceClockAllEnable();             //����������ʱ��
    SystemTick_Config();               //ϵͳʱ������

    UARTInit();
    LEDInit();
    KeyInit();
}

/***************************************************************
 ��������void SysTickInit(void)
 ��  ����ϵͳ�δ�ʱ������
 ����ֵ����
 ���ֵ����
 ����ֵ����
***************************************************************/
void SystemTick_Config(void)
{
    SYSTICK_InitStruType x;

    x.SysTick_Value = SystemCoreClock/RHINO_CONFIG_TICKS_PER_SECOND;                     
    x.SysTick_ClkSource = SysTick_ClkS_Cpu;
    x.SysTick_ITEnable = ENABLE;                //�ж�ʹ��
    SysTick_Init(&x);
    SysTick_Enable();
     /* SysTick_IRQn interrupt configuration */
    NVIC_SetPriority(SysTick_IRQn,0);
}

/*********************************************************
������: void UARTInit(void)
��  ��: UART��ʼ���ӳ���
����ֵ: ��
���ֵ: ��
����ֵ: �� 
**********************************************************/
static void UARTInit(void)
{
    GPIO_InitStruType y;
    UART_InitStruType uart;

    y.GPIO_Signal = GPIO_Pin_Signal_Digital;
    y.GPIO_Func = GPIO_Func_2;
    y.GPIO_Direction = GPIO_Dir_Out;
    y.GPIO_PUEN = GPIO_PUE_Input_Disable;
    y.GPIO_PDEN = GPIO_PDE_Input_Disable;
    y.GPIO_OD = GPIO_ODE_Output_Disable;
    y.GPIO_DS = GPIO_DS_Output_Normal;
    GPIO_Init(GPIOA,GPIO_Pin_15,&y);                 //PA15---TxD
 
	y.GPIO_Signal = GPIO_Pin_Signal_Digital;
    y.GPIO_Func = GPIO_Func_2;
    y.GPIO_Direction = GPIO_Dir_In;
    y.GPIO_PUEN = GPIO_PUE_Input_Disable;
    y.GPIO_PDEN = GPIO_PDE_Input_Disable;
    y.GPIO_OD = GPIO_ODE_Output_Disable;
    y.GPIO_DS = GPIO_DS_Output_Normal;
    GPIO_Init(GPIOA,GPIO_Pin_16,&y);                 //PA16---RxD

    uart.UART_StopBits = UART_StopBits_1;          //ֹͣλ��1
    uart.UART_TxMode = UART_DataMode_8;            //�������ݸ�ʽ��8λ����
    uart.UART_TxPolar = UART_Polar_Normal;         //���Ͷ˿ڼ��ԣ�����
    uart.UART_RxMode = UART_DataMode_8;            //�������ݸ�ʽ��8λ����
    uart.UART_RxPolar = UART_Polar_Normal;         //���ն˿ڼ��ԣ�����
    uart.UART_BaudRate = 9600;                     //������
    uart.UART_ClockSet = UART_Clock_1;             //ʱ��ѡ��Pclk
    UART_Init(UART2,&uart);

    UART_TBIMConfig(UART2,UART_TRBIM_Byte);
    UART_RBIMConfig(UART2, UART_TRBIM_Byte);
    UART_ITConfig(UART2,UART_IT_RB,ENABLE);
//    NVIC_Init(NVIC_UART2_IRQn,NVIC_Priority_1,ENABLE);
    UART2_TxEnable();                               //UART2����ʹ��
    UART2_RxEnable();
}
 
/*********************************************************
������: void LEDInit(void)
��  ��: LED��ʼ��
����ֵ: ��
���ֵ: ��
����ֵ: �� 
**********************************************************/
static void LEDInit(void)
{
    GPIO_InitStruType x;

	x.GPIO_Signal = GPIO_Pin_Signal_Digital;
    x.GPIO_Func = GPIO_Func_0;
    x.GPIO_Direction = GPIO_Dir_Out;
    x.GPIO_PUEN = GPIO_PUE_Input_Disable;
    x.GPIO_PDEN = GPIO_PDE_Input_Disable;
    x.GPIO_OD = GPIO_ODE_Output_Disable;
    x.GPIO_DS = GPIO_DS_Output_Normal;

    GPIO_Init(GPIOA,GPIO_Pin_14,&x);     //LD1
    GPIO_Init(GPIOA,GPIO_Pin_13,&x);     //LD2
    GPIO_Init(GPIOA,GPIO_Pin_12,&x);     //LD3
    GPIO_Init(GPIOA,GPIO_Pin_11,&x);     //LD4    
    
    GPIOA_SetBit(GPIO_Pin_14);
    GPIOA_SetBit(GPIO_Pin_13);
    GPIOA_SetBit(GPIO_Pin_12);
    GPIOA_SetBit(GPIO_Pin_11);
    
}

/*********************************************************
������: void KeyInit(void)
��  ��: �����Ͱ������жϳ�ʼ���ӳ���
����ֵ: ��
���ֵ: ��
����ֵ: �� 
**********************************************************/
static void KeyInit(void)
{
    GPIO_InitStruType x;

	x.GPIO_Signal = GPIO_Pin_Signal_Digital;
    x.GPIO_Func = GPIO_Func_0;
    x.GPIO_Direction = GPIO_Dir_In;
    x.GPIO_PUEN = GPIO_PUE_Input_Enable;
    x.GPIO_PDEN = GPIO_PDE_Input_Disable;
    x.GPIO_OD = GPIO_ODE_Output_Disable;
    x.GPIO_DS = GPIO_DS_Output_Normal;
    GPIO_Init(GPIOB,GPIO_Pin_7,&x);         //KL1
    GPIO_Init(GPIOB,GPIO_Pin_2,&x);         //KL2
    GPIO_Init(GPIOB,GPIO_Pin_8,&x);         //KR1
    GPIO_Init(GPIOB,GPIO_Pin_3,&x);         //KR2
    GPIO_Init(GPIOA,GPIO_Pin_20,&x);         //K5

    PINT_Config(PINT4, PINT_SEL2, PINT_Trig_Rise);          //ѡ��SEL2�ж�Դ�������ش����ж�
    NVIC_Init(NVIC_PINT4_IRQn,NVIC_Priority_2,ENABLE);
    
    PINT_Config(PINT7, PINT_SEL4, PINT_Trig_Rise);          //ѡ��SEL2�ж�Դ�������ش����ж�
    NVIC_Init(NVIC_PINT7_IRQn,NVIC_Priority_2,ENABLE);
    
    PINT_Config(PINT2, PINT_SEL4, PINT_Trig_Rise);          //ѡ��SEL2�ж�Դ�������ش����ж�
    NVIC_Init(NVIC_PINT2_IRQn,NVIC_Priority_2,ENABLE);    
    
    PINT4_MaskDisable();
    PINT4_Enable();                       //����KINT�ж�
    PINT2_MaskDisable();
    PINT2_Enable();                       //����KINT�ж�
    PINT7_MaskDisable();
    PINT7_Enable();                       //����KINT�ж�
}

