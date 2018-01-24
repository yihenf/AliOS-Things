/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */

#include <k_api.h>
#include <stdio.h>
#include <stdlib.h>
#include <aos/aos.h>

extern void sdk_init(void);

#define DEMO_TASK_STACKSIZE    512 //512*cpu_stack_t = 2048byte
#define DEMO_TASK_PRIORITY     20
static ktask_t demo_task_obj;
cpu_stack_t demo_task_buf[DEMO_TASK_STACKSIZE];

void demo_task(void *arg)
{
    int count = 0;
    printf("demo_task here!\n\r");
    
    while (1)
    {
        printf("hello world! count %d\n\r", count++);
        //sleep 1 second
        krhino_task_sleep(RHINO_CONFIG_TICKS_PER_SECOND);
    };
}

int main(void)
{
    krhino_init();
    krhino_task_create( &demo_task_obj,             //�������
                        "demo_task",                //��������
                        0,                          //��������Ĳ�����û�в���������Ϊ0
                        DEMO_TASK_PRIORITY,         //�������ȼ�    
                        50,                         //����ʱ��Ƭ
                        demo_task_buf,              //����ջ�Ļ���ַ
                        DEMO_TASK_STACKSIZE,        //����ջ�Ĵ�С
                        demo_task,                  //�����ִ�к���
                        1                           //����������״̬
                        );
    //uart init 
    sdk_init(); 
    
    krhino_start();
    
    return 0;
}

