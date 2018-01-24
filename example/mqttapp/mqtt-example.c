/*
 * Copyright (C) 2015-2017 Alibaba Group Holding Limited
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iot_import.h"
#include "iot_export.h"
#include "aos/log.h"
//#include "json_parser.h"
#include "aos/yloop.h"
#include "aos/network.h"
#include <netmgr.h>
#include <aos/kernel.h>
#include <k_err.h>
//#include "aliot_platform.h"
//#include "aliot_log.h"
//#include "aliot_mqtt_client.h"
//#include "aliot_auth.h"
//#include "aliot_device.h"
#include <netmgr.h>
#include <aos/cli.h>
#include <aos/cloud.h>
#if defined(MQTT_ID2_AUTH) && defined(TEST_ID2_DAILY)
/*
    #define PRODUCT_KEY             "OvNmiEYRDSY"
    #define DEVICE_NAME             "sh_online_sample_mqtt"
    #define DEVICE_SECRET           "v9mqGzepKEphLhXmAoiaUIR2HZ7XwTky"
*/
#else
/*
    #define PRODUCT_KEY             "yfTuLfBJTiL"
    #define DEVICE_NAME             "TestDeviceForDemo"
    #define DEVICE_SECRET           "fSCl9Ns5YPnYN8Ocg0VEel1kXFnRlV6c"
*/
    #define PRODUCT_KEY             "BfKxBDSjWCH"
    #define DEVICE_NAME             "aos_mqtt_test"
    #define DEVICE_SECRET           "zcBZ5TB9cfAylUGo1flH0o47PxS8Mqu2"

#endif

// These are pre-defined topics
#define TOPIC_UPDATE            "/"PRODUCT_KEY"/"DEVICE_NAME"/update"
#define TOPIC_ERROR             "/"PRODUCT_KEY"/"DEVICE_NAME"/update/error"
#define TOPIC_GET               "/"PRODUCT_KEY"/"DEVICE_NAME"/get"
#define TOPIC_DATA              "/"PRODUCT_KEY"/"DEVICE_NAME"/data"

#define MSG_LEN_MAX             (2048)

#define EXAMPLE_TRACE(fmt, args...)  \
    do { \
        printf("%s|%03d :: ", __func__, __LINE__); \
        printf(fmt, ##args); \
        printf("%s", "\r\n"); \
    } while(0)


int cnt = 0;
static int is_subscribed = 0;

typedef struct ota_device_info {
    const char *product_key;
    const char *device_name;
    void *pclient;
} OTA_device_info_t;

OTA_device_info_t ota_device_info;

void *gpclient;

char *msg_buf = NULL, *msg_readbuf = NULL;

iotx_mqtt_topic_info_t topic_msg;
char msg_pub[128];

static void ota_init(void *pclient);
int mqtt_client_example(void);
static void wifi_service_event(input_event_t *event, void *priv_data) {
    EXAMPLE_TRACE("wifi_service_event!");
    if (event->type != EV_WIFI) {
        return;
    }

    if (event->code != CODE_WIFI_ON_GOT_IP) {
        return;
    }

    mqtt_client_example();
}

static void _demo_message_arrive(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg)
{
    iotx_mqtt_topic_info_pt ptopic_info = (iotx_mqtt_topic_info_pt) msg->msg;

    // print topic name and topic message
    EXAMPLE_TRACE("----");
    EXAMPLE_TRACE("Topic: '%.*s' (Length: %d)",
                  ptopic_info->topic_len,
                  ptopic_info->ptopic,
                  ptopic_info->topic_len);
    EXAMPLE_TRACE("Payload: '%.*s' (Length: %d)",
                  ptopic_info->payload_len,
                  ptopic_info->payload,
                  ptopic_info->payload_len);
    EXAMPLE_TRACE("----");
}

void release_buff() {
    if (NULL != msg_buf) {
        HAL_Free(msg_buf);
    }

    if (NULL != msg_readbuf) {
        HAL_Free(msg_readbuf);
    }
}

/*
 * Subscribe the topic: IOT_MQTT_Subscribe(pclient, TOPIC_DATA, IOTX_MQTT_QOS1, _demo_message_arrive, NULL);
 * Publish the topic: IOT_MQTT_Publish(pclient, TOPIC_DATA, &topic_msg);
 */
static void mqtt_publish(void *pclient) {

    int rc = -1;

    if(is_subscribed == 0) {
        /* Subscribe the specific topic */
        rc = IOT_MQTT_Subscribe(pclient, TOPIC_DATA, IOTX_MQTT_QOS1, _demo_message_arrive, NULL);
        if (rc < 0) {
            IOT_MQTT_Destroy(&pclient);
            EXAMPLE_TRACE("IOT_MQTT_Subscribe() failed, rc = %d", rc);
            rc = -1;
            return;
        }
        is_subscribed = 1;

        HAL_SleepMs(1000);
    }

    /* Initialize topic information */
    memset(&topic_msg, 0x0, sizeof(iotx_mqtt_topic_info_t));

    topic_msg.qos = IOTX_MQTT_QOS1;
    topic_msg.retain = 0;
    topic_msg.dup = 0;

    /* Generate topic message */
    int msg_len = snprintf(msg_pub, sizeof(msg_pub), "{\"attr_name\":\"temperature\", \"attr_value\":\"%d\"}", cnt);
    if (msg_len < 0) {
        EXAMPLE_TRACE("Error occur! Exit program");
        rc = -1;
    }

    topic_msg.payload = (void *)msg_pub;
    topic_msg.payload_len = msg_len;

    rc = IOT_MQTT_Publish(pclient, TOPIC_DATA, &topic_msg);
    if (rc < 0) {
        EXAMPLE_TRACE("error occur when publish");
        rc = -1;
    }
#ifdef MQTT_ID2_CRYPTO
    EXAMPLE_TRACE("packet-id=%u, publish topic msg='0x%02x%02x%02x%02x'...",
            (uint32_t)rc,
            msg_pub[0], msg_pub[1], msg_pub[2], msg_pub[3]
       );
#else
    EXAMPLE_TRACE("packet-id=%u, publish topic msg=%s", (uint32_t)rc, msg_pub);
#endif

    cnt++;
    if(cnt < 200) {
        aos_post_delayed_action(2000, mqtt_publish, pclient);
    } else {

        IOT_MQTT_Unsubscribe(pclient, TOPIC_DATA);

        HAL_SleepMs(200);

        IOT_MQTT_Destroy(&pclient);

        release_buff();

        is_subscribed = 0;
        cnt = 0;
    }
}

static void mqtt_service_event(input_event_t *event, void *priv_data) {
    EXAMPLE_TRACE("wifi_service_event!");
    if (event->type != EV_SYS) {
        return;
    }

    if (event->code != CODE_SYS_ON_MQTT_READ) {
        return;
    }

    mqtt_publish(priv_data);
}

void event_handle_mqtt(void *pcontext, void *pclient, iotx_mqtt_event_msg_pt msg)
{
    uintptr_t packet_id = (uintptr_t)msg->msg;
    iotx_mqtt_topic_info_pt topic_info = (iotx_mqtt_topic_info_pt)msg->msg;

    switch (msg->event_type) {
        case IOTX_MQTT_EVENT_UNDEF:
            EXAMPLE_TRACE("undefined event occur.");
            break;

        case IOTX_MQTT_EVENT_DISCONNECT:
            EXAMPLE_TRACE("MQTT disconnect.");
            break;

        case IOTX_MQTT_EVENT_RECONNECT:
            EXAMPLE_TRACE("MQTT reconnect.");
            break;

        case IOTX_MQTT_EVENT_SUBCRIBE_SUCCESS:
            EXAMPLE_TRACE("subscribe success, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_SUBCRIBE_TIMEOUT:
            EXAMPLE_TRACE("subscribe wait ack timeout, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_SUBCRIBE_NACK:
            EXAMPLE_TRACE("subscribe nack, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_UNSUBCRIBE_SUCCESS:
            EXAMPLE_TRACE("unsubscribe success, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_UNSUBCRIBE_TIMEOUT:
            EXAMPLE_TRACE("unsubscribe timeout, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_UNSUBCRIBE_NACK:
            EXAMPLE_TRACE("unsubscribe nack, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_PUBLISH_SUCCESS:
            EXAMPLE_TRACE("publish success, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_PUBLISH_TIMEOUT:
            EXAMPLE_TRACE("publish timeout, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_PUBLISH_NACK:
            EXAMPLE_TRACE("publish nack, packet-id=%u", (unsigned int)packet_id);
            break;

        case IOTX_MQTT_EVENT_PUBLISH_RECVEIVED:
            EXAMPLE_TRACE("topic message arrived but without any related handle: topic=%.*s, topic_msg=%.*s",
                          topic_info->topic_len,
                          topic_info->ptopic,
                          topic_info->payload_len,
                          topic_info->payload);
            break;

        default:
            EXAMPLE_TRACE("Should NOT arrive here.");
            break;
    }
}

/*
 * initialization parameter: mqtt_params
 */
int mqtt_client_example(void)
{
    int rc = 0;
    iotx_conn_info_pt pconn_info;
    iotx_mqtt_param_t mqtt_params;

    if (msg_buf != NULL) {
        return rc;
    }

    if (NULL == (msg_buf = (char *)HAL_Malloc(MSG_LEN_MAX))) {
        EXAMPLE_TRACE("not enough memory");
        rc = -1;
        release_buff();
        return rc;
    }

    if (NULL == (msg_readbuf = (char *)HAL_Malloc(MSG_LEN_MAX))) {
        EXAMPLE_TRACE("not enough memory");
        rc = -1;
        release_buff();
        return rc;
    }

    /* Device AUTH */
    if (0 != IOT_SetupConnInfo(PRODUCT_KEY, DEVICE_NAME, DEVICE_SECRET, (void **)&pconn_info)) {
        EXAMPLE_TRACE("AUTH request failed!");
        rc = -1;
        release_buff();
        return rc;
    }

    /* Initialize MQTT parameter */
    memset(&mqtt_params, 0x0, sizeof(mqtt_params));

    mqtt_params.port = pconn_info->port;
    mqtt_params.host = pconn_info->host_name;
    mqtt_params.client_id = pconn_info->client_id;
    mqtt_params.username = pconn_info->username;
    mqtt_params.password = pconn_info->password;
    mqtt_params.pub_key = pconn_info->pub_key;

    mqtt_params.request_timeout_ms = 2000;
    mqtt_params.clean_session = 0;
    mqtt_params.keepalive_interval_ms = 60000;
    mqtt_params.pread_buf = msg_readbuf;
    mqtt_params.read_buf_size = MSG_LEN_MAX;
    mqtt_params.pwrite_buf = msg_buf;
    mqtt_params.write_buf_size = MSG_LEN_MAX;

    mqtt_params.handle_event.h_fp = event_handle_mqtt;
    mqtt_params.handle_event.pcontext = NULL;


    /* Construct a MQTT client with specify parameter */
    gpclient = IOT_MQTT_Construct(&mqtt_params);
    if (NULL == gpclient) {
        EXAMPLE_TRACE("MQTT construct failed");
        rc = -1;
        release_buff();
    } else {
        aos_post_delayed_action(3000, ota_init, gpclient);
        aos_register_event_filter(EV_SYS,  mqtt_service_event, gpclient);
    }

    return rc;
}

static void handle_mqtt(char *pwbuf, int blen, int argc, char **argv)
{
    mqtt_client_example();
}

static struct cli_command mqttcmd = {
    .name = "mqtt",
    .help = "factory mqtt",
    .function = handle_mqtt
};


int application_start(int argc, char *argv[])
{
    aos_set_log_level(AOS_LL_DEBUG);

    aos_register_event_filter(EV_WIFI, wifi_service_event, NULL);

    netmgr_init();
    netmgr_start(false);

    aos_cli_register_command(&mqttcmd);
#ifdef CSP_LINUXHOST
    mqtt_client_example();
#endif
    aos_loop_run();
    return 0;
}

static void ota_init(void *pclient)
{
    ota_device_info.product_key=PRODUCT_KEY;
    ota_device_info.device_name=DEVICE_NAME;
    ota_device_info.pclient=pclient;
    aos_post_event(EV_SYS, CODE_SYS_ON_START_FOTA, (long unsigned int)&ota_device_info);
}
