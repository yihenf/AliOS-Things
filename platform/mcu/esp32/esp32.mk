HOST_OPENOCD := esp32

NAME := esp32

$(NAME)_TYPE := kernel 

$(NAME)_COMPONENTS := framework.common modules.fs.kv cli
$(NAME)_COMPONENTS += protocols.net alicrypto

ESP_INC_PATH    := bsp/include
GLOBAL_INCLUDES += $(ESP_INC_PATH)
GLOBAL_INCLUDES += $(ESP_INC_PATH)/esp32/include
GLOBAL_INCLUDES += $(ESP_INC_PATH)/soc/esp32/include
GLOBAL_INCLUDES += $(ESP_INC_PATH)/soc/include
GLOBAL_INCLUDES += $(ESP_INC_PATH)/driver/include
GLOBAL_INCLUDES += $(ESP_INC_PATH)/ethernet/include
GLOBAL_INCLUDES += $(ESP_INC_PATH)/log/include
GLOBAL_INCLUDES += $(ESP_INC_PATH)/nvs_flash/include
GLOBAL_INCLUDES += $(ESP_INC_PATH)/spi_flash/include
GLOBAL_INCLUDES += $(ESP_INC_PATH)/container/include
GLOBAL_INCLUDES += $(ESP_INC_PATH)/app_update/include

GLOBAL_CFLAGS   += -ffunction-sections -fdata-sections -fstrict-volatile-bitfields -mlongcalls
GLOBAL_LDFLAGS   += -nostdlib -Lplatform/mcu/esp32/ -lc
GLOBAL_LDFLAGS   += -lgcc -lstdc++ -lgcov -lm

GLOBAL_LDS_FILES += platform/mcu/esp32/bsp/ld/esp32.ld.S
GLOBAL_LDS_FILES += platform/mcu/esp32/bsp/ld/esp32.common.ld
GLOBAL_LDS_FILES += platform/mcu/esp32/bsp/ld/esp32.rom.ld
GLOBAL_LDS_FILES += platform/mcu/esp32/bsp/ld/esp32.peripherals.ld
GLOBAL_LDS_FILES += platform/mcu/esp32/bsp/ld/esp32.rom.spiram_incompatible_fns.ld
GLOBAL_LDFLAGS   += -L platform/mcu/esp32/bsp/ld

GLOBAL_DEFINES   += CONFIG_AOS_KV_BUFFER_SIZE=8192
GLOBAL_DEFINES   += CONFIG_AOS_CLI_BOARD

$(NAME)_SOURCES  := bsp/entry.c
$(NAME)_SOURCES  += bsp/setboot_cli.c
$(NAME)_SOURCES  += hal/uart.c
$(NAME)_SOURCES  += hal/flash.c
$(NAME)_SOURCES  += hal/wifi_port.c
$(NAME)_SOURCES  += hal/ota_port.c
$(NAME)_SOURCES  += hal/misc.c
$(NAME)_SOURCES  += bsp/tcpip_adapter_lwip.c bsp/wlanif.c bsp/ethernetif.c
$(NAME)_CFLAGS   := -std=gnu99

ifneq ($(wifi),0)
$(NAME)_CFLAGS   += -DENABLE_WIFI
endif
$(NAME)_CFLAGS	 += -I platform/mcu/esp32/bsp

ifeq (0,1)
libs := $(wildcard platform/mcu/esp32/lib/*.a)
libs := $(foreach lib,$(libs),lib/$(notdir $(lib)))
$(NAME)_PREBUILT_LIBRARY := $(libs)
endif

$(NAME)_PREBUILT_LIBRARY := lib/libesp32.a
$(NAME)_PREBUILT_LIBRARY += lib/libsoc.a
$(NAME)_PREBUILT_LIBRARY += lib/libhal.a
$(NAME)_PREBUILT_LIBRARY += lib/libnewlib.a
$(NAME)_PREBUILT_LIBRARY += lib/libvfs.a
$(NAME)_PREBUILT_LIBRARY += lib/libspi_flash.a
$(NAME)_PREBUILT_LIBRARY += lib/liblog.a
$(NAME)_PREBUILT_LIBRARY += lib/libdriver.a
$(NAME)_PREBUILT_LIBRARY += lib/libcontainer.a
$(NAME)_PREBUILT_LIBRARY += lib/librtc.a

$(NAME)_PREBUILT_LIBRARY += lib/libcoexist.a
$(NAME)_PREBUILT_LIBRARY += lib/libcore.a
$(NAME)_PREBUILT_LIBRARY += lib/libnet80211.a
$(NAME)_PREBUILT_LIBRARY += lib/libpp.a
$(NAME)_PREBUILT_LIBRARY += lib/libwpa.a
$(NAME)_PREBUILT_LIBRARY += lib/libwpa2.a
$(NAME)_PREBUILT_LIBRARY += lib/libwps.a
$(NAME)_PREBUILT_LIBRARY += lib/libphy.a
$(NAME)_PREBUILT_LIBRARY += lib/libnvs_flash.a
$(NAME)_PREBUILT_LIBRARY += lib/libcxx.a
$(NAME)_PREBUILT_LIBRARY += lib/libstdcc++-cache-workaround.a
$(NAME)_PREBUILT_LIBRARY += lib/libwpa_supplicant.a
$(NAME)_PREBUILT_LIBRARY += lib/libapp_update.a
$(NAME)_PREBUILT_LIBRARY += lib/libbootloader_support.a

ifeq ($(vcall),freertos)
GLOBAL_CFLAGS            += -I $(IDF_PATH)/components/espos/include
GLOBAL_CFLAGS            += -I $(IDF_PATH)/components/freertos/include
$(NAME)_PREBUILT_LIBRARY += lib/libespos.a
$(NAME)_PREBUILT_LIBRARY += lib/libfreertos.a
$(NAME)_PREBUILT_LIBRARY += lib/libheap.a
else
$(NAME)_COMPONENTS       += rhino platform/arch/xtensa
$(NAME)_SOURCES          += aos/hook_impl.c
$(NAME)_SOURCES          += aos/soc_impl.c
$(NAME)_SOURCES          += aos/trace_impl.c
$(NAME)_SOURCES          += aos/heap_wrapper.c
endif

ifneq ($(mesh),0)
$(NAME)_COMPONENTS += protocols.mesh
$(NAME)_SOURCES  += hal/mesh.c
endif

ble := 0
ifneq ($(ble),0)
GLOBAL_INCLUDES += $(ESP_INC_PATH)/bt/include
$(NAME)_PREBUILT_LIBRARY += lib/libbt.a
$(NAME)_PREBUILT_LIBRARY += lib/libbtdm_app.a
GLOBAL_DEFINES   += CONFIG_ESP32_WITH_BLE
endif
