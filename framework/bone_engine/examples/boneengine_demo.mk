NAME := boneengine_demo

$(NAME)_SOURCES := demo.c


$(NAME)_INCLUDES += ./include ./


$(NAME)_COMPONENTS := log protocol.alink  cli fota netmgr framework.common  bone_engine

#default release_log
#可选 debug release_log release
#BUILD_TYPE = release_log
#编译时可以传入该参数,如: aos make jsdemo@mk3060 BUILD_TYPE=release


ifeq ($(findstring ALI_AOS_LINUXHOST, $(CONFIG_SYSINFO_PRODUCT_MODEL)), ALI_AOS_LINUXHOST)
	GLOBAL_DEFINES += AOS_NO_WIFI
else
endif


ifneq (,${BINS})
GLOBAL_CFLAGS += -DSYSINFO_OS_BINS
endif


ifneq ($(ywss),0)
$(NAME)_COMPONENTS += ywss
endif

ifneq (,$(filter linuxhost,$(COMPONENTS)))
gateway ?= 0
else
gateway ?= 1
endif

ifeq ($(gateway),1)

$(NAME)_COMPONENTS += gateway
ifneq (,$(filter linuxhost,$(COMPONENTS)))
DDA ?= 1
endif

ifneq (,$(filter armhflinux,$(COMPONENTS)))
DDA ?= 1
endif

endif

ifeq ($(LWIP),1)
$(NAME)_COMPONENTS  += protocols.net
no_with_lwip := 0
endif

MESHDEBUG = 0
ifeq ($(meshdebug), 1)
MESHDEBUG = 1
endif

MESHSUPER = 0
ifeq ($(meshsuper), 1)
MESHSUPER = 1
endif

ifeq ($(DDA),1)
GLOBAL_LDFLAGS += -lreadline -lncurses
$(NAME)_COMPONENTS  += dda
endif

ifeq ($(sds),1)
GLOBAL_DEFINES += CONFIG_SDS
endif



ifeq ($(BENCHMARKS),1)
$(NAME)_COMPONENTS  += benchmarks
GLOBAL_DEFINES      += CONFIG_CMD_BENCHMARKS
endif



#CURRENT_TIME = $(shell /bin/date +%Y%m%d.%H%M)
#CONFIG_SYSINFO_APP_VERSION = APP-1.0.0-$(CURRENT_TIME)
#$(info app_version:${CONFIG_SYSINFO_APP_VERSION})
#GLOBAL_CFLAGS += -DSYSINFO_APP_VERSION=\"$(CONFIG_SYSINFO_APP_VERSION)\"

