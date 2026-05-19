LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE        := hotspotd
LOCAL_SRC_FILES     := hotspotd.c
LOCAL_CFLAGS        := -O2 -Wall -Wextra -D_GNU_SOURCE -DANDROID
LOCAL_LDFLAGS       := -fPIE -pie
LOCAL_MODULE_TAGS   := optional
LOCAL_FORCE_STATIC_EXECUTABLE := false
include $(BUILD_EXECUTABLE)
