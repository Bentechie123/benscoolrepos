# iOS 10.3 is the newest SDK that can still build armv7 (32-bit devices).
# Runs on iOS 5.0 and up. No arm64e: no arm64e device ever ran iOS 10 or older.
TARGET := iphone:clang:10.3:5.0
ARCHS = armv7 arm64

include $(THEOS)/makefiles/common.mk

TOOL_NAME = benscertfix

benscertfix_FILES = main.m
benscertfix_CFLAGS = -fobjc-arc
benscertfix_LDFLAGS = -lsqlite3
benscertfix_INSTALL_PATH = /usr/bin

# iOS 5 needs the crt1.3.1.o startup file to run a 32-bit program. The 10.3 SDK
# doesn't ship it, the 9.3 SDK does; without it the armv7 build would need iOS 7.
# Expose just that one file (the rest of the 9.3 SDK's usr/lib breaks the link).
CRT_DIR := $(THEOS_PROJECT_DIR)/.theos/crt
benscertfix_LDFLAGS += -L$(CRT_DIR)

include $(THEOS_MAKE_PATH)/tool.mk

before-all::
	@mkdir -p $(CRT_DIR)
	@ln -sf $(THEOS)/sdks/iPhoneOS9.3.sdk/usr/lib/crt1.3.1.o $(CRT_DIR)/crt1.3.1.o
