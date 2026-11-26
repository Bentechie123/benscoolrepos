# iOS 10.3 is the newest SDK that can still build armv7 (32-bit devices).
# Supports iOS 5.0 and up (the arm64 slices only ever load on iOS 7+).
TARGET := iphone:clang:10.3:5.0
ARCHS = armv7 arm64 arm64e
INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = benscarrier

benscarrier_FILES = Tweak.x
benscarrier_CFLAGS = -fobjc-arc
benscarrier_FRAMEWORKS = UIKit

include $(THEOS_MAKE_PATH)/tweak.mk
