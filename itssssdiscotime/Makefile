# iOS 10.3 is the newest SDK that can still build armv7 (32-bit devices).
# Supports iOS 5.0 and up (the arm64 slices only ever load on iOS 7+).
TARGET := iphone:clang:10.3:5.0
ARCHS = armv7 arm64 arm64e
INSTALL_TARGET_PROCESSES = SpringBoard


include $(THEOS)/makefiles/common.mk

TWEAK_NAME = itssssdiscotime

itssssdiscotime_FILES = Tweak.x
itssssdiscotime_CFLAGS = -fobjc-arc
itssssdiscotime_FRAMEWORKS = UIKit
# The 10.3 SDK's libobjc stub omits objc_msgSend_stret, which armv7 uses for
# struct returns like UIScreen.bounds. The device's libobjc has it, so look it up at load time.
itssssdiscotime_LDFLAGS = -Wl,-U,_objc_msgSend_stret

include $(THEOS_MAKE_PATH)/tweak.mk
