ARCHS = arm64 arm64e
TARGET = iphone:clang:14.5:14.0
include $(THEOS)/makefiles/common.mk
TWEAK_NAME = APNsRoute
APNsRoute_FILES = src/Tweak.c src/HookEngine.c src/Diagnostics.c src/Connections.c src/Retirement.c src/NECPHooks.c src/NECPResults.c src/TunnelSelector.c src/InterfaceCheck.c src/NWHooks.c src/NWObserver.c
APNsRoute_CFLAGS = -std=c11 -Wall -Wextra -Werror -O2 -fvisibility=hidden -fblocks
APNsRoute_FRAMEWORKS = Network
APNsRoute_USE_SUBSTRATE = 0
include $(THEOS_MAKE_PATH)/tweak.mk

TOOL_NAME = apnsroute-diag
apnsroute-diag_FILES = src/Diagnose.c src/LiveSockets.c
apnsroute-diag_ARCHS = arm64
apnsroute-diag_CFLAGS = -Isrc/vendor -std=c11 -Wall -Wextra -Werror -O2
apnsroute-diag_INSTALL_PATH = /usr/libexec
include $(THEOS_MAKE_PATH)/tool.mk
