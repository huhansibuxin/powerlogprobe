# PowerlogProbe - read-only diagnostic tweak for com.apple.aggregated
# Rootless + Roothide dual variant. THEOS_PACKAGE_SCHEME is overridden by CI
# per matrix job; the ?= below is only the local default (never use '=' here).
export TARGET = iphone:clang:latest:16.0
export ARCHS = arm64e

THEOS_PACKAGE_SCHEME ?= rootless
export THEOS_PACKAGE_SCHEME
export _THEOS_PLATFORM_DPKG_DEB_COMPRESSION = gzip

TWEAK_NAME = PowerlogProbe
PowerlogProbe_FILES = Tweak.xm

# Zero substrate/ellekit LINK dependency. aggregated is a launchd daemon; if it
# cannot dlopen libellekit, any LC_LOAD_DYLIB referencing it makes our dylib
# fail to load silently (proven on keybagd, 2026-09-28). We only use %ctor plus
# objc/runtime method_setImplementation, never %hook / MSHookFunction, so
# dead-stripping is safe. Plan A needs no libsqlite3 anymore - we never open the
# database, we short-circuit before SQL is issued.
PowerlogProbe_LDFLAGS = -Wl,-dead_strip_dylibs
PowerlogProbe_CFLAGS = -Os
ERROR_ON_WARNINGS = 0

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk
