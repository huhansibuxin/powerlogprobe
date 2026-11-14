# PowerlogProbe v1.3.0 RELEASE - write filter for com.apple.aggregated
# (rootless + roothide)
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
# objc/runtime class_replaceMethod, never %hook / MSHookFunction, so
# dead-stripping is safe. Plan C3 never opens the database itself - it filters
# entries before SQL is issued, so no libsqlite3 link is needed. The RELEASE
# build also writes no log file: no fcntl/unistd writes, no mutex, no counters.
PowerlogProbe_LDFLAGS = -Wl,-dead_strip_dylibs
PowerlogProbe_CFLAGS = -Os
ERROR_ON_WARNINGS = 0

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk
