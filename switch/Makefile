#──────────────────────────────────────────────────────────────────
# cutecontainer Switch homebrew (NRO)
#
# Usage:
#   make                   → builds cute-demo.nro
#   make run SWITCH_IP=x   → sends to Switch via nxlink
#   make clean
#
# Prerequisites:
#   Build libcutecontainer for Switch first:
#     cd .. && ./build.sh --target libnx
#──────────────────────────────────────────────────────────────────

APP_NAME    := cute-demo
APP_TITLE   := cutecontainer demo
APP_AUTHOR  := cutecontainer
APP_VERSION := 1.0.0
APP_SOURCES := main.c
APP_LIBS    := ../build/libnx/libcutecontainer.a

CFLAGS += -I../include

include ../../shared/switch-template/Makefile
