# SPDX-License-Identifier: GPL-2.0-or-later
#
# Build the susfs_kpm KernelPatch Module.
# Targets android15-6.6 GKI kernel, arm64 only.
#
# Reference: KernelPatch/kpms/demo-hello/Makefile and
#            gh_disable_deferred_split_KernelPatch/Makefile
ifndef TARGET_COMPILE
    TARGET_COMPILE = aarch64-linux-gnu-
endif
ifndef KP_DIR
    KP_DIR = ../KernelPatch
endif

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld
BUILD_DIR := build

# Allow CC override (e.g. CC="clang --target=aarch64-linux-gnu" for clang)
ifdef CC_OVERRIDE
CC = $(CC_OVERRIDE)
endif

INCLUDE_DIRS := . include \
                $(KP_DIR)/kernel/include \
                $(KP_DIR)/kernel/patch/include \
                $(KP_DIR)/kernel/linux/include \
                $(KP_DIR)/kernel/linux/arch/arm64/include \
                $(KP_DIR)/kernel/linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(dir))

# When using clang as a cross-compiler, lld is preferred (the system ld is
# usually x86-only and rejects arm64 objects).
ifdef CC_OVERRIDE
LDFLAGS += -fuse-ld=lld
endif

# KPM relocation constraints:
#  -mcmodel=large            : literal pool for data refs (ABS64, no range limit)
#  -fno-pic -fno-plt         : no PIC/PLT, KPM is loaded at a fixed addr
#  -fno-asynchronous-unwind-tables / -fno-unwind-tables
#                            : avoid .eh_frame PREL32 relo overflow
#  -mno-outline-atomics      : avoid out-of-range BL to libatomic helpers
COMMON_CFLAGS := $(CFLAGS) $(INCLUDE_FLAGS) -c -O2 \
                 -mcmodel=large -fno-pic -fno-plt \
                 -fno-asynchronous-unwind-tables -fno-unwind-tables \
                 -mno-outline-atomics \
                 -Wall -Wno-unused-function -Wno-unused-variable

KPM_SRCS := \
    susfs_kpm.c \
    features/sus_path.c \
    features/open_redirect.c \
    features/sus_mount.c \
    features/sus_kstat.c \
    features/sus_map.c \
    features/set_uname.c \
    features/set_cmdline.c \
    features/flags.c \
    features/show.c

KPM_OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(KPM_SRCS))

all: $(BUILD_DIR)/susfs_kpm.kpm

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/features: | $(BUILD_DIR)
	mkdir -p $@

# order-only prerequisite to create build subdirs
$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR) $(BUILD_DIR)/features
	${CC} $(COMMON_CFLAGS) -o $@ $<

$(BUILD_DIR)/susfs_kpm.kpm: $(KPM_OBJS)
	${CC} $(LDFLAGS) -r -o $@ $^

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
