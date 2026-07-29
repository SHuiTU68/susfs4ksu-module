# SPDX-License-Identifier: GPL-2.0-or-later
#
# Build the susfs_kpm KernelPatch Module.
# Targets android15-6.6 GKI kernel, arm64 only.
#
# The build mirrors the verified-working AuditPatch-KPM project
# (https://github.com/brunoanc/AuditPatch-KPM): same compiler flags, the
# same linker script that drops .plt / .init.plt / .text.ftrace_trampoline,
# and the same post-link strip pass.  These three pieces together ensure the
# final .kpm only contains relocation types the KernelPatch in-kernel loader
# (kernel/patch/module/relo.c) knows how to apply — in particular NO
# R_AARCH64_ADR_GOT / R_AARCH64_LD64_GOT, which the loader silently rejects
# and which manifest at runtime as "KPM load failed".

ifndef TARGET_COMPILE
    # Default to the NDK clang triple used by AuditPatch-KPM.  When invoked
    # from the CI workflow with CC_OVERRIDE="clang --target=aarch64-linux-gnu"
    # this prefix is ignored (CC is overridden below).
    TARGET_COMPILE = aarch64-linux-android31-
endif
ifndef KP_DIR
    KP_DIR = ../KernelPatch
endif

CC  = $(TARGET_COMPILE)clang
LD  = $(TARGET_COMPILE)ld.lld
OBJCOPY = $(TARGET_COMPILE)llvm-objcopy
STRIP   = $(TARGET_COMPILE)llvm-strip
BUILD_DIR := build

# Allow CC override (e.g. CC_OVERRIDE="clang --target=aarch64-linux-gnu" when
# the NDK is unavailable — the CI host has clang/lld from apt).
ifdef CC_OVERRIDE
CC = $(CC_OVERRIDE)
# system ld is x86-only and rejects arm64 objects; always use lld with clang.
LDFLAGS += -fuse-ld=lld
STRIP = llvm-strip
endif

INCLUDE_DIRS := . include \
                $(KP_DIR)/kernel/include \
                $(KP_DIR)/kernel/patch/include \
                $(KP_DIR)/kernel/linux/include \
                $(KP_DIR)/kernel/linux/arch/arm64/include \
                $(KP_DIR)/kernel/linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(dir))

# Flags reproduced from AuditPatch-KPM/Makefile.  Rationale:
#   -fno-PIC                       : no PIC codegen -> the compiler emits
#                                    direct absolute / PC-relative relocations
#                                    (ADR_PREL_PG_HI21, ADD_ABS_LO12_NC,
#                                    CALL26, ABS64) instead of ADR_GOT /
#                                    LD64_GOT, which the KP in-kernel loader
#                                    (kernel/patch/module/relo.c) cannot apply
#                                    and which manifest as "KPM load failed".
#                                    DO NOT add -fno-plt: under clang, -fno-plt
#                                    re-introduces GOT relocations for external
#                                    symbols even with -fno-PIC, because it
#                                    implements PLT-less calls as direct GOT
#                                    loads.  AuditPatch-KPM (a known-good KPM)
#                                    uses -fno-PIC alone.
#   -fno-semantic-interposition    : with -fno-PIC lets clang fold inter-TU
#                                    symbol refs to direct accesses.
#   -fvisibility=hidden            : default-hide non-exported symbols so no
#                                    GOT entry is needed for them.
#   -fno-common -U_FORTIFY_SOURCE -fno-stack-protector
#                                   : match kernel-style codegen, avoid extra
#                                    sections / calls that generate more
#                                    relocations.
#   -fno-asynchronous-unwind-tables -fno-unwind-tables
#                                   : drop .eh_frame (would otherwise carry
#                                    PREL32 relocs we don't need).
#   -fno-builtin -fno-builtin-memcpy -fno-builtin-memset
#                                   : stop clang from synthesising calls to
#                                    memcpy/memset for struct copies / large
#                                    initialisers.  Those bare calls would
#                                    show up as UND "memcpy" which the KP
#                                    loader cannot resolve (only kf_memcpy is
#                                    exported-via-kfunc, and even that isn't
#                                    KP_EXPORT_SYMBOL'd).  Combined with the
#                                    susfs_* function-pointer pattern in the
#                                    sources, this eliminates every
#                                    unresolvable string/mem symbol.
COMMON_CFLAGS := $(CFLAGS) $(INCLUDE_FLAGS) -c -O2 \
                 -fno-PIC -fno-semantic-interposition \
                 -fvisibility=hidden -fno-common \
                 -fno-stack-protector -U_FORTIFY_SOURCE \
                 -fno-asynchronous-unwind-tables -fno-unwind-tables \
                 -fno-builtin -fno-builtin-memcpy -fno-builtin-memset \
                 -Wall -Wno-unused-function -Wno-unused-variable

LDFLAGS += -s

# Linker script: force .plt / .init.plt / .text.ftrace_trampoline to NOLOAD
# (one byte each) so the final .kpm carries no PLT relocations.  Same script
# as AuditPatch-KPM/kpm_audit_patch.lds.
KPM_LDS := susfs_kpm.lds

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

$(BUILD_DIR)/susfs_kpm.kpm: $(KPM_OBJS) $(KPM_LDS)
	${CC} $(LDFLAGS) -T$(KPM_LDS) -r -o $@ $(KPM_OBJS)
	# Strip debugging / non-needed symbols and the comment / GNU-stack
	# sections, exactly like AuditPatch-KPM.  Keep .symtab minimally so the
	# loader can resolve .kpm.init / .kpm.ctl0 / .kpm.exit entry symbols.
	${STRIP} -g --strip-unneeded --strip-debug \
		--remove-section=.comment \
		--remove-section=.note.GNU-stack \
		$@

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
