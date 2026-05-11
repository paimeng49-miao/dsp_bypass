# Build dsp_bypass.kpm with the KernelPatch SDK and Android NDK clang.
#
# Override these on the command line if your paths differ:
#   make KP_DIR=/path/to/KernelPatch NDK_HOME=/path/to/ndk

KP_DIR   ?= $(HOME)/KernelPatch
NDK_HOME ?= $(HOME)/Android/Sdk/ndk/25.2.9519653

CC := $(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang

INC := -I$(KP_DIR)/kernel/include \
       -I$(KP_DIR)/kernel/patch/include \
       -I$(KP_DIR)/kernel/linux/include \
       -I$(KP_DIR)/kernel/linux/arch/arm64/include \
       -I$(KP_DIR)/kernel/linux/tools/arch/arm64/include

CFLAGS := -O2 -Wall -nostdinc -ffreestanding -fno-stack-protector \
          -fno-pic -fno-pie -fno-common -mgeneral-regs-only

TARGET := dsp_bypass.kpm
OBJ    := dsp_bypass.o

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -r -nostdlib -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

clean:
	rm -f *.o *.kpm

.PHONY: all clean
