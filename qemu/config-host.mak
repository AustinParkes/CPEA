# Automatically generated by configure - do not modify

all:
extra_cflags=-m64 -DUNICORN_HAS_ARM -DUNICORN_HAS_ARMEB -fPIC -fvisibility=hidden
extra_ldflags=
ARCH=x86_64
STRIP=strip
CONFIG_POSIX=y
CONFIG_LINUX=y
SRC_PATH=/home/austin/school/thesis/unicorn-1.0.2/qemu
TARGET_DIRS=arm-softmmu  armeb-softmmu 
CONFIG_BYTESWAP_H=y
CONFIG_VALGRIND_H=y
CONFIG_CPUID_H=y
CONFIG_INT128=y
MAKE=make
CC=cc
CC_I386=$(CC) -m32
HOST_CC=cc
OBJCC=cc
AR=ar
ARFLAGS=rv
AS=as
CPP=cc -E
OBJCOPY=objcopy
LD=ld
NM=nm
CFLAGS=-g 
CFLAGS_NOPIE=
QEMU_CFLAGS=-fPIE -DPIE -m64 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -Wstrict-prototypes -Wredundant-decls -Wall -Wundef -Wwrite-strings -Wmissing-prototypes -fno-strict-aliasing -fno-common -DUNICORN_HAS_ARM -DUNICORN_HAS_ARMEB -fPIC -fvisibility=hidden  -Wendif-labels -Wmissing-include-dirs -Wempty-body -Wnested-externs -Wformat-security -Wformat-y2k -Winit-self -Wignored-qualifiers -Wold-style-declaration -Wold-style-definition -Wtype-limits -fstack-protector-strong
QEMU_INCLUDES=-I$(SRC_PATH)/tcg -I$(SRC_PATH)/tcg/i386 -I. -I$(SRC_PATH) -I$(SRC_PATH)/include
LDFLAGS=-Wl,--warn-common -Wl,-z,relro -Wl,-z,now -pie -m64 -g 
LDFLAGS_NOPIE=
LIBS+=-lm -pthread  -lrt
EXESUF=
DSOSUF=.so
LDFLAGS_SHARED=-shared
TRANSLATE_OPT_CFLAGS=
