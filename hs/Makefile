
KDIR := /Volumes/android/msm-kernel
ARG = ARCH=arm CROSS_COMPILE=arm-linux-androideabi-
MAKE = make
CC = arm-linux-androideabi-gcc
ccflags-y += -fno-pic

obj-m += kp.o

all:
	$(MAKE) -C $(KDIR) $(ARG)  M=$(shell pwd) modules



