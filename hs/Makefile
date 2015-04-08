
KDIR := /home/hitmoon/work/android/linux-3.4
#KDIR := /home/hitmoon/work/android/msm-kernel
ARG = ARCH=arm CROSS_COMPILE=arm-linux-androideabi-
MAKE = make
CC = arm-linux-androideabi-gcc
# ccflags-y += -fno-pic -DDEBUG -DKPROBE
ccflags-y += -fno-pic -DDEBUG

obj-m += hs.o
hs-y := kp.o ksyms.o

all:
	$(MAKE) -C $(KDIR) $(ARG)  M=$(shell pwd) modules


.PHONY: clean
clean:
	rm -fv *.o *.mod.*
	rm -fv *.ko

