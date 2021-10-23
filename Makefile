MODULE = yark
obj-m += $(MODULE).o
$(MODULE)-objs := main.o command.o

LKMNAME += yark.ko

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install: all
	sudo insmod yark.ko

uninstall:
	sudo rmmod yark.ko

test:
	sudo dmesg -C
	sudo insmod $(LKMNAME)
	sudo netstat -antp
	sudo rmmod $(LKMNAME)
	sudo dmesg