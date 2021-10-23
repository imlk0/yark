MODULE = yark
obj-m += $(MODULE).o
$(MODULE)-objs := main.o command.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install: all
	sudo insmod $(MODULE).ko

uninstall:
	sudo rmmod $(MODULE).ko

test:
	sudo dmesg -C
	sudo insmod $(MODULE).ko
	sudo netstat -antp
	sudo rmmod $(MODULE)
	sudo dmesg