obj-m += yark.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install: all
	sudo insmod yark.ko

uninstall:
	sudo rmmod yark.ko
