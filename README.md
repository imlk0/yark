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

