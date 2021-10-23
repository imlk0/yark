# example to use yhook
```c
#include "yhook.h"

// Suppose there is a function called 'func'
static asmlinkage long (*orig_func)(...);

static asmlinkage long hook_func(...)
{
    // do some thing...
    return orig_func(...);
}

static int __init lkm_init(void)
{
    hook_function_name_add("func", hook_func, &orig_func);
    return 0;
}

static void __exit lkm_exit(void) {
    hook_function_name_del("func");
}

module_init(lkm_init);
module_exit(lkm_exit);
```