/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved. 
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>

KPM_NAME("kpm-syscall-hook-demo-improved");
KPM_VERSION("2.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("Improved KernelPatch Module System Call Hook Example");

const char *margs = 0;
enum hook_type hook_type = NONE;

// 保存原始hook句柄
static void *openat_hook_handle = NULL;

uint64_t open_counts = 0;

void before_openat_improved(hook_fargs4_t *args, void *udata) {
    int dfd = (int)syscall_argn(args, 0);
    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    int flag = (int)syscall_argn(args, 2);
    umode_t mode = (int)syscall_argn(args, 3);
    
    char buf[256];
    long ret;
    
    // 尝试读取文件名
    ret = strncpy_from_user_nofault(buf, filename, sizeof(buf) - 1);
    if (ret > 0) {
        buf[ret] = '\0';
        pr_info("openat hook: dfd=%d, filename=%s, flags=0x%x, mode=0x%x\n", 
                dfd, buf, flag, mode);
    } else {
        pr_info("openat hook: dfd=%d, flags=0x%x, mode=0x%x\n", dfd, flag, mode);
    }
    
    // 统计计数
    open_counts++;
}

void after_openat_improved(hook_fargs4_t *args, void *udata) {
    long ret = (long)syscall_argn(args, 4); // 获取返回值
    
    if (ret < 0) {
        pr_info("openat failed with error: %ld\n", ret);
    } else {
        pr_info("openat succeeded, fd: %ld\n", ret);
    }
}

static long syscall_hook_demo_init(const char *args, const char *event, void *__user reserved) {
    int err = 0;
    margs = args;
    
    pr_info("kpm-syscall-hook-demo-improved init ..., args: %s\n", margs);

    // Hook openat系统调用
    err = hook_syscall(__NR_openat, before_openat_improved, after_openat_improved, 
                      HOOK_TYPE_BEFORE_AFTER, &open_counts, &openat_hook_handle);
    
    if (err) {
        pr_err("hook openat error: %d\n", err);
        return err;
    } else {
        pr_info("hook openat success\n");
    }
    
    return 0;
}

static long syscall_hook_control0(const char *args, char *__user out_msg, int outlen) {
    pr_info("syscall_hook control, args: %s\n", args);
    
    // 可以添加控制逻辑，比如返回统计信息
    if (out_msg && outlen > 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "Open counts: %llu", open_counts);
        copy_to_user(out_msg, msg, min((int)strlen(msg) + 1, outlen));
    }
    
    return 0;
}

static long syscall_hook_demo_exit(void *__user reserved) {
    pr_info("kpm-syscall-hook-demo-improved exit ...\n");
    
    // 取消hook
    if (openat_hook_handle) {
        unhook_syscall(openat_hook_handle);
        pr_info("unhook openat success\n");
    }
    
    pr_info("Total openat calls: %llu\n", open_counts);
    
    return 0;
}

KPM_INIT(syscall_hook_demo_init);
KPM_CTL0(syscall_hook_control0);
KPM_EXIT(syscall_hook_demo_exit);
