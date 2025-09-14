/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/kern_levels.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/kernel.h>

KPM_NAME("kpm-syscall-hook-demo");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("GHOSTXX");
KPM_DESCRIPTION("KernelPatch Module System Call Hook Example");

const char *margs = 0;
enum hook_type hook_type = NONE;

// 这些定义已经在 linux/sched.h 中存在，不需要重复定义

void before_openat_0(hook_fargs4_t *args, void *udata)
{
    int dfd = (int)syscall_argn(args, 0);
    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    int flag = (int)syscall_argn(args, 2);
    umode_t mode = (int)syscall_argn(args, 3);

    char buf[1024];
    compat_strncpy_from_user(buf, filename, sizeof(buf));

    struct task_struct *task = current;
    pid_t pid = -1, tgid = -1;
    
    // 使用内核提供的函数获取PID和TGID
    pid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
    tgid = __task_pid_nr_ns(task, PIDTYPE_TGID, 0);

    args->local.data0 = (uint64_t)task;

    // 输出详细信息 (PID开头便于过滤)
    printk(KERN_INFO "[KP] pid: %d, tgid: %d, task: %llx, openat dfd: %d, filename: %s, flag: %x, mode: %d\n", 
           pid, tgid, task, dfd, buf, flag, mode);
}

uint64_t open_counts = 0;

void before_openat_1(hook_fargs4_t *args, void *udata)
{
    uint64_t *pcount = (uint64_t *)udata;
    (*pcount)++;
    printk(KERN_INFO "[KP] hook_chain_1 before openat task: %llx, count: %llx\n", args->local.data0, *pcount);
}

void after_openat_1(hook_fargs4_t *args, void *udata)
{
    printk(KERN_INFO "[KP] hook_chain_1 after openat task: %llx\n", args->local.data0);
}

static long syscall_hook_demo_init(const char *args, const char *event, void *__user reserved)
{
    margs = args;
    printk(KERN_INFO "[KP] kpm-syscall-hook-demo init ..., args: %s\n", margs);

    // __task_pid_nr_ns 函数已经通过头文件可用，不需要动态查找
    printk(KERN_INFO "[KP] kernel function __task_pid_nr_ns available via headers\n");

    if (!margs) {
        printk(KERN_WARNING "[KP] no args specified, skip hook\n");
        return 0;
    }

    hook_err_t err = HOOK_NO_ERR;

    if (!strcmp("function_pointer_hook", margs)) {
        printk(KERN_INFO "[KP] function pointer hook ...\n");
        hook_type = FUNCTION_POINTER_CHAIN;
        err = fp_hook_syscalln(__NR_openat, 4, before_openat_0, 0, 0);
        if (err) goto out;
        err = fp_hook_syscalln(__NR_openat, 4, before_openat_1, after_openat_1, &open_counts);
    } else if (!strcmp("inline_hook", margs)) {
        printk(KERN_INFO "[KP] inline hook ...\n");
        hook_type = INLINE_CHAIN;
        err = inline_hook_syscalln(__NR_openat, 4, before_openat_0, 0, 0);
    } else {
        printk(KERN_WARNING "[KP] unknown args: %s\n", margs);
        return 0;
    }

out:
    if (err) {
        printk(KERN_ERR "[KP] hook openat error: %d\n", err);
    } else {
        printk(KERN_INFO "[KP] hook openat success\n");
    }
    return 0;
}

static long syscall_hook_control0(const char *args, char *__user out_msg, int outlen)
{
    printk(KERN_INFO "[KP] syscall_hook control, args: %s\n", args);
    
    if (!args) {
        printk(KERN_WARNING "[KP] control: no args specified\n");
        return -1;
    }
    
    hook_err_t err = HOOK_NO_ERR;
    
    if (!strcmp("function_pointer_hook", args)) {
        printk(KERN_INFO "[KP] control: setting up function pointer hook ...\n");
        
        // 如果已经有钩子，先清理
        if (hook_type == FUNCTION_POINTER_CHAIN) {
            fp_unhook_syscalln(__NR_openat, before_openat_0, 0);
            fp_unhook_syscalln(__NR_openat, before_openat_1, after_openat_1);
        } else if (hook_type == INLINE_CHAIN) {
            inline_unhook_syscalln(__NR_openat, before_openat_0, 0);
        }
        
        hook_type = FUNCTION_POINTER_CHAIN;
        err = fp_hook_syscalln(__NR_openat, 4, before_openat_0, 0, 0);
        if (err) goto out_control;
        err = fp_hook_syscalln(__NR_openat, 4, before_openat_1, after_openat_1, &open_counts);
        
    } else if (!strcmp("inline_hook", args)) {
        printk(KERN_INFO "[KP] control: setting up inline hook ...\n");
        
        // 如果已经有钩子，先清理
        if (hook_type == FUNCTION_POINTER_CHAIN) {
            fp_unhook_syscalln(__NR_openat, before_openat_0, 0);
            fp_unhook_syscalln(__NR_openat, before_openat_1, after_openat_1);
        } else if (hook_type == INLINE_CHAIN) {
            inline_unhook_syscalln(__NR_openat, before_openat_0, 0);
        }
        
        hook_type = INLINE_CHAIN;
        err = inline_hook_syscalln(__NR_openat, 4, before_openat_0, 0, 0);
        
    } else if (!strcmp("unhook", args)) {
        printk(KERN_INFO "[KP] control: removing hooks ...\n");
        
        if (hook_type == FUNCTION_POINTER_CHAIN) {
            fp_unhook_syscalln(__NR_openat, before_openat_0, 0);
            fp_unhook_syscalln(__NR_openat, before_openat_1, after_openat_1);
        } else if (hook_type == INLINE_CHAIN) {
            inline_unhook_syscalln(__NR_openat, before_openat_0, 0);
        }
        hook_type = NONE;
        printk(KERN_INFO "[KP] control: hooks removed\n");
        return 0;
        
    } else if (!strcmp("status", args)) {
        printk(KERN_INFO "[KP] control: Status - Hook type: %d\n", hook_type);
        return 0;
        
    } else {
        printk(KERN_WARNING "[KP] control: unknown args: %s\n", args);
        printk(KERN_INFO "[KP] control: Available commands:\n");
        printk(KERN_INFO "[KP] control:   function_pointer_hook - Enable function pointer hook\n");
        printk(KERN_INFO "[KP] control:   inline_hook - Enable inline hook\n");
        printk(KERN_INFO "[KP] control:   unhook - Remove all hooks\n");
        printk(KERN_INFO "[KP] control:   status - Show current status\n");
        return -1;
    }

out_control:
    if (err) {
        printk(KERN_ERR "[KP] control: hook openat error: %d\n", err);
        return -1;
    } else {
        printk(KERN_INFO "[KP] control: hook openat success\n");
        return 0;
    }
}

static long syscall_hook_demo_exit(void *__user reserved)
{
    printk(KERN_INFO "[KP] kpm-syscall-hook-demo exit ...\n");

    if (hook_type == INLINE_CHAIN) {
        inline_unhook_syscalln(__NR_openat, before_openat_0, 0);
    } else if (hook_type == FUNCTION_POINTER_CHAIN) {
        fp_unhook_syscalln(__NR_openat, before_openat_0, 0);
        fp_unhook_syscalln(__NR_openat, before_openat_1, after_openat_1);
    } else {
    }
    return 0;
}

KPM_INIT(syscall_hook_demo_init);
KPM_CTL0(syscall_hook_control0);
KPM_EXIT(syscall_hook_demo_exit);