/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/kern_levels.h>
#include <linux/errno.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>

KPM_NAME("kpm-syscall-hook-demo");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("KernelPatch Module System Call Hook Example");

const char *margs = 0;
enum hook_type hook_type = NONE;

enum pid_type
{
    PIDTYPE_PID,
    PIDTYPE_TGID,
    PIDTYPE_PGID,
    PIDTYPE_SID,
    PIDTYPE_MAX,
};
struct pid_namespace;
pid_t (*__task_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;

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
    if (__task_pid_nr_ns) {
        pid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
        tgid = __task_pid_nr_ns(task, PIDTYPE_TGID, 0);
    }

    args->local.data0 = (uint64_t)task;

    printk(KERN_INFO "[KP] hook_chain_0 task: %llx, pid: %d, tgid: %d, openat dfd: %d, filename: %s, flag: %x, mode: %d\n", task, pid,
            tgid, dfd, buf, flag, mode);
}

uint64_t open_counts = 0;
uint64_t ptrace_counts = 0;

// 调试绕过配置
static bool enable_debug_bypass = true;  // 默认启用调试绕过

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

// ptrace系统调用hook - 用于检测和绕过调试行为
void before_ptrace_0(hook_fargs4_t *args, void *udata)
{
    long request = (long)syscall_argn(args, 0);
    pid_t target_pid = (pid_t)syscall_argn(args, 1);

    struct task_struct *task = current;
    pid_t pid = -1, tgid = -1;
    if (__task_pid_nr_ns) {
        pid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
        tgid = __task_pid_nr_ns(task, PIDTYPE_TGID, 0);
    }

    ptrace_counts++;
    
    if (enable_debug_bypass) {
        // 标记需要绕过调试
        args->local.data0 = 1;  // 标记为需要绕过的ptrace调用
        printk(KERN_WARNING "[KP] PTRACE BYPASS! pid:%d tgid:%d request:%ld target:%d count:%llu\n", 
               pid, tgid, request, target_pid, ptrace_counts);
    } else {
        args->local.data0 = 0;  // 正常记录
        printk(KERN_WARNING "[KP] PTRACE DETECTED! pid:%d tgid:%d request:%ld target:%d count:%llu\n", 
               pid, tgid, request, target_pid, ptrace_counts);
    }
}

// ptrace after hook - 实现调试绕过
void after_ptrace_0(hook_fargs4_t *args, void *udata)
{
    if (args->local.data0 == 1 && enable_debug_bypass) {
        // 让ptrace调用失败，返回权限错误
        args->ret = -EPERM;  // Operation not permitted
        printk(KERN_INFO "[KP] Ptrace call bypassed with -EPERM\n");
    }
}

static long syscall_hook_demo_init(const char *args, const char *event, void *__user reserved)
{
    margs = args;
    printk(KERN_INFO "[KP] kpm-syscall-hook-demo init ..., args: %s\n", margs);

    __task_pid_nr_ns = (typeof(__task_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
    printk(KERN_INFO "[KP] kernel function __task_pid_nr_ns addr: %llx\n", __task_pid_nr_ns);

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
        if (err) goto out;
        
        // 添加ptrace系统调用监控和绕过(高危操作检测+绕过)
        err = fp_hook_syscalln(__NR_ptrace, 4, before_ptrace_0, after_ptrace_0, 0);
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
    printk(KERN_INFO "[KP] syscall_hook control, args: %s\n", args ? args : "null");
    
    if (!args) {
        printk(KERN_INFO "[KP] Available commands:\n");
        printk(KERN_INFO "[KP]   hook_openat_fp - Install openat function pointer hook\n");
        printk(KERN_INFO "[KP]   hook_openat_inline - Install openat inline hook\n");
        printk(KERN_INFO "[KP]   hook_ptrace_fp - Install ptrace function pointer hook\n");
        printk(KERN_INFO "[KP]   unhook_openat - Remove openat hooks\n");
        printk(KERN_INFO "[KP]   unhook_ptrace - Remove ptrace hooks\n");
        printk(KERN_INFO "[KP]   unhook_all - Remove all hooks\n");
        printk(KERN_INFO "[KP]   enable_bypass - Enable ptrace bypass\n");
        printk(KERN_INFO "[KP]   disable_bypass - Disable ptrace bypass\n");
        printk(KERN_INFO "[KP]   status - Show current status\n");
        return 0;
    }
    
    hook_err_t err = HOOK_NO_ERR;
    
    // 单一职责命令 - 每个命令只做一件事
    if (!strcmp("hook_openat_fp", args)) {
        printk(KERN_INFO "[KP] Installing openat function pointer hook...\n");
        // 先尝试移除可能存在的旧hook，避免重复安装
        fp_unhook_syscalln(__NR_openat, before_openat_0, 0);
        fp_unhook_syscalln(__NR_openat, before_openat_1, after_openat_1);
        err = fp_hook_syscalln(__NR_openat, 4, before_openat_0, 0, 0);
        if (err) goto out;
        err = fp_hook_syscalln(__NR_openat, 4, before_openat_1, after_openat_1, &open_counts);
        
    } else if (!strcmp("hook_openat_inline", args)) {
        printk(KERN_INFO "[KP] Installing openat inline hook...\n");
        // 先尝试移除可能存在的旧hook，避免重复安装
        inline_unhook_syscalln(__NR_openat, before_openat_0, 0);
        err = inline_hook_syscalln(__NR_openat, 4, before_openat_0, 0, 0);
        
    } else if (!strcmp("hook_ptrace_fp", args)) {
        printk(KERN_INFO "[KP] Installing ptrace function pointer hook...\n");
        // 先尝试移除可能存在的旧hook，避免重复安装
        fp_unhook_syscalln(__NR_ptrace, before_ptrace_0, after_ptrace_0);
        err = fp_hook_syscalln(__NR_ptrace, 4, before_ptrace_0, after_ptrace_0, 0);
        
    } else if (!strcmp("unhook_openat", args)) {
        printk(KERN_INFO "[KP] Removing openat hooks...\n");
        // 移除所有openat相关hook
        inline_unhook_syscalln(__NR_openat, before_openat_0, 0);
        fp_unhook_syscalln(__NR_openat, before_openat_0, 0);
        fp_unhook_syscalln(__NR_openat, before_openat_1, after_openat_1);
        printk(KERN_INFO "[KP] Openat hooks removed\n");
        return 0;
        
    } else if (!strcmp("unhook_ptrace", args)) {
        printk(KERN_INFO "[KP] Removing ptrace hooks...\n");
        fp_unhook_syscalln(__NR_ptrace, before_ptrace_0, after_ptrace_0);
        printk(KERN_INFO "[KP] Ptrace hooks removed\n");
        return 0;
        
    } else if (!strcmp("unhook_all", args)) {
        printk(KERN_INFO "[KP] Removing all hooks...\n");
        // 移除所有hook
        inline_unhook_syscalln(__NR_openat, before_openat_0, 0);
        fp_unhook_syscalln(__NR_openat, before_openat_0, 0);
        fp_unhook_syscalln(__NR_openat, before_openat_1, after_openat_1);
        fp_unhook_syscalln(__NR_ptrace, before_ptrace_0, after_ptrace_0);
        hook_type = NONE;
        printk(KERN_INFO "[KP] All hooks removed\n");
        return 0;
        
    } else if (!strcmp("status", args)) {
        printk(KERN_INFO "[KP] === Current Status ===\n");
        printk(KERN_INFO "[KP] Hook type: %s\n", 
               (hook_type == FUNCTION_POINTER_CHAIN) ? "FUNCTION_POINTER" :
               (hook_type == INLINE_CHAIN) ? "INLINE" : "NONE");
        printk(KERN_INFO "[KP] Open counts: %llu\n", open_counts);
        printk(KERN_INFO "[KP] Ptrace counts: %llu\n", ptrace_counts);
        printk(KERN_INFO "[KP] Debug bypass: %s\n", enable_debug_bypass ? "ENABLED" : "DISABLED");
        return 0;
        
    } else if (!strcmp("enable_bypass", args)) {
        enable_debug_bypass = true;
        printk(KERN_INFO "[KP] Debug bypass enabled - ptrace calls will be blocked\n");
        return 0;
        
    } else if (!strcmp("disable_bypass", args)) {
        enable_debug_bypass = false;
        printk(KERN_INFO "[KP] Debug bypass disabled - ptrace calls will be monitored only\n");
        return 0;
        
    } else {
        printk(KERN_WARNING "[KP] Unknown command: %s\n", args);
        return -1;
    }

out:
    if (err) {
        switch (err) {
            case HOOK_DUPLICATED:
                printk(KERN_WARNING "[KP] Hook already exists (code: %d)\n", err);
                break;
            case HOOK_BAD_ADDRESS:
                printk(KERN_ERR "[KP] Invalid hook address (code: %d)\n", err);
                break;
            case HOOK_NO_MEM:
                printk(KERN_ERR "[KP] Insufficient memory for hook (code: %d)\n", err);
                break;
            case HOOK_CHAIN_FULL:
                printk(KERN_ERR "[KP] Hook chain is full (code: %d)\n", err);
                break;
            default:
                printk(KERN_ERR "[KP] Hook operation error: %d\n", err);
                break;
        }
        return -1;
    } else {
        printk(KERN_INFO "[KP] Hook operation success\n");
    }
    return 0;
}

static long syscall_hook_demo_exit(void *__user reserved)
{
    printk(KERN_INFO "[KP] kpm-syscall-hook-demo exit ...\n");

    if (hook_type == INLINE_CHAIN) {
        inline_unhook_syscalln(__NR_openat, before_openat_0, 0);
    } else if (hook_type == FUNCTION_POINTER_CHAIN) {
        fp_unhook_syscalln(__NR_openat, before_openat_0, 0);
        fp_unhook_syscalln(__NR_openat, before_openat_1, after_openat_1);
        fp_unhook_syscalln(__NR_ptrace, before_ptrace_0, 0);
    } else {
    }
    return 0;
}

KPM_INIT(syscall_hook_demo_init);
KPM_CTL0(syscall_hook_control0);
KPM_EXIT(syscall_hook_demo_exit);