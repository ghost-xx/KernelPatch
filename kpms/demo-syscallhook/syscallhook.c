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
#include <linux/stacktrace.h>

KPM_NAME("kpm-syscall-hook-demo");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("KernelPatch Module System Call Hook Example");

const char *margs = 0;
enum hook_type hook_type = NONE;

// 栈回溯配置
static bool enable_stack_trace = false;

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

// KernelPatch栈回溯函数
static void do_stack_trace(pid_t pid)
{
    #define MAX_STACK_ENTRIES 16
    unsigned long entries[MAX_STACK_ENTRIES];
    struct stack_trace trace;
    int i;
    
    if (!enable_stack_trace) return;
    
    // 初始化栈跟踪结构
    trace.nr_entries = 0;
    trace.max_entries = MAX_STACK_ENTRIES;
    trace.entries = entries;
    trace.skip = 0;
    
    pr_info("[KP] === Stack trace for pid:%d ===\n", pid);
    
    // 使用KernelPatch提供的用户空间栈回溯
    save_stack_trace_user(&trace);
    
    if (trace.nr_entries == 0) {
        pr_info("[KP] pid:%d No stack entries found\n", pid);
        return;
    }
    
    // 打印栈回溯信息
    for (i = 0; i < trace.nr_entries; i++) {
        pr_info("[KP] pid:%d frame[%d]: 0x%lx\n", pid, i, trace.entries[i]);
    }
    
    pr_info("[KP] === End stack trace (%d entries) ===\n", trace.nr_entries);
}

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

    // 执行栈回溯（如果启用）
    do_stack_trace(pid);

    pr_info("hook_chain_0 task: %llx, pid: %d, tgid: %d, openat dfd: %d, filename: %s, flag: %x, mode: %d\n", task, pid,
            tgid, dfd, buf, flag, mode);
}

uint64_t open_counts = 0;

void before_openat_1(hook_fargs4_t *args, void *udata)
{
    uint64_t *pcount = (uint64_t *)udata;
    (*pcount)++;
    pr_info("hook_chain_1 before openat task: %llx, count: %llx\n", args->local.data0, *pcount);
}

void after_openat_1(hook_fargs4_t *args, void *udata)
{
    pr_info("hook_chain_1 after openat task: %llx\n", args->local.data0);
}

static long syscall_hook_demo_init(const char *args, const char *event, void *__user reserved)
{
    margs = args;
    pr_info("kpm-syscall-hook-demo init ..., args: %s\n", margs);

    __task_pid_nr_ns = (typeof(__task_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
    pr_info("kernel function __task_pid_nr_ns addr: %llx\n", __task_pid_nr_ns);

    if (!margs) {
        pr_warn("no args specified, skip hook\n");
        return 0;
    }

    hook_err_t err = HOOK_NO_ERR;

    if (!strcmp("function_pointer_hook", margs)) {
        pr_info("function pointer hook ...");
        hook_type = FUNCTION_POINTER_CHAIN;
        err = fp_hook_syscalln(__NR_openat, 4, before_openat_0, 0, 0);
        if (err) goto out;
        err = fp_hook_syscalln(__NR_openat, 4, before_openat_1, after_openat_1, &open_counts);
    } else if (!strcmp("inline_hook", margs)) {
        pr_info("inline hook ...");
        hook_type = INLINE_CHAIN;
        err = inline_hook_syscalln(__NR_openat, 4, before_openat_0, 0, 0);
    } else {
        pr_warn("unknown args: %s\n", margs);
        return 0;
    }

out:
    if (err) {
        pr_err("hook openat error: %d\n", err);
    } else {
        pr_info("hook openat success\n");
    }
    return 0;
}

static long syscall_hook_control0(const char *args, char *__user out_msg, int outlen)
{
    pr_info("syscall_hook control, args: %s\n", args ? args : "null");

    if (!args) {
        pr_info("Available commands:\n");
        pr_info("  function_pointer_hook - Enable function pointer hook\n");
        pr_info("  inline_hook - Enable inline hook\n");
        pr_info("  unhook - Remove all hooks\n");
        pr_info("  enable_stack_trace - Enable stack trace\n");
        pr_info("  disable_stack_trace - Disable stack trace\n");
        pr_info("  status - Show current status\n");
        return 0;
    }

    hook_err_t err = HOOK_NO_ERR;

    if (!strcmp("function_pointer_hook", args)) {
        // 先清理现有hook
        if (hook_type == INLINE_CHAIN) {
            inline_unhook_syscalln(__NR_openat, before_openat_0, 0);
        } else if (hook_type == FUNCTION_POINTER_CHAIN) {
            fp_unhook_syscalln(__NR_openat, before_openat_0, 0);
            fp_unhook_syscalln(__NR_openat, before_openat_1, after_openat_1);
        }
        
        pr_info("Installing function pointer hook...\n");
        hook_type = FUNCTION_POINTER_CHAIN;
        err = fp_hook_syscalln(__NR_openat, 4, before_openat_0, 0, 0);
        if (err) goto out;
        err = fp_hook_syscalln(__NR_openat, 4, before_openat_1, after_openat_1, &open_counts);
        
    } else if (!strcmp("inline_hook", args)) {
        // 先清理现有hook
        if (hook_type == INLINE_CHAIN) {
            inline_unhook_syscalln(__NR_openat, before_openat_0, 0);
        } else if (hook_type == FUNCTION_POINTER_CHAIN) {
            fp_unhook_syscalln(__NR_openat, before_openat_0, 0);
            fp_unhook_syscalln(__NR_openat, before_openat_1, after_openat_1);
        }
        
        pr_info("Installing inline hook...\n");
        hook_type = INLINE_CHAIN;
        err = inline_hook_syscalln(__NR_openat, 4, before_openat_0, 0, 0);
        
    } else if (!strcmp("unhook", args)) {
        pr_info("Removing all hooks...\n");
        if (hook_type == INLINE_CHAIN) {
            inline_unhook_syscalln(__NR_openat, before_openat_0, 0);
        } else if (hook_type == FUNCTION_POINTER_CHAIN) {
            fp_unhook_syscalln(__NR_openat, before_openat_0, 0);
            fp_unhook_syscalln(__NR_openat, before_openat_1, after_openat_1);
        }
        hook_type = NONE;
        pr_info("All hooks removed\n");
        return 0;
        
    } else if (!strcmp("enable_stack_trace", args)) {
        enable_stack_trace = true;
        pr_info("Stack trace enabled\n");
        return 0;
        
    } else if (!strcmp("disable_stack_trace", args)) {
        enable_stack_trace = false;
        pr_info("Stack trace disabled\n");
        return 0;
        
    } else if (!strcmp("status", args)) {
        pr_info("=== Current Status ===\n");
        pr_info("Hook type: %s\n", 
               (hook_type == FUNCTION_POINTER_CHAIN) ? "FUNCTION_POINTER" :
               (hook_type == INLINE_CHAIN) ? "INLINE" : "NONE");
        pr_info("Stack trace: %s\n", enable_stack_trace ? "ENABLED" : "DISABLED");
        pr_info("Open counts: %llu\n", open_counts);
        return 0;
        
    } else {
        pr_warn("Unknown command: %s\n", args);
        return -1;
    }

out:
    if (err) {
        pr_err("Hook operation error: %d\n", err);
        return -1;
    } else {
        pr_info("Hook operation success\n");
        pr_info("Stack trace: %s\n", enable_stack_trace ? "ENABLED" : "DISABLED");
    }
    return 0;
}

static long syscall_hook_demo_exit(void *__user reserved)
{
    pr_info("kpm-syscall-hook-demo exit ...\n");

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