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

KPM_NAME("kpm-syscall-hook-demo");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("KernelPatch Module System Call Hook Example");

const char *margs = 0;
enum hook_type hook_type = NONE;

// PID 过滤配置
static pid_t target_pid = 0;      // 目标进程PID (0表示不过滤)
static pid_t target_tgid = 0;     // 目标线程组PID (0表示不过滤)
static bool pid_filter_enabled = false; // 是否启用PID过滤

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

    // PID 过滤逻辑
    if (pid_filter_enabled) {
        bool should_log = false;
        
        // 检查是否匹配目标PID或TGID
        if (target_pid > 0 && pid == target_pid) {
            should_log = true;
        }
        if (target_tgid > 0 && tgid == target_tgid) {
            should_log = true;
        }
        
        // 如果不匹配，跳过日志
        if (!should_log) {
            return;
        }
    }

    // 输出详细信息 (带PID标识)
    if (pid_filter_enabled) {
        printk(KERN_INFO "[KP] [PID:%d] hook_chain_0 task: %llx, pid: %d, tgid: %d, openat dfd: %d, filename: %s, flag: %x, mode: %d\n", 
               pid, task, pid, tgid, dfd, buf, flag, mode);
    } else {
        printk(KERN_INFO "[KP] hook_chain_0 task: %llx, pid: %d, tgid: %d, openat dfd: %d, filename: %s, flag: %x, mode: %d\n", 
               task, pid, tgid, dfd, buf, flag, mode);
    }
}

uint64_t open_counts = 0;

void before_openat_1(hook_fargs4_t *args, void *udata)
{
    // 如果启用了PID过滤，检查是否应该跳过
    if (pid_filter_enabled) {
        // 这里我们依赖 before_openat_0 的过滤结果
        // 如果 before_openat_0 因为PID不匹配而返回，这里也不会被调用
    }
    
    uint64_t *pcount = (uint64_t *)udata;
    (*pcount)++;
    
    if (pid_filter_enabled) {
        printk(KERN_INFO "[KP] [PID:?] hook_chain_1 before openat task: %llx, count: %llx\n", args->local.data0, *pcount);
    } else {
        printk(KERN_INFO "[KP] hook_chain_1 before openat task: %llx, count: %llx\n", args->local.data0, *pcount);
    }
}

void after_openat_1(hook_fargs4_t *args, void *udata)
{
    if (pid_filter_enabled) {
        printk(KERN_INFO "[KP] [PID:?] hook_chain_1 after openat task: %llx\n", args->local.data0);
    } else {
        printk(KERN_INFO "[KP] hook_chain_1 after openat task: %llx\n", args->local.data0);
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
        
    } else if (!strncmp("pid:", args, 4)) {
        // 格式: pid:1234 或 pid:off
        const char *pid_arg = args + 4;
        if (!strcmp("off", pid_arg)) {
            pid_filter_enabled = false;
            target_pid = 0;
            target_tgid = 0;
            printk(KERN_INFO "[KP] control: PID filter disabled\n");
        } else {
            long pid_val = 0;
            int ret = kstrtol(pid_arg, 10, &pid_val);
            if (ret == 0 && pid_val > 0) {
                pid_filter_enabled = true;
                target_pid = (pid_t)pid_val;
                target_tgid = 0;  // 只过滤PID，不过滤TGID
                printk(KERN_INFO "[KP] control: PID filter enabled for PID: %d\n", target_pid);
            } else {
                printk(KERN_ERR "[KP] control: Invalid PID: %s\n", pid_arg);
                return -1;
            }
        }
        return 0;
        
    } else if (!strncmp("tgid:", args, 5)) {
        // 格式: tgid:1234 或 tgid:off
        const char *tgid_arg = args + 5;
        if (!strcmp("off", tgid_arg)) {
            pid_filter_enabled = false;
            target_pid = 0;
            target_tgid = 0;
            printk(KERN_INFO "[KP] control: TGID filter disabled\n");
        } else {
            long tgid_val = 0;
            int ret = kstrtol(tgid_arg, 10, &tgid_val);
            if (ret == 0 && tgid_val > 0) {
                pid_filter_enabled = true;
                target_pid = 0;  // 只过滤TGID，不过滤PID
                target_tgid = (pid_t)tgid_val;
                printk(KERN_INFO "[KP] control: TGID filter enabled for TGID: %d\n", target_tgid);
            } else {
                printk(KERN_ERR "[KP] control: Invalid TGID: %s\n", tgid_arg);
                return -1;
            }
        }
        return 0;
        
    } else if (!strcmp("status", args)) {
        printk(KERN_INFO "[KP] control: Status - Hook type: %d, PID filter: %s\n", 
               hook_type, pid_filter_enabled ? "enabled" : "disabled");
        if (pid_filter_enabled) {
            if (target_pid > 0) {
                printk(KERN_INFO "[KP] control: Target PID: %d\n", target_pid);
            }
            if (target_tgid > 0) {
                printk(KERN_INFO "[KP] control: Target TGID: %d\n", target_tgid);
            }
        }
        return 0;
        
    } else {
        printk(KERN_WARNING "[KP] control: unknown args: %s\n", args);
        printk(KERN_INFO "[KP] control: Available commands:\n");
        printk(KERN_INFO "[KP] control:   function_pointer_hook - Enable function pointer hook\n");
        printk(KERN_INFO "[KP] control:   inline_hook - Enable inline hook\n");
        printk(KERN_INFO "[KP] control:   unhook - Remove all hooks\n");
        printk(KERN_INFO "[KP] control:   pid:1234 - Monitor specific PID\n");
        printk(KERN_INFO "[KP] control:   tgid:1234 - Monitor specific thread group\n");
        printk(KERN_INFO "[KP] control:   pid:off - Disable PID filter\n");
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