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

KPM_NAME("kpm-syscall-hook-demo");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("KernelPatch Module System Call Hook Example");

const char *margs = 0;
enum hook_type hook_type = NONE;

// 环境隐藏功能配置
static bool hide_environment = true;  // 默认启用环境隐藏
static bool enable_detailed_log = false;  // 详细日志开关

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

// 检查是否需要隐藏文件访问
static bool should_hide_file(const char *filename)
{
    if (!hide_environment) return false;
    
    // 隐藏敏感路径
    const char *sensitive_paths[] = {
        "/proc/version",
        "/proc/cpuinfo", 
        "/system/build.prop",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/tmp",
        "/dev/block/",
        "/sys/kernel/",
        NULL
    };
    
    for (int i = 0; sensitive_paths[i]; i++) {
        if (strstr(filename, sensitive_paths[i])) {
            return true;
        }
    }
    return false;
}

void before_openat_0(hook_fargs4_t *args, void *udata)
{
    int dfd = (int)syscall_argn(args, 0);
    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    int flag = (int)syscall_argn(args, 2);
    umode_t mode = (int)syscall_argn(args, 3);

    char buf[1024];
    int ret = compat_strncpy_from_user(buf, filename, sizeof(buf));
    if (ret < 0) {
        // 用户空间地址无效，跳过处理
        return;
    }

    struct task_struct *task = current;
    pid_t pid = -1, tgid = -1;
    if (__task_pid_nr_ns) {
        pid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
        tgid = __task_pid_nr_ns(task, PIDTYPE_TGID, 0);
    }

    args->local.data0 = (uint64_t)task;

    // 检查是否需要隐藏此文件访问
    if (should_hide_file(buf)) {
        // 对敏感文件访问返回 ENOENT 错误
        syscall_set_return_value(current, args, -2); // -ENOENT
        if (enable_detailed_log) {
            printk(KERN_INFO "[KP] Hidden file access: %s (pid:%d)\n", buf, pid);
        }
        return;
    }

    // 只有启用详细日志时才输出
    if (enable_detailed_log) {
        printk(KERN_INFO "[KP] hook_chain_0 task: %llx, pid: %d, tgid: %d, openat dfd: %d, filename: %s, flag: %x, mode: %d\n", 
               task, pid, tgid, dfd, buf, flag, mode);
    }
}

uint64_t open_counts = 0;

void before_openat_1(hook_fargs4_t *args, void *udata)
{
    uint64_t *pcount = (uint64_t *)udata;
    (*pcount)++;
    if (enable_detailed_log) {
        printk(KERN_INFO "[KP] hook_chain_1 before openat task: %llx, count: %llx\n", args->local.data0, *pcount);
    }
}

void after_openat_1(hook_fargs4_t *args, void *udata)
{
    if (enable_detailed_log) {
        printk(KERN_INFO "[KP] hook_chain_1 after openat task: %llx\n", args->local.data0);
    }
}

static long syscall_hook_demo_init(const char *args, const char *event, void *__user reserved)
{
    margs = args;
    // 使用 printk 而不是 pr_info 确保日志输出
    printk(KERN_INFO "[KP] kpm-syscall-hook-demo init ..., args: %s\n", margs ? margs : "(null)");

    __task_pid_nr_ns = (typeof(__task_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
    printk(KERN_INFO "[KP] kernel function __task_pid_nr_ns addr: %llx\n", __task_pid_nr_ns);

    if (!margs) {
        printk(KERN_WARNING "[KP] no args specified, skip hook\n");
        return 0;
    }

    // 解析参数
    if (strstr(margs, "verbose")) {
        enable_detailed_log = true;
        printk(KERN_INFO "[KP] verbose logging enabled\n");
    }
    
    if (strstr(margs, "no_hide")) {
        hide_environment = false;
        printk(KERN_INFO "[KP] environment hiding disabled\n");
    }

    hook_err_t err = HOOK_NO_ERR;

    if (strstr(margs, "function_pointer_hook")) {
        printk(KERN_INFO "[KP] setting up function pointer hook...\n");
        hook_type = FUNCTION_POINTER_CHAIN;
        err = fp_hook_syscalln(__NR_openat, 4, before_openat_0, 0, 0);
        if (err) {
            printk(KERN_ERR "[KP] fp_hook_syscalln first hook failed: %d\n", err);
            goto out;
        }
        err = fp_hook_syscalln(__NR_openat, 4, before_openat_1, after_openat_1, &open_counts);
        if (err) {
            printk(KERN_ERR "[KP] fp_hook_syscalln second hook failed: %d\n", err);
            goto out;
        }
    } else if (strstr(margs, "inline_hook")) {
        printk(KERN_INFO "[KP] setting up inline hook...\n");
        hook_type = INLINE_CHAIN;
        err = inline_hook_syscalln(__NR_openat, 4, before_openat_0, 0, 0);
        if (err) {
            printk(KERN_ERR "[KP] inline_hook_syscalln failed: %d\n", err);
            goto out;
        }
    } else {
        printk(KERN_WARNING "[KP] unknown args: %s\n", margs);
        printk(KERN_INFO "[KP] supported args: function_pointer_hook, inline_hook, verbose, no_hide\n");
        return 0;
    }

out:
    if (err) {
        printk(KERN_ERR "[KP] hook openat error: %d\n", err);
    } else {
        printk(KERN_INFO "[KP] hook openat success! Environment hiding: %s, Verbose: %s\n", 
               hide_environment ? "enabled" : "disabled",
               enable_detailed_log ? "enabled" : "disabled");
    }
    return 0;
}

static long syscall_hook_control0(const char *args, char *__user out_msg, int outlen)
{
    printk(KERN_INFO "[KP] syscall_hook control, args: %s\n", args ? args : "(null)");
    
    if (!args) return -1;
    
    // 动态控制参数
    if (!strcmp(args, "enable_verbose")) {
        enable_detailed_log = true;
        printk(KERN_INFO "[KP] verbose logging enabled via control\n");
    } else if (!strcmp(args, "disable_verbose")) {
        enable_detailed_log = false;
        printk(KERN_INFO "[KP] verbose logging disabled via control\n");
    } else if (!strcmp(args, "enable_hide")) {
        hide_environment = true;
        printk(KERN_INFO "[KP] environment hiding enabled via control\n");
    } else if (!strcmp(args, "disable_hide")) {
        hide_environment = false;
        printk(KERN_INFO "[KP] environment hiding disabled via control\n");
    } else if (!strcmp(args, "status")) {
        char status_msg[256];
        snprintf(status_msg, sizeof(status_msg), 
                "Hook type: %d, Hide env: %s, Verbose: %s, Open count: %llu",
                hook_type, 
                hide_environment ? "on" : "off",
                enable_detailed_log ? "on" : "off",
                open_counts);
        printk(KERN_INFO "[KP] Status: %s\n", status_msg);
        if (out_msg && outlen > 0) {
            copy_to_user(out_msg, status_msg, min(strlen(status_msg) + 1, (size_t)outlen));
        }
    } else {
        printk(KERN_WARNING "[KP] unknown control command: %s\n", args);
        printk(KERN_INFO "[KP] available commands: enable_verbose, disable_verbose, enable_hide, disable_hide, status\n");
        return -1;
    }
    
    return 0;
}

static long syscall_hook_demo_exit(void *__user reserved)
{
    printk(KERN_INFO "[KP] kpm-syscall-hook-demo exit ...\n");

    if (hook_type == INLINE_CHAIN) {
        inline_unhook_syscalln(__NR_openat, before_openat_0, 0);
        printk(KERN_INFO "[KP] inline hook removed\n");
    } else if (hook_type == FUNCTION_POINTER_CHAIN) {
        fp_unhook_syscalln(__NR_openat, before_openat_0, 0);
        fp_unhook_syscalln(__NR_openat, before_openat_1, after_openat_1);
        printk(KERN_INFO "[KP] function pointer hooks removed\n");
    }
    
    printk(KERN_INFO "[KP] Total openat calls intercepted: %llu\n", open_counts);
    return 0;
}

KPM_INIT(syscall_hook_demo_init);
KPM_CTL0(syscall_hook_control0);
KPM_EXIT(syscall_hook_demo_exit);
