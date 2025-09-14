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
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/mm.h>

KPM_NAME("kpm-syscall-hook-demo");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("bmax121");
KPM_DESCRIPTION("KernelPatch Module System Call Hook Example");

const char *margs = 0;
enum hook_type hook_type = NONE;

// 反检测配置 - 默认全部开启
static bool enable_proc_filter = true;     // 是否启用/proc文件过滤 (默认开启)
static bool enable_ptrace_hide = true;     // 是否隐藏ptrace痕迹 (默认开启)
static bool enable_anti_detect = true;     // 总开关 (默认开启)

// 敏感的/proc文件列表
static const char *sensitive_proc_files[] = {
    "mounts", "mountinfo", "mountstats", "maps", "smaps", 
    "status", "stat", "cmdline", "environ", "fd/", "task/",
    NULL
};

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

// 检查是否是系统应用（通过进程信息判断，不应被拦截）
static bool is_system_app(void)
{
    struct task_struct *task = current;
    struct mm_struct *mm;
    struct file *exe_file;
    char *pathname = NULL;
    char *path_buf = NULL;
    bool is_system = false;
    
    if (!task) {
        return false;
    }
    
    mm = task->mm;
    if (!mm) {
        return true; // 内核线程，认为是系统进程
    }
    
    exe_file = mm->exe_file;
    if (!exe_file) {
        return false;
    }
    
    // 分配临时缓冲区获取路径
    path_buf = kmalloc(256, GFP_ATOMIC);
    if (!path_buf) {
        return false;
    }
    
    pathname = d_path(&exe_file->f_path, path_buf, 256);
    if (IS_ERR(pathname)) {
        kfree(path_buf);
        return false;
    }
    
    // 检查系统应用路径特征
    if (strstr(pathname, "/system/") ||           // 系统分区
        strstr(pathname, "/vendor/") ||           // 厂商分区  
        strstr(pathname, "/apex/") ||             // APEX模块
        strstr(pathname, "/system_ext/") ||       // 系统扩展
        strstr(pathname, "/product/") ||          // 产品分区
        strstr(pathname, "/odm/")) {              // ODM分区
        is_system = true;
    }
    
    kfree(path_buf);
    return is_system;
}

// 检查是否是敏感的/proc文件（仅对非系统应用）
static bool is_sensitive_proc_file(const char *filename, pid_t current_pid)
{
    if (!filename || !enable_proc_filter || !enable_anti_detect) {
        return false;
    }
    
    // 系统应用不拦截，避免系统崩溃
    if (is_system_app()) {
        return false;
    }
    
    // 检查是否是/proc路径
    if (strncmp(filename, "/proc/", 6) != 0) {
        return false;
    }
    
    // 只拦截访问其他进程信息的敏感文件
    // 允许访问自己的/proc信息，但拦截访问其他进程的信息
    if (strstr(filename, "maps") || 
        strstr(filename, "smaps") ||
        strstr(filename, "status") ||
        strstr(filename, "stat") ||
        strstr(filename, "cmdline") ||
        strstr(filename, "environ")) {
        
        // 检查是否是访问其他进程的信息
        char pid_str[16];
        snprintf(pid_str, sizeof(pid_str), "/proc/%d/", current_pid);
        
        // 如果不是访问自己的信息，则认为是敏感访问
        if (!strstr(filename, pid_str)) {
            return true;
        }
    }
    
    return false;
}

// 检查是否是ptrace相关调用
static bool is_ptrace_call(const char *filename, pid_t current_pid)
{
    if (!filename || !enable_ptrace_hide || !enable_anti_detect) {
        return false;
    }
    
    // 系统应用不拦截
    if (is_system_app()) {
        return false;
    }
    
    // 检查ptrace相关文件，但只拦截跨进程访问
    if (strstr(filename, "/proc/") && (
        strstr(filename, "status") || 
        strstr(filename, "stat") ||
        strstr(filename, "task") ||
        strstr(filename, "mem"))) {
        
        // 检查是否是访问其他进程
        char pid_str[16];
        snprintf(pid_str, sizeof(pid_str), "/proc/%d/", current_pid);
        
        // 如果不是访问自己的信息，则认为是ptrace尝试
        if (!strstr(filename, pid_str)) {
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
    compat_strncpy_from_user(buf, filename, sizeof(buf));

    struct task_struct *task = current;
    pid_t pid = -1, tgid = -1;
    
    if (__task_pid_nr_ns) {
        pid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
        tgid = __task_pid_nr_ns(task, PIDTYPE_TGID, 0);
    }

    args->local.data0 = (uint64_t)task;

    // 反检测逻辑
    bool is_sensitive = is_sensitive_proc_file(buf, pid);
    bool is_ptrace = is_ptrace_call(buf, pid);
    
    if (enable_anti_detect && (is_sensitive || is_ptrace)) {
        // 记录被拦截的访问
        if (is_sensitive) {
            printk(KERN_INFO "[KP] BLOCKED sensitive proc file: pid:%d filename:%s\n", pid, buf);
        }
        if (is_ptrace) {
            printk(KERN_INFO "[KP] BLOCKED ptrace attempt: pid:%d filename:%s\n", pid, buf);
        }
        // 对于敏感文件访问，我们只记录但不阻止（避免破坏系统功能）
        // 实际的阻止可以通过修改返回值在 after_openat 中实现
        args->local.data1 = 1;  // 标记这是一个敏感访问
        return;  // 不记录敏感操作的详细日志
    }

    // 正常日志记录
    printk(KERN_INFO "[KP] pid:%d tgid:%d task:%llx openat dfd:%d filename:%s flag:%x mode:%d\n", 
           pid, tgid, task, dfd, buf, flag, mode);
}

uint64_t open_counts = 0;

void before_openat_1(hook_fargs4_t *args, void *udata)
{
    uint64_t *pcount = (uint64_t *)udata;
    (*pcount)++;
    printk(KERN_INFO "[KP] hook_chain_1 before openat task:%llx count:%llx\n", args->local.data0, *pcount);
}

void after_openat_1(hook_fargs4_t *args, void *udata)
{
    // 检查是否是被标记的敏感访问
    if (args->local.data1 == 1 && enable_anti_detect) {
        // 对于敏感文件访问，修改返回值为错误
        args->ret = -ENOENT;  // 文件不存在错误
        printk(KERN_INFO "[KP] Modified return value for sensitive access: task:%llx ret:-ENOENT\n", args->local.data0);
    } else {
        printk(KERN_INFO "[KP] hook_chain_1 after openat task:%llx\n", args->local.data0);
    }
}

static long syscall_hook_demo_init(const char *args, const char *event, void *__user reserved)
{
    margs = args;
    printk(KERN_INFO "[KP] kpm-syscall-hook-demo init, args:%s\n", margs ? margs : "null");

    __task_pid_nr_ns = (typeof(__task_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
    printk(KERN_INFO "[KP] kernel function __task_pid_nr_ns addr:%llx\n", __task_pid_nr_ns);

    if (!margs) {
        printk(KERN_WARNING "[KP] no args specified, skip hook\n");
        return 0;
    }

    hook_err_t err = HOOK_NO_ERR;

    if (!strcmp("function_pointer_hook", margs)) {
        printk(KERN_INFO "[KP] function pointer hook enabled\n");
        hook_type = FUNCTION_POINTER_CHAIN;
        err = fp_hook_syscalln(__NR_openat, 4, before_openat_0, 0, 0);
        if (err) goto out;
        err = fp_hook_syscalln(__NR_openat, 4, before_openat_1, after_openat_1, &open_counts);
    } else if (!strcmp("inline_hook", margs)) {
        printk(KERN_INFO "[KP] inline hook enabled\n");
        hook_type = INLINE_CHAIN;
        err = inline_hook_syscalln(__NR_openat, 4, before_openat_0, 0, 0);
    } else {
        printk(KERN_WARNING "[KP] unknown args:%s\n", margs);
        return 0;
    }

out:
    if (err) {
        printk(KERN_ERR "[KP] hook openat error:%d\n", err);
    } else {
        printk(KERN_INFO "[KP] hook openat success\n");
        // 显示反检测状态
        printk(KERN_INFO "[KP] Anti-detection features: %s\n", enable_anti_detect ? "ENABLED" : "DISABLED");
        printk(KERN_INFO "[KP] - Proc filter: %s\n", enable_proc_filter ? "ENABLED" : "DISABLED");
        printk(KERN_INFO "[KP] - Ptrace hiding: %s\n", enable_ptrace_hide ? "ENABLED" : "DISABLED");
    }
    return 0;
}

static long syscall_hook_control0(const char *args, char *__user out_msg, int outlen)
{
    printk(KERN_INFO "[KP] syscall_hook control, args:%s\n", args ? args : "null");
    
    if (!args) {
        printk(KERN_WARNING "[KP] control: no args specified\n");
        return -1;
    }
    
    hook_err_t err = HOOK_NO_ERR;
    
    if (!strcmp("function_pointer_hook", args)) {
        printk(KERN_INFO "[KP] control: enabling function pointer hook\n");
        
        // 清理已有钩子
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
        printk(KERN_INFO "[KP] control: enabling inline hook\n");
        
        // 清理已有钩子
        if (hook_type == FUNCTION_POINTER_CHAIN) {
            fp_unhook_syscalln(__NR_openat, before_openat_0, 0);
            fp_unhook_syscalln(__NR_openat, before_openat_1, after_openat_1);
        } else if (hook_type == INLINE_CHAIN) {
            inline_unhook_syscalln(__NR_openat, before_openat_0, 0);
        }
        
        hook_type = INLINE_CHAIN;
        err = inline_hook_syscalln(__NR_openat, 4, before_openat_0, 0, 0);
        
    } else if (!strcmp("unhook", args)) {
        printk(KERN_INFO "[KP] control: removing hooks\n");
        
        if (hook_type == FUNCTION_POINTER_CHAIN) {
            fp_unhook_syscalln(__NR_openat, before_openat_0, 0);
            fp_unhook_syscalln(__NR_openat, before_openat_1, after_openat_1);
        } else if (hook_type == INLINE_CHAIN) {
            inline_unhook_syscalln(__NR_openat, before_openat_0, 0);
        }
        hook_type = NONE;
        printk(KERN_INFO "[KP] control: hooks removed\n");
        return 0;
        
    } else if (!strcmp("enable_anti_detect", args)) {
        enable_anti_detect = true;
        enable_proc_filter = true;
        enable_ptrace_hide = true;
        printk(KERN_INFO "[KP] control: Anti-detection enabled\n");
        return 0;
        
    } else if (!strcmp("disable_anti_detect", args)) {
        enable_anti_detect = false;
        enable_proc_filter = false;
        enable_ptrace_hide = false;
        printk(KERN_INFO "[KP] control: Anti-detection disabled\n");
        return 0;
        
    } else if (!strcmp("enable_proc_filter", args)) {
        enable_proc_filter = true;
        printk(KERN_INFO "[KP] control: Proc filter enabled\n");
        return 0;
        
    } else if (!strcmp("disable_proc_filter", args)) {
        enable_proc_filter = false;
        printk(KERN_INFO "[KP] control: Proc filter disabled\n");
        return 0;
        
    } else if (!strcmp("enable_ptrace_hide", args)) {
        enable_ptrace_hide = true;
        printk(KERN_INFO "[KP] control: Ptrace hiding enabled\n");
        return 0;
        
    } else if (!strcmp("disable_ptrace_hide", args)) {
        enable_ptrace_hide = false;
        printk(KERN_INFO "[KP] control: Ptrace hiding disabled\n");
        return 0;
        
    } else if (!strcmp("status", args)) {
        printk(KERN_INFO "[KP] control: Hook type:%d\n", hook_type);
        printk(KERN_INFO "[KP] control: Anti-detect:%s\n", enable_anti_detect ? "enabled" : "disabled");
        printk(KERN_INFO "[KP] control: Proc filter:%s\n", enable_proc_filter ? "enabled" : "disabled");
        printk(KERN_INFO "[KP] control: Ptrace hide:%s\n", enable_ptrace_hide ? "enabled" : "disabled");
        return 0;
        
    } else {
        printk(KERN_WARNING "[KP] control: unknown command:%s\n", args);
        printk(KERN_INFO "[KP] control: Available commands:\n");
        printk(KERN_INFO "[KP] control:   function_pointer_hook - Enable function pointer hook\n");
        printk(KERN_INFO "[KP] control:   inline_hook - Enable inline hook\n");
        printk(KERN_INFO "[KP] control:   unhook - Remove all hooks\n");
        printk(KERN_INFO "[KP] control:   enable_anti_detect - Enable all anti-detection\n");
        printk(KERN_INFO "[KP] control:   disable_anti_detect - Disable all anti-detection\n");
        printk(KERN_INFO "[KP] control:   enable_proc_filter - Enable /proc filtering\n");
        printk(KERN_INFO "[KP] control:   disable_proc_filter - Disable /proc filtering\n");
        printk(KERN_INFO "[KP] control:   enable_ptrace_hide - Enable ptrace hiding\n");
        printk(KERN_INFO "[KP] control:   disable_ptrace_hide - Disable ptrace hiding\n");
        printk(KERN_INFO "[KP] control:   status - Show current status\n");
        return -1;
    }

out_control:
    if (err) {
        printk(KERN_ERR "[KP] control: hook error:%d\n", err);
        return -1;
    } else {
        printk(KERN_INFO "[KP] control: hook success\n");
        // 显示反检测状态
        printk(KERN_INFO "[KP] Anti-detection features: %s\n", enable_anti_detect ? "ENABLED" : "DISABLED");
        if (enable_anti_detect) {
            printk(KERN_INFO "[KP] - Proc filter: %s\n", enable_proc_filter ? "ENABLED" : "DISABLED");
            printk(KERN_INFO "[KP] - Ptrace hiding: %s\n", enable_ptrace_hide ? "ENABLED" : "DISABLED");
        }
        return 0;
    }
}

static long syscall_hook_demo_exit(void *__user reserved)
{
    printk(KERN_INFO "[KP] kpm-syscall-hook-demo exit\n");

    if (hook_type == INLINE_CHAIN) {
        inline_unhook_syscalln(__NR_openat, before_openat_0, 0);
    } else if (hook_type == FUNCTION_POINTER_CHAIN) {
        fp_unhook_syscalln(__NR_openat, before_openat_0, 0);
        fp_unhook_syscalln(__NR_openat, before_openat_1, after_openat_1);
    }
    return 0;
}

KPM_INIT(syscall_hook_demo_init);
KPM_CTL0(syscall_hook_control0);
KPM_EXIT(syscall_hook_demo_exit);