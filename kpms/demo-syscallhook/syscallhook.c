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
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>

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
static bool enable_mount_hide = true;      // 是否隐藏挂载信息检测 (默认开启)
static bool enable_anti_detect = true;     // 总开关 (默认开启)

// 敏感的/proc文件列表
static const char *sensitive_proc_files[] = {
    "mounts", "mountinfo", "mountstats", "maps", "smaps", 
    "status", "stat", "cmdline", "environ", "fd/", "task/",
    NULL
};

// 内核PID函数声明（如果头文件中没有导出）
extern pid_t task_pid_nr(struct task_struct *task);
extern pid_t task_tgid_nr(struct task_struct *task);

// 获取当前进程名称的简化方法 - 最大兼容性
static void get_current_comm(char *buf, size_t size)
{
    // 简化方案：直接使用PID作为标识，避免复杂的进程名获取
    if (size > 0) {
        pid_t pid = task_pid_nr(current);
        snprintf(buf, size, "pid_%d", pid);
    }
}

// 检查是否是系统应用（简化版本，主要基于PID判断）
static bool is_system_app_by_hook_info(pid_t pid, pid_t tgid, const char *comm)
{
    // 1. 系统关键进程通常PID较小 - 这是最可靠的判断方法
    if (pid <= 1000) {
        return true;
    }
    
    // 2. 内核线程检查 (TGID为0通常表示内核线程)
    if (tgid == 0) {
        return true;
    }
    
    // 3. 对于Android系统，还可以基于PID范围进行更精确的判断
    // Android系统服务通常在1000-2000范围内
    if (pid >= 1000 && pid <= 2000) {
        return true;
    }
    
    // 4. 如果comm包含PID信息，可以进行一些基本的判断
    // 但为了最大兼容性，我们主要依赖PID范围
    
    return false;
}

// 简化版本，用于不需要详细信息的场合
static bool is_system_app(void)
{
    pid_t pid = task_pid_nr(current);
    pid_t tgid = task_tgid_nr(current);
    char comm[TASK_COMM_LEN];
    get_current_comm(comm, sizeof(comm));
    
    return is_system_app_by_hook_info(pid, tgid, comm);
}

// 检查是否是Root检测相关的挂载文件访问
static bool is_root_detection_mount_access(const char *filename, pid_t pid, pid_t tgid, const char *comm)
{
    if (!filename || !enable_mount_hide || !enable_anti_detect) {
        return false;
    }
    
    // 系统应用不拦截
    if (is_system_app_by_hook_info(pid, tgid, comm)) {
        return false;
    }
    
    // 检查是否访问用于Root检测的关键挂载文件
    if (strstr(filename, "/proc/mounts") ||           // 系统挂载信息
        strstr(filename, "/proc/mountinfo") ||        // 详细挂载信息  
        strstr(filename, "/proc/mountstats") ||       // 挂载统计信息
        strstr(filename, "/proc/self/mounts") ||      // 当前进程挂载视图
        strstr(filename, "/proc/self/mountinfo") ||   // 当前进程挂载详情
        strstr(filename, "/proc/1/mounts") ||         // init进程挂载信息
        strstr(filename, "/proc/1/mountinfo")) {      // init进程挂载详情
        
        // 这些文件常被用来检测:
        // 1. Magisk: 检查是否有 /sbin/.magisk 等异常挂载
        // 2. KernelSU: 检查是否有 overlayfs 挂载
        // 3. APatch: 检查内核模块相关挂载
        // 4. Zygisk: 检查 zygote 进程的挂载namespace
        return true;
    }
    
    return false;
}

// 检查是否是敏感的/proc文件（仅对非系统应用）
static bool is_sensitive_proc_file(const char *filename, pid_t pid, pid_t tgid, const char *comm)
{
    if (!filename || !enable_proc_filter || !enable_anti_detect) {
        return false;
    }
    
    // 系统应用不拦截，避免系统崩溃
    if (is_system_app_by_hook_info(pid, tgid, comm)) {
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
        snprintf(pid_str, sizeof(pid_str), "/proc/%d/", pid);
        
        // 如果不是访问自己的信息，则认为是敏感访问
        if (!strstr(filename, pid_str)) {
            return true;
        }
    }
    
    return false;
}

// 检查是否是ptrace相关调用
static bool is_ptrace_call(const char *filename, pid_t pid, pid_t tgid, const char *comm)
{
    if (!filename || !enable_ptrace_hide || !enable_anti_detect) {
        return false;
    }
    
    // 系统应用不拦截
    if (is_system_app_by_hook_info(pid, tgid, comm)) {
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
        snprintf(pid_str, sizeof(pid_str), "/proc/%d/", pid);
        
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
    pid_t pid = task_pid_nr(task);
    pid_t tgid = task_tgid_nr(task);

    args->local.data0 = (uint64_t)task;

    // 获取进程名用于系统应用检测和日志
    char comm[TASK_COMM_LEN];
    get_current_comm(comm, sizeof(comm));
    
    // 反检测逻辑 - 使用钩子中的完整进程信息进行精确判断
    bool is_sensitive = is_sensitive_proc_file(buf, pid, tgid, comm);
    bool is_ptrace = is_ptrace_call(buf, pid, tgid, comm);
    bool is_mount_detect = is_root_detection_mount_access(buf, pid, tgid, comm);
    
    // 检查是否是系统应用（用于调试和日志）
    bool is_sys_app = is_system_app_by_hook_info(pid, tgid, comm);
    
    if (enable_anti_detect && (is_sensitive || is_ptrace || is_mount_detect)) {
        
        // 记录被拦截的访问
        if (is_sensitive) {
            printk(KERN_INFO "[KP] BLOCKED sensitive proc file: pid:%d tgid:%d comm:%s filename:%s\n", pid, tgid, comm, buf);
        }
        if (is_ptrace) {
            printk(KERN_INFO "[KP] BLOCKED ptrace attempt: pid:%d tgid:%d comm:%s filename:%s\n", pid, tgid, comm, buf);
        }
        if (is_mount_detect) {
            printk(KERN_INFO "[KP] BLOCKED root detection (mount): pid:%d tgid:%d comm:%s filename:%s\n", pid, tgid, comm, buf);
        }
        // 对于敏感文件访问，我们只记录但不阻止（避免破坏系统功能）
        // 实际的阻止可以通过修改返回值在 after_openat 中实现
        args->local.data1 = 1;  // 标记这是一个敏感访问
        return;  // 不记录敏感操作的详细日志
    }

    // 正常日志记录（显示是否为系统应用）
    printk(KERN_INFO "[KP] pid:%d tgid:%d comm:%s%s openat dfd:%d filename:%s flag:%x mode:%d\n", 
           pid, tgid, comm, is_sys_app ? " (system)" : "", dfd, buf, flag, mode);
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

    // 直接使用内核提供的 task_pid_nr 和 task_tgid_nr 函数

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
        
    } else if (!strcmp("enable_mount_hide", args)) {
        enable_mount_hide = true;
        printk(KERN_INFO "[KP] control: Mount detection hiding enabled\n");
        return 0;
        
    } else if (!strcmp("disable_mount_hide", args)) {
        enable_mount_hide = false;
        printk(KERN_INFO "[KP] control: Mount detection hiding disabled\n");
        return 0;
        
    } else if (!strcmp("status", args)) {
        printk(KERN_INFO "[KP] control: Hook type:%d\n", hook_type);
        printk(KERN_INFO "[KP] control: Anti-detect:%s\n", enable_anti_detect ? "enabled" : "disabled");
        printk(KERN_INFO "[KP] control: Proc filter:%s\n", enable_proc_filter ? "enabled" : "disabled");
        printk(KERN_INFO "[KP] control: Ptrace hide:%s\n", enable_ptrace_hide ? "enabled" : "disabled");
        printk(KERN_INFO "[KP] control: Mount detection hide:%s\n", enable_mount_hide ? "enabled" : "disabled");
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
        printk(KERN_INFO "[KP] control:   enable_mount_hide - Enable mount detection hiding\n");
        printk(KERN_INFO "[KP] control:   disable_mount_hide - Disable mount detection hiding\n");
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