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

// 监控配置
static bool enable_stack_trace = false;    // 是否启用栈回溯 (默认关闭，性能考虑)

// 移除敏感文件列表（不再需要反检测）

// 内核PID函数声明（如果头文件中没有导出）
extern pid_t task_pid_nr(struct task_struct *task);
extern pid_t task_tgid_nr(struct task_struct *task);

// 栈回溯相关函数类型定义（基于APatch教程）
typedef int (*access_process_vm_t)(struct task_struct *tsk, unsigned long addr, void *buf, int len, int write);
typedef struct mm_struct *(*get_task_mm_t)(struct task_struct *task);
typedef void (*mmput_t)(struct mm_struct *mm);
typedef void (*get_task_comm_t)(char *buf, int len, struct task_struct *task);

// 函数指针声明
static access_process_vm_t access_process_vm_func = NULL;
static get_task_mm_t get_task_mm_func = NULL; 
static mmput_t mmput_func = NULL;
static get_task_comm_t get_task_comm_func = NULL;

// ARM64栈帧结构（基于APatch教程）
struct user_frame {
    unsigned long fp;  // x29寄存器 - 帧指针
    unsigned long lr;  // x30寄存器 - 链接寄存器（返回地址）
};

// 栈回溯实现（基于APatch教程）
static bool unwind_user_stack(struct task_struct *task, pid_t pid)
{
    struct user_frame frame;
    int i;
    
    if (!access_process_vm_func || !get_task_mm_func || !mmput_func) {
        printk(KERN_WARNING "[KP] Stack unwinding functions not available\n");
        return false;
    }
    
    // 获取当前寄存器状态
    struct pt_regs *regs = task_pt_regs(task);
    if (!regs) {
        return false;
    }
    
    frame.fp = regs->regs[29];  // x29 - 帧指针
    frame.lr = regs->regs[30];  // x30 - 链接寄存器
    unsigned long pc = regs->pc; // 程序计数器
    
    // 获取进程内存管理结构
    struct mm_struct *mm = get_task_mm_func(task);
    if (!mm) {
        return false;
    }
    
    printk(KERN_INFO "[KP] === Stack trace for pid:%d ===\n", pid);
    
    // 栈回溯循环（最多16层）
    for (i = 0; i < 16; i++) {
        if (i == 0) {
            printk(KERN_INFO "[KP] pid:%d frame[%d]: lr:0x%llx, fp:0x%llx, pc:0x%llx\n", 
                   pid, i, frame.lr, frame.fp, pc);
        } else {
            printk(KERN_INFO "[KP] pid:%d frame[%d]: lr:0x%llx, fp:0x%llx\n", 
                   pid, i, frame.lr, frame.fp);
        }
        
        // 检查帧指针和返回地址是否有效
        if (!frame.fp || !frame.lr) {
            break;
        }
        
        // 从用户空间读取下一个栈帧
        if (access_process_vm_func(task, frame.fp, &frame, sizeof(struct user_frame), 0) != sizeof(frame)) {
            printk(KERN_INFO "[KP] pid:%d Failed to read frame at 0x%llx\n", pid, frame.fp);
            break;
        }
    }
    
    printk(KERN_INFO "[KP] === End of stack trace ===\n");
    mmput_func(mm);
    return true;
}

// 获取当前进程名称的改进方法
static void get_current_comm(char *buf, size_t size)
{
    if (get_task_comm_func && size > 0) {
        // 使用内核函数获取进程名
        get_task_comm_func(buf, size, current);
    } else if (size > 0) {
        // fallback: 使用PID作为标识
        pid_t pid = task_pid_nr(current);
        snprintf(buf, size, "pid_%d", pid);
    }
}

// 移除系统应用检测函数（不再需要反检测）

// 移除Root检测相关函数（不再需要反检测）

// 移除敏感文件检测函数（不再需要反检测）

// 移除ptrace检测函数（不再需要反检测）

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

    // 获取进程名用于日志
    char comm[TASK_COMM_LEN];
    get_current_comm(comm, sizeof(comm));
    
    args->local.data1 = 0;  // 标记为正常访问

    // 如果启用栈回溯，进行栈回溯（基于APatch教程）
    if (enable_stack_trace) {
        printk(KERN_INFO "[KP] Performing stack trace for syscall...\n");
        unwind_user_stack(task, pid);
    }

    // 正常日志记录
    printk(KERN_INFO "[KP] pid:%d tgid:%d comm:%s openat dfd:%d filename:%s flag:%x mode:%d\n", 
           pid, tgid, comm, dfd, buf, flag, mode);
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
    uint64_t *pcount = (uint64_t *)udata;
    
    // 正常的after钩子日志
    printk(KERN_INFO "[KP] hook_chain_1 after openat task:%llx count:%llx ret:%ld\n", 
           args->local.data0, *pcount, args->ret);
}

static long syscall_hook_demo_init(const char *args, const char *event, void *__user reserved)
{
    margs = args;
    printk(KERN_INFO "[KP] kpm-syscall-hook-demo init, args:%s\n", margs ? margs : "null");

    // 直接使用内核提供的 task_pid_nr 和 task_tgid_nr 函数
    
    // 查找栈回溯相关函数（基于APatch教程）
    access_process_vm_func = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
    get_task_mm_func = (get_task_mm_t)kallsyms_lookup_name("get_task_mm");
    mmput_func = (mmput_t)kallsyms_lookup_name("mmput");
    get_task_comm_func = (get_task_comm_t)kallsyms_lookup_name("__get_task_comm");
    
    // 检查栈回溯函数是否可用
    if (access_process_vm_func && get_task_mm_func && mmput_func) {
        printk(KERN_INFO "[KP] Stack unwinding functions loaded successfully\n");
    } else {
        printk(KERN_WARNING "[KP] Some stack unwinding functions not found, stack trace disabled\n");
        enable_stack_trace = false;
    }
    
    if (get_task_comm_func) {
        printk(KERN_INFO "[KP] Task comm function loaded successfully\n");
    } else {
        printk(KERN_WARNING "[KP] Task comm function not found, using fallback\n");
    }

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
        
    // 移除所有反检测控制命令
        
    } else if (!strcmp("enable_stack_trace", args)) {
        if (access_process_vm_func && get_task_mm_func && mmput_func) {
            enable_stack_trace = true;
            printk(KERN_INFO "[KP] control: Stack trace enabled\n");
        } else {
            printk(KERN_WARNING "[KP] control: Stack trace functions not available\n");
        }
        return 0;
        
    } else if (!strcmp("disable_stack_trace", args)) {
        enable_stack_trace = false;
        printk(KERN_INFO "[KP] control: Stack trace disabled\n");
        return 0;
        
    } else if (!strcmp("status", args)) {
        printk(KERN_INFO "[KP] control: Hook type:%d\n", hook_type);
        printk(KERN_INFO "[KP] control: Stack trace:%s\n", enable_stack_trace ? "enabled" : "disabled");
        return 0;
        
    } else {
        printk(KERN_WARNING "[KP] control: unknown command:%s\n", args);
        printk(KERN_INFO "[KP] control: Available commands:\n");
        printk(KERN_INFO "[KP] control:   function_pointer_hook - Enable function pointer hook\n");
        printk(KERN_INFO "[KP] control:   inline_hook - Enable inline hook\n");
        printk(KERN_INFO "[KP] control:   unhook - Remove all hooks\n");
        printk(KERN_INFO "[KP] control:   enable_stack_trace - Enable stack trace (APatch style)\n");
        printk(KERN_INFO "[KP] control:   disable_stack_trace - Disable stack trace\n");
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