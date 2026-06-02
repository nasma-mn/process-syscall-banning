#include <linux/kernel.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/pid.h>

asmlinkage long sys_hello(void) {
 printk("Hello, World!\n");
 return 0;
}



asmlinkage long sys_set_ban(int ban_getpid, int ban_pipe, int ban_kill) {
    char new_bans = 0;

    /* 1. Check for negative arguments (Priority 1: -EINVAL) */
    if (ban_getpid < 0 || ban_pipe < 0 || ban_kill < 0) {
        return -EINVAL;
    }

    /* 2. Check for root privileges (Priority 2: -EPERM) */
    if (!capable(CAP_SYS_ADMIN)) {
        return -EPERM;
    }

    /* 3. Set the bans. Arguments > 1 are treated as 1 */
    if (ban_getpid >= 1) new_bans |= (1 << 0);
    if (ban_pipe >= 1)   new_bans |= (1 << 1);
    if (ban_kill >= 1)   new_bans |= (1 << 2);

    current->syscall_bans = new_bans;

    return 0; /* Success */
}




asmlinkage long sys_get_ban(char ban) {
    /* 1. Validate the input character */
    if (ban != 'g' && ban != 'p' && ban != 'k') {
        return -EINVAL; /* Return -EINVAL if the char is invalid */
    }

    /* 2. Check the specific bit in our 1-byte storage */
    if (ban == 'g') {
        return (current->syscall_bans & (1 << 0)) ? 1 : 0; /* bit 0 = getpid */
    } else if (ban == 'p') {
        return (current->syscall_bans & (1 << 1)) ? 1 : 0; /* bit 1 = pipe */
    } else if (ban == 'k') {
        return (current->syscall_bans & (1 << 2)) ? 1 : 0; /* bit 2 = kill */
    }

    return 0; 
}



asmlinkage long sys_check_ban(pid_t pid, char ban) {
    struct task_struct *target_task;
    int bit_index;

    /* 1. Validate the input character (Priority: -EINVAL) */
    if (ban == 'g') bit_index = 0;
    else if (ban == 'p') bit_index = 1;
    else if (ban == 'k') bit_index = 2;
    else return -EINVAL;

    /* 2. Find the target process (Priority: -ESRCH) */
    target_task = find_task_by_vpid(pid);
    if (!target_task) {
        return -ESRCH;
    }

    /* 3. Ensure the CALLER is not banned from this syscall (Priority: -EPERM) */
    if (current->syscall_bans & (1 << bit_index)) {
        return -EPERM;
    }

    /* 4. Success: Return 1 if target is banned, 0 if not */
    return (target_task->syscall_bans & (1 << bit_index)) ? 1 : 0;
}



asmlinkage long sys_flip_ban_branch(int height, char ban) {
    struct task_struct *curr_task = current;
    int bit_index, flipped_count = 0, i;

    /* 1. Validate height (Priority: -EINVAL) */
    if (height <= 0) return -EINVAL;

    /* 2. Validate input character (Priority: -EINVAL) */
    if (ban == 'g') bit_index = 0;
    else if (ban == 'p') bit_index = 1;
    else if (ban == 'k') bit_index = 2;
    else return -EINVAL;

    /* 3. Check if CALLER is banned from this syscall (Priority: -EPERM) */
    if (current->syscall_bans & (1 << bit_index)) {
        return -EPERM;
    }

    /* 4. Traverse up the family tree */
    for (i = 0; i < height; i++) {
        // Move to the direct parent
        curr_task = curr_task->parent;
        
        // Stop if we reach the root of the tree (init has no parent)
        if (!curr_task || curr_task->pid == 0) break;

        // Invert the specific ban bit
        curr_task->syscall_bans ^= (1 << bit_index);

        // Count only if the result of the flip was imposing a ban (bit is now 1)
        if (curr_task->syscall_bans & (1 << bit_index)) {
            flipped_count++;
        }
    }

    return flipped_count; /* Success: return number of parents newly banned */
}