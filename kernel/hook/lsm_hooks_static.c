#if !defined(CONFIG_ARM64)
#error "automated LSM hooking on 6.8+ is only for ARM64!"
#endif

#if !defined(CONFIG_KALLSYMS)
#error "automated LSM hooking on 6.8+ requires kallsyms!"
#endif

// security.c hijack for 6.8+
// however this requires kallsyms
// TODO: refine, try to lessen kallsyms dependence further

/*

https://godbolt.org/z/Eh8vfrdns

__attribute__((noinline)) 
void target_fn() {
    volatile int x = 0;
}

int main() {
    target_fn();
    return 0;
}

target_fn:
        sub     sp, sp, #16
        str     wzr, [sp, 12]
        nop
        add     sp, sp, 16
        ret
main:
        stp     x29, x30, [sp, -16]!
        mov     x29, sp
        bl      target_fn   << hunt for this!
        mov     w0, 0
        ldp     x29, x30, [sp], 16
        ret
*/

// bl is 94 ~ 97
// so we can do this like on x86 where 74 xx to 74 yy
// bl is call+ret equivalent on x86 though


// rename
extern int security_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, unsigned int flags);
static __nocfi int ksu_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	ksu_rename_observer(old_dentry, new_dentry);
	return security_inode_rename(old_dir, old_dentry, new_dir, new_dentry, flags);
}

// setuid
extern int security_task_fix_setuid(struct cred *new, const struct cred *old, int flags);
static __nocfi int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	return security_task_fix_setuid(new, old, flags);
}

// bprm
extern int security_bprm_check(struct linux_binprm *bprm);
static __nocfi int ksu_bprm_check(struct linux_binprm *bprm)
{
	return security_bprm_check(bprm);
}

static int lsm_hunt_symbol_callsite(uintptr_t target_callsite, ptrdiff_t target_width, uintptr_t symbol_addr, uintptr_t hook_addr)
{
	if (!target_callsite || !symbol_addr) {
		pr_info("lsm_hijack: no vallsite or symbol addr specified!\n");
		return 1;
	}

	uintptr_t start_addr = (uintptr_t)target_callsite;
	uintptr_t end_addr = start_addr + target_width;
	uintptr_t curr_addr = start_addr;
	uint32_t raw_instruction; // arm64 wordsize

start_scan:
	if (curr_addr >= end_addr)
		goto bail;

	if (copy_from_kernel_nofault(&raw_instruction, (void *)curr_addr, sizeof(uint32_t)))
		goto step_up;

	// bl
	if ((raw_instruction & 0xFC000000) != 0x94000000)
		goto step_up;

	// 26-bit signed relative jump offset
	// FC, D, E, F, so 3
	int32_t imm26 = raw_instruction & 0x03FFFFFF;

	// in case of backward jumps
	if (imm26 & 0x02000000)
		imm26 |= 0xFC000000;

	long byte_delta = (long)imm26 * 4;
	uintptr_t calculated_destination = curr_addr + byte_delta;

	if (calculated_destination != symbol_addr)
		goto step_up;

	pr_info("lsm_hijack: found call site at 0x%lx\n", curr_addr);

	uintptr_t new_byte_delta = (uintptr_t)((uintptr_t)hook_addr - curr_addr);

	// raw bytes to ARM64 relative insn delta
	// basically 'how many steps', 'how many words away'
	int32_t new_imm26 = (int32_t)(new_byte_delta / 4);

	// so max jump is like 2^25 * 4 bytes.
	uint32_t new_instruction = (0x94000000 | (new_imm26 & 0x03FFFFFF));

	uintptr_t base = curr_addr & PAGE_MASK;
	uintptr_t offset = curr_addr & ~PAGE_MASK;
			
	struct page *page = phys_to_page(__pa(base));
	if (!page)
		goto step_up;

	void *writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		goto step_up;

	uint32_t *patch_target = (uint32_t *)((unsigned long)writable_addr + offset);

	preempt_disable();
	local_irq_disable();

	WRITE_ONCE(*patch_target, new_instruction);

	local_irq_enable();
	preempt_enable();

	vunmap(writable_addr);

	flush_icache_range(base, base + PAGE_SIZE);
	smp_mb();

	pr_info("lsm_hijack: patched callsite at 0x%lx to hook!\n", curr_addr);
	return 0;

step_up:
	curr_addr = curr_addr + sizeof(uint32_t);
	goto start_scan;

bail:
	pr_info("lsm_hijack: callsite scan done!\n");
	return 1;
}

static void __init ksu_core_init(void)
{
	int ret;
	uintptr_t target_callsite;
	uintptr_t symbol_addr;

	// rename
	extern int vfs_rename(struct renamedata *rd);
	target_callsite = (uintptr_t)&vfs_rename;
	symbol_addr = (uintptr_t)&security_inode_rename;

	ret = lsm_hunt_symbol_callsite(target_callsite, 256 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_inode_rename);
	pr_info("lsm_hijack: security_inode_rename: ret %d \n", ret);
	symbol_addr = NULL;

	// setuid
	extern long __sys_setresuid(uid_t ruid, uid_t euid, uid_t suid);
	target_callsite = (uintptr_t)&__sys_setresuid;
	symbol_addr = (uintptr_t)&security_task_fix_setuid;

	ret = lsm_hunt_symbol_callsite(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_task_fix_setuid);
	pr_info("lsm_hijack: security_task_fix_setuid: ret %d \n", ret);
	symbol_addr = NULL;

	// bprm, TODO: refine
	target_callsite = (uintptr_t)kallsyms_lookup_name("bprm_execve");
	symbol_addr = (uintptr_t)&security_bprm_check;
	
	ret = lsm_hunt_symbol_callsite(target_callsite, 256 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_bprm_check);
	pr_info("lsm_hijack: security_bprm_check: ret %d \n", ret);
	symbol_addr = NULL;

}
