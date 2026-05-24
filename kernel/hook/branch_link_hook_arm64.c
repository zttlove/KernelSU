#ifndef CONFIG_ARM64
#error "only meant for ARM64!"
#endif

#ifndef CONFIG_KALLSYMS
#error "kallsyms is required for branch link hack!"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
#error "probably impossible for sub 4.17, unless you have backported do_faccessat"
#endif

/**
 *  NOTE: theres no way to hijack sys_reboot and sys_newfstat cleanly.
 *
 *  however, we will require kprobes for this feature. and this is still highly experimental. (260524)
 *  this works the same as lsm_hooks_static.c, where we patch caller's site
 *
 *  as of now this has been tested to work on 6.12 aarch64 GKI
 *
 *  Changelog:
 *	- init, 260524
 *	- partial/probably-broken 4.19/5.4 compat, 260525
 *
 * TODO: 
 *	try to fixup for 4.19 / 5.4
 *	wire compat syscalls maybe?
 *	reduce kallsyms dependece
 *
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
extern int vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat, int flags);
static __nocfi int ksu_vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat, int flags)
{
	ksu_handle_stat(&dfd, &filename, &flags);
	return vfs_fstatat(dfd, filename, stat, flags);
}
#else
extern int vfs_statx(int dfd, const char __user *filename, int flags, struct kstat *stat, u32 request_mask);
static int ksu_vfs_statx(int dfd, const char __user *filename, int flags, struct kstat *stat, u32 request_mask)
{
	ksu_handle_stat(&dfd, &filename, &flags);
	return vfs_statx(dfd, filename, flags, stat, request_mask);
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static long (*do_faccessat_fn)(int dfd, const char __user *filename, int mode, int flags) __read_mostly = NULL;
static __nocfi long ksu_do_faccessat(int dfd, const char __user *filename, int mode, int flags)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return do_faccessat_fn(dfd, filename, mode, flags);
}
#else
extern long do_faccessat(int dfd, const char __user *filename, int mode);
static __nocfi long ksu_do_faccessat(int dfd, const char __user *filename, int mode)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return do_faccessat(dfd, filename, mode);
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
static int (*do_execveat_common_fn)(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags) __read_mostly = NULL;
static __nocfi int ksu_do_execveat_common(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags)
{
	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
	return do_execveat_common_fn(fd, filename, argv, envp, flags);
}
#else
static int (*__do_execve_file_fn)(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags, struct file *file) __read_mostly = NULL;
static __nocfi int ksu_do_execve_file(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags, struct file *file)
{
	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
	return __do_execve_file_fn(fd, filename, argv, envp, flags, file);
}
extern int do_execve(struct filename *filename, const char __user *const __user *__argv, const char __user *const __user *__envp);
static __nocfi int ksu_do_execve(struct filename *filename, const char __user *const __user *__argv, const char __user *const __user *__envp)
{
	struct user_arg_ptr argv = { .ptr.native = __argv };
	struct user_arg_ptr envp = { .ptr.native = __envp };
	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);

	return do_execve(filename, __argv, __envp);
}
#endif

static int su_hunt_symbol_callsite(uintptr_t target_callsite, ptrdiff_t target_width, uintptr_t symbol_addr, uintptr_t hook_addr)
{
	if (!target_callsite || !symbol_addr) {
		pr_info("sucompat_hijack: no vallsite or symbol addr specified!\n");
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

	pr_info("sucompat_hijack: found call site at 0x%lx\n", curr_addr);

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

	pr_info("sucompat_hijack: patched callsite at 0x%lx to hook!\n", curr_addr);
	return 0;

step_up:
	curr_addr = curr_addr + sizeof(uint32_t);
	goto start_scan;

bail:
	pr_info("sucompat_hijack: callsite scan done!\n");
	return 1;
}

static int ksu_branch_link_patch_init()
{
	int ret;
	uintptr_t target_callsite;
	uintptr_t symbol_addr;

// newfstatat
	extern long __arm64_sys_newfstatat(const struct pt_regs *regs);
	target_callsite = (uintptr_t)&__arm64_sys_newfstatat;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	symbol_addr = (uintptr_t)&vfs_fstatat;
	ret = su_hunt_symbol_callsite(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_vfs_fstatat);
	pr_info("sucompat_hijack: vfs_fstatat: ret %d \n", ret);
#else
	symbol_addr = (uintptr_t)&vfs_statx;
	ret = su_hunt_symbol_callsite(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_vfs_statx);
	pr_info("sucompat_hijack: vfs_statx: ret %d \n", ret);
#endif
	symbol_addr = NULL;

// faccessat
	extern long __arm64_sys_faccessat(const struct pt_regs *regs);
	target_callsite = (uintptr_t)&__arm64_sys_faccessat;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
	symbol_addr = (uintptr_t)kallsyms_lookup_name("do_faccessat");
	do_faccessat_fn = symbol_addr;
	ret = su_hunt_symbol_callsite(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_faccessat);
#else
	symbol_addr = (uintptr_t)&do_faccessat;
	ret = su_hunt_symbol_callsite(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_faccessat);
#endif
	pr_info("sucompat_hijack: do_faccessat: ret %d \n", ret);
	symbol_addr = NULL;

// execve
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	extern long __arm64_sys_execve(const struct pt_regs *regs);
	target_callsite = (uintptr_t)&__arm64_sys_execve;
	symbol_addr = (uintptr_t)kallsyms_lookup_name("do_execveat_common");
	do_execveat_common_fn = symbol_addr;
	ret = su_hunt_symbol_callsite(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_execveat_common);
	pr_info("sucompat_hijack: do_execveat_common: ret %d \n", ret);
#else
	extern long __arm64_sys_execve(const struct pt_regs *regs);
	target_callsite = (uintptr_t)&__arm64_sys_execve;
	symbol_addr = (uintptr_t)kallsyms_lookup_name("__do_execve_file.cfi_jt");
	if (!symbol_addr)
		symbol_addr = (uintptr_t)kallsyms_lookup_name("__do_execve_file");

	__do_execve_file_fn = symbol_addr;
	ret = su_hunt_symbol_callsite(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&ksu_do_execve_file);
	pr_info("sucompat_hijack: __do_execve_file: ret %d \n", ret);
	if (ret) {
		symbol_addr = (uintptr_t)&do_execve;
		ret = su_hunt_symbol_callsite(target_callsite, 128 * sizeof(void *), symbol_addr, (uintptr_t)&do_execve);
		pr_info("sucompat_hijack: do_execve: ret %d \n", ret);
	}
#endif
	symbol_addr = NULL;

	return 0;
}
