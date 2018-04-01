# 实验一报告
## 实验环境搭建
1. 下载qemu
2. 下载内核代码linux-4.15.11.tar.gz
3. 解压压缩包转到文件夹内
4. 使用make menuconfig
5. 选上Compile the kernel with debug info, 取消KASLR 
6. make
7. make modules_install
8. mkinitcpio -k 4.15.11 -g rootfs.img
9. qemu-system-x86_64 -kernel arch/x86/boot/bzImage -initrd rootfs.img -s -S
10. 新开一个terminal
11. 转到内核文件夹内
12. gdb vmlinux
13. gdb 内
    - target remote : 1234
    - b start_kernel
    - c
    - 开始调试
## linux 内核启动过程
1. set_task_stack_end_magic(&init_task);
    - 设置栈边界，for overflow detection
2. smp_setup_processor_id();
    - 空操作
3. cgroup_init_early();
    - 早期初始化cgroup
4. local_irq_disable();
    - 禁止中断，在必要的初始化设置之后再开启
5. boot_cpu_init();  
    - Mark the boot cpu "present", "online" etc for SMP and UP case
    - set_cpu_online(cpu, true);  当前所有在线的CPU以及通过 cpu_present 来决定被调度出去的CPU
    - set_cpu_active(cpu, true);  
    - set_cpu_present(cpu, true);   表示当前热插拔的CPU
    - set_cpu_possible(cpu, true);  设置支持CPU热插拔时候的CPU ID
6. pr_notice("%s", linux_banner);
    - 第一条打印消息，内容为："Linux version 4.15.11 (josen@josenlinux)
 (gcc version 7.3.1 20180312 (GCC)) #2 SMP Thu Mar 29 15:10:43 CST 2018\n"

7. setup_arch(&command_line);
    - 先调用memblock_reserve分配内存
    - early_reserve_initrd(); 初始化initrd
    - idt_setup_early_traps();  idt setup and load
    - early_cpu_init(); cpu dev数的确定以及一些identify
    - early_ioremap_init();
        - 早期的ioremap setup
        - pmd的一些设置和检查
    - ROOT_DEV = 0, screen_info, edid_info, saved_video_mode, bootloader_type = 176, bootloader_version = 0, iomem_resource.end; 一些设备值的初始化
    - e820__memory_setup();
        - x86_init.resources.memory_setup();
        - e820资源初始化以及一些信息的设置
    - parse_setup_data();
        - boot_params的一些解析
    - init_mm， code_resorce, data_resource, bss_resource 初始化
    - strlcpy(command_line, boot_command_line, COMMAND_LINE_SIZE); 命令复制
    - x86_configure_nx(); 
        - __supported_pte_mask = 18446744073709551615 设置这个值
    - parse_early_param();
        - 早期boot_command_line的解析
    - x86_report_nx(); 
        - 全是prink,一些信息的报告
    -  memblock_x86_reserve_range_setup_data();/* after early param, so could get panic from serial */ 
    -  e820__reserve_setup_data(); 
    -  e820__finish_early_params(); 
        -  e820信息搜集完毕
    -  dmi_scan_machine(); dmi_memdev_walk(); dmi_set_dump_stack_arch_desc(); 
        -  dmi设备的设置
    -  x86_init.resources.probe_roms();
    -  insert_source/* after parse_early_param, so could debug it */
    -  e820_add_kernel_range(); 
        -  e820__mapped_all(start, start + size, E820_TYPE_RAM))
        -  内存映射？
    -  trim_bios_range();
        -  由于bios内存区域带来的一些影响，对e820__range进行调整
    - max_pfn = e820__end_of_ram_pfn(); max_pfn = 32736
        - max_possible_pfn和max_low_pfn与max_pfn相同
    - find_smp_config();
        - Find and reserve possible boot-time SMP configuration
    - reserve_ibft_region();
    - early_alloc_pgt_buf();
    - mtrr_bp_init();/* update e820 for memory not covered by WB MTRRs */
    - init_cache_modes();
    - find_smp_config(); Find and reserve possible boot-time SMP configuration
    - early_alloc_pgt_buf(); 
        - 分配page table buffer
    - reserve_brk();
        - 决定brk，防止e820__memblock_setup()使用memblock_find_in_range的时候产生区域重叠
    - cleanup_highmap();
    - memblock_set_current_limit(ISA_END_ADDRESS); 
        - memblock.current_limit = ISA_END_ADDRESS;值为1048576
    - e820__memblock_setup();
        - e820 entry的设置和memblock的分配
    - reserve_bios_regions();
        - 保存bios内存区域
    - e820__memblock_alloc_reserved_mpc_new();/* preallocate 4k for mptable mpc */ 
    - setup_bios_corruption_check();
    - reserve_real_mode();
        - real mode内存分配和设置
    - trim_platform_memory_ranges(); trim_low_memory_range();
    - init_mem_mapping(); 
    - idt_setup_early_pf();
    - memblock_set_current_limit(get_max_mapped()); 
    - setup_log_buf(1);/* Allocate bigger log buffer */
    - reserve_initrd();
        - 为ramdisk_image分配内存
    - acpi_table_upgrade(); vsmp_init(); io_delay_init();  early_platform_quirks();
    - acpi_boot_table_init(); early_acpi_boot_init(); initmem_init(); dma_contiguous_reserve(max_pfn_mapped << PAGE_SHIFT);
        - 设备初始化
    - reserve_crashkernel();Reserve memory for crash kernel
8. add_device_randomness(command_line, strlen(command_line));
9. mm_init_cpumask(&init_mm);
    - 内存中关于cpu一些初始化设置
10. setup_command_line(command_line);
    - 命令保存
11. setup_nr_cpu_ids();
    - nr_cpu_ids = 1
12. setup_per_cpu_areas(); Allocate percpu area
13. boot_cpu_state_init();
    - per_cpu_ptr(&cpuhp_state, smp_processor_id())->state = CPUHP_ONLINE; 
14. smp_prepare_boot_cpu(); /* arch-specific boot-cpu hooks */
15. build_all_zonelists(NULL); 
    - 设置zone
16. page_alloc_init();
17. parse_early_param();
   - 解析commmand line
18. jump_label_init(); 
19. setup_log_buf(0);
    - setups the printk log buffer
20. vfs_caches_init_early();
21. sort_main_extable(); 
22. trap_init();
23. mm_init(); 
    - 内存分配和初始化
24. early_trace_init();  /* trace_printk can be enabled here */
    - 给prink使用分配内存，如果trace_printk有使用的话
25. sched_init();
    - Set up the scheduler prior starting any interrupts
26. preempt_disable
    - 被跳过
27. radix_tree_init();
28. housekeeping_init();
    - Set up housekeeping before setting up workqueues to allow the unbound workqueue to take non-housekeeping into account.
    - 直接被跳过
29. workqueue_init_early(); 
    - Allow workqueue creation and work item queueing/cancelling early.  Work item execution depends on kthreads and starts after workqueue_init().
    - 工作队列初始化，为每个CPU都分配了
30. rcu_init(); 
    - 进入了kernel/rcu/tree.c
    - rcu tree结构的构建和初始化
31. trace_init(); /* Trace events are available after this */
32. early_irq_init();/* init some links before init_ISA_irqs() */
33. init_IRQ(); 
34. tick_init();
35. init_timers();
36. hrtimers_init();
37. softirq_init();
38. timekeeping_init();
39. time_init();
40. printk_safe_init();
41. perf_event_init();
42. profile_init();
43. call_function_init();
44. WARN(!irqs_disabled(), "Interrupts were enabled early\n"); 
45. local_irq_enable();
    - 就执行了asm volatile("sti": : :"memory");
    - 开始允许中断
46. kmem_cache_init_late();
47. console_init(); 
    - enable the console
    - qemu开始进行输出
48. mem_encrypt_init();
    - mark the bounce buffers as decrypted
49. setup_per_cpu_pageset(); 
50. numa_policy_init();
51. acpi_early_init(); 
52. late_time_init(); 
53. calibrate_delay();
54. pid_idr_init();
55. anon_vma_init();
56. thread_stack_cache_init();
    - 空操作
57. cred_init();
    - allocate a slab in which we can store credentials
58. fork_init();
    - create a slab on which task_structs can be allocated 
    - do the arch specific task caches init
    - set_max_threads(MAX_THREADS); gdb 显示值为 <optimized out>
    - init_task.signal 结构设置
    - init_user_ns.ucount_max数组设置
59. proc_caches_init();
    - sighand_cachep, signal_cachep, files_cachep, fs_cachep, mm_cachep使用kmem_cache_create分配cache?
    - vm_area_cachep使用KMEM_CACHE进行分配
    - mmap_init();
    - nsproxy_cache_init();
60. buffer_init();
61. key_init();
62. security_init();
    - 输出SELinux: initializing
63. dbg_late_init();
64. vfs_caches_init();
    - 一些关于mount的初始化
65. pagecache_init();
66. signals_init();
    - 创建sigqueue_cachep
67. proc_root_init();
    - 注册一个文件系统
    - 设置当前进程信息
    - proc_symlink("mounts", NULL, "self/mounts");创建一个符号链接？
    - proc_net_init(); 创建了一个symlink和register pernet_subsys
    - 创建了文件夹sysvipc, fs, driver
    - 创建了mount point "fs/nfsd"
    - tty init
    - 创建了文件夹bus
    - proc_sys_init()
        - 创建了文件夹sys
        - sysctl_init
68. nsfs_init();
69. cpuset_init();
70. cgroup_init();
71. taskstats_init_early();
72. delayacct_init();
73. check_bugs();
74. acpi_subsystem_init();
75. arch_post_acpi_subsys_init();
76. rest_init();
    - rcu_scheduler_starting(); makes RCU scheduler active
    - pid = kernel_thread(kernel_init, NULL, CLONE_FS); 创建init进程
    - pid = kernel_thread(kthreadd, NULL, CLONE_FS | CLONE_FILES); 创建kthreadd进程
    - rcu_read_lock(); 获得锁
    - kthreadd_task = find_task_by_pid_ns(pid, &init_pid_ns); returns pointer to the task_struct
    - rcu_read_unlock(); 释放锁
    - system_state = SYSTEM_SCHEDULING; Enable might_sleep() and smp_processor_id() checks.
    - complete(&kthreadd_done);
    - schedule_preempt_disabled(); The boot idle thread must execute schedule() at least once to get things moving
    - cpu_startup_entry(CPUHP_ONLINE); Call into cpu_idle with preempt disabled
        - arch_cpu_idle_prepare(); 空操作
        - cpuhp_online_idle(state); 
        - while (1) do_idle();
77. 然后就进入emergency shell了

## 关键事件
1. 激活第一个CPU : boot_cpu_init, 通过掩码初始化
每一个CPU
2. Linux 内核的第一条打印信息 : pr_notice("%s", linux_banner);
    - 内容为："Linux version 4.15.11 (josen@josenlinux)
 (gcc version 7.3.1 20180312 (GCC)) #2 SMP Thu Mar 29 15:10:43 CST 2018\n"
 3. 体系结构相关的初始化: setup_arch(&command_line);与系统架构有关的初始化，主要是各种设备和内存、处理器的一些设置和初始化
 4. 进程调度器初始化: sched_init
 5. 创建root：proc_root_init; 主要是注册一个文件系统，创建一些必要的文件夹，设置mount point等
 6. 最后一步：rest_init; 主要是创建init和kthreadd进程
