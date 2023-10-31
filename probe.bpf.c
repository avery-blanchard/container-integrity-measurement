#include "vmlinux.h"
/*#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/types.h>*/
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#define X86_64_UNSHARE_SYSCALL 272
#define UNSHARE_SYSCALL X86_64_UNSHARE_SYSCALL
#include <string.h>

#define bpf_target_x86
#define bpf_target_defined

char _license[] SEC("license") = "GPL";

struct ebpf_data {
        struct dentry *root;
	struct path *pwd;
	unsigned int ns;
};

extern int bpf_image_measure(void *, int) __ksym;
extern int measure_file(struct file *) __ksym;

SEC("lsm.s/cred_prepare")
int BPF_PROG(handle_cred_prepare, struct cred *new, const struct cred *old,
             gfp_t gfp, int ret)
{
    struct task_struct *task;
    struct dentry *root;
    struct path pwd;
    unsigned int ns;
    struct pt_regs *regs;
    int syscall;
    unsigned long flags;
   
    task = (struct task_struct *) bpf_get_current_task();  
    //regs = (struct pt_regs *) bpf_task_pt_regs(task);
    syscall = 0; //regs->orig_ax;

    if (syscall == 0) { //UNSHARE_SYSCALL) {

	//flags = PT_REGS_PARM1_CORE(regs);

    	/* Filter on flags
    	if (!(flags & CLONE_NEWUSER)) {
        	return 0;
    	}	*/
        ns = BPF_CORE_READ(task, nsproxy, uts_ns, ns.inum);
	pwd = BPF_CORE_READ(task,fs,pwd);
	root = BPF_CORE_READ(task,fs, pwd.dentry, d_parent);
	struct ebpf_data data = { .root = root, .pwd = &pwd, .ns = ns };
	
	ret = bpf_image_measure((void *) &data, 
			sizeof(&data));


    }
    
    return 0;

}
