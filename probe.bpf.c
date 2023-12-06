#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <string.h>

#define bpf_target_x86
#define bpf_target_defined
#define PROT_EXEC 0x04

char _license[] SEC("license") = "GPL";

struct ebpf_data {
        struct dentry *root;
        struct path *pwd;
        unsigned int cgroup_ns;
        unsigned int uts_ns;
        unsigned int ipc_ns;
        unsigned int pid_ns;
        struct linux_binprm *bprm;
};

extern int bpf_process_measurement(void *, int) __ksym;
extern int measure_file(struct file *) __ksym;

SEC("lsm.s/bprm_check_security")
int BPF_PROG(handle_execv, struct linux_binprm *bprm) 
{
    struct task_struct *task;
    struct dentry *root;
    struct path pwd;
    unsigned int cgroup_ns;
    unsigned int uts_ns;
    unsigned int ipc_ns;
    unsigned int pid_ns;
    int ret;
    
    task = (void *) bpf_get_current_task();
    uts_ns = BPF_CORE_READ(task, nsproxy, uts_ns, ns.inum);	
    cgroup_ns = BPF_CORE_READ(task, nsproxy, cgroup_ns, ns.inum);
    ipc_ns = BPF_CORE_READ(task, nsproxy, ipc_ns, ns.inum);
    pid_ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    pwd = BPF_CORE_READ(task,fs,pwd);
    root = BPF_CORE_READ(task,fs, pwd.dentry, d_parent);

    struct ebpf_data data = { .root = root, .pwd = &pwd, .cgroup_ns = cgroup_ns, .uts_ns = uts_ns, 
   	.ipc_ns = ipc_ns, .pid_ns = pid_ns, .bprm = bprm };

    ret = bpf_process_measurement((void *) &data, sizeof(&data));

    return 0;

}
