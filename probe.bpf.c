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
        struct path *path;
	char *dev_name;
	char *type;
	unsigned int ns;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, unsigned int);
	__type(value, struct ebpf_data);
	__uint(max_entries, 1000);
} ns_map SEC(".maps");

extern int bpf_image_measure(void *, int) __ksym;
extern int fs_traverse(char *, unsigned int ns)  __ksym;
extern char *measure_file(struct file *file, char *aggregate)  __ksym;
extern  int ima_store(unsigned int ns, char *agreggate, struct dentry *root, int hash_algo,
		struct ima_max_digest_data *hash, int length) __ksym;
extern struct file *open_wrapper(char *) __ksym;


SEC("lsm.s/sb_mount")
int BPF_PROG(mount_hook, const char *dev_name, const struct path *path,
	 const char *type, unsigned long flags, void *data)
{
    struct task_struct *task;
    struct ebpf_data *stored;
    unsigned int ns;
    int ret;

    task = (void *) bpf_get_current_task();
    ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

    stored = bpf_map_lookup_elem(&ns_map, &ns);
    if (stored) {
	    ret = bpf_image_measure((void *) &stored, sizeof(&stored));
    } else {
   	struct ebpf_data prog_data = { .path =path, .dev_name = dev_name, .type = type, .ns = ns };

    	ret = bpf_image_measure((void *) &prog_data, 
			sizeof(&prog_data));

	/*if (ret == 1)
		bpf_map_update_elem(&ns_map, &ns, (void *) &prog_data, BPF_ANY);*/
    }
    return 0;

}

