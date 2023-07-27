/*
 * Container IMA using eBPF
 *
 * File: container_ima.c
 * 	Implements namespaced IMA measurements,
 * 	defines kernel symbols, registers kfuncs
 * 	with libbpf
 */

#define _GNU_SOURCE
#include <linux/unistd.h>
#include <linux/mount.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/printk.h>
#include <linux/ima.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/integrity.h>
#include <uapi/linux/bpf.h>
#include <linux/bpf.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <linux/fcntl.h>
#include <crypto/hash_info.h>
#include <linux/bpf_trace.h>
#include <uapi/linux/bpf.h>
#include <linux/bpf_lirc.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/sysfs.h>
#include <linux/bpfptr.h>
#include <linux/bsearch.h>
#include <linux/btf_ids.h>
#include <uapi/linux/btf.h>
#include <uapi/linux/bpf.h>
#include <linux/iversion.h>
#include <linux/preempt.h>
#include <linux/utsname.h>
#include <linux/fs_struct.h>

#include "container_ima.h"

#define MODULE_NAME "ContainerIMA"
extern void security_task_getsecid(struct task_struct *p, u32 *secid);
extern const int hash_digest_size[HASH_ALGO__LAST];
extern char *dentry_path_raw(const struct dentry *, char *, int);
extern void unregister_kprobe(struct kprobe *p);

static DEFINE_MUTEX(tpm_mutex);


#define preempt_enable_no_resched_notrace() \
do { \
        barrier(); \
        __preempt_count_dec(); \
} while (0)

static char func_name[KSYM_NAME_LEN] = "ksys_unshare";
void synchronize_sched(void)
{
        RCU_LOCKDEP_WARN(lock_is_held(&rcu_bh_lock_map) ||
                         lock_is_held(&rcu_lock_map) ||
                         lock_is_held(&rcu_sched_lock_map),
                         "Illegal synchronize_sched() in RCU read-side critical section");
}

char *kprobe_measure_file(struct file *file, char *aggregate)
{

        int length, check, hash_algo;
        char buf[32];
        char *extend;
        struct ima_max_digest_data hash;


        hash_algo = ima_file_hash(file, buf, sizeof(buf));
        hash.hdr.length = hash_digest_size[hash_algo];
        hash.hdr.algo =  hash_algo;
        memset(&hash.digest, 0, sizeof(hash.digest));

        length = sizeof(hash.hdr) + hash.hdr.length;

        extend = strncat(aggregate, buf, hash.hdr.length);

        check = ima_calc_buffer_hash(extend, sizeof(extend), &hash.hdr);

        memcpy(aggregate, hash.digest, 32);

        return aggregate;

}

/* Function might sleep, grab a lock 
 */
int ima_store_kprobe(unsigned int ns, char *agreggate, struct dentry *root, int hash_algo,
                struct ima_max_digest_data *hash, int length)
{

        int i, check;
        u64 i_version;
        struct inode *inode;
        struct ima_template_entry *entry;
        struct integrity_iint_cache iint = {};
        struct ima_template_desc *desc = NULL;
        char name[64];
        char *extend;

        inode = root->d_inode;
        i_version = inode_query_iversion(inode);

        iint.version = i_version;
        iint.inode = inode;
        iint.ima_hash = &hash->hdr;
        iint.ima_hash->algo =  4;
        iint.ima_hash->length = hash_digest_size[4];

        memcpy(hash->hdr.digest, hash->digest, sizeof(hash->digest));
        memcpy(iint.ima_hash, hash, length);


        sprintf(name, "%u", ns);

        /* IMA event data */
        struct ima_event_data event_data = { .iint = &iint,
                                             .filename = name
                                             //.buf = name,
                                             //.buf_len = strlen(name)
                                           };

        /* Initialize IMA template */
        check = ima_alloc_init_template(&event_data, &entry, desc);
        if (check < 0) {
                return 0;
        }

        /* Enable and protect task preemption, Store template, extend to PCR 11 */
        //preempt_enable();
        preempt_enable_no_resched_notrace();
        mdelay(0);
        if (!in_task())
                return 0;
        check = ima_store_template(entry, 0, inode, name, 11);
        preempt_disable();
        if ((!check || check == -EEXIST)) {
                        iint.flags |= IMA_MEASURED;
                iint.measured_pcrs |= (0x1 << 11);
                return 0;
        }
        /* Clean up if needed */
        for (i = 0; i < entry->template_desc->num_fields; i++)
                kfree(entry->template_data[i].data);

        kfree(entry->digests);
        kfree(entry);

        return check;

}
int fs_traverse(struct dentry *root, unsigned int ns, char *aggregate)
{
        struct dentry *cur;
        int hash_algo, length;
        struct file *file;
        struct ima_max_digest_data hash;

        list_for_each_entry(cur, &root->d_subdirs, d_child) {
                char *f_name;
                char buf[256];
                struct inode *inode;
                struct file *file;

                f_name = dentry_path_raw(cur, buf, 256);
                inode = d_real_inode(cur);
                if (!inode) {
                        continue;
                }

                if (S_ISREG(inode->i_mode)) {
                        file = filp_open(f_name, O_RDONLY, 0);
                        if (!IS_ERR(file)) {
                                aggregate =  kprobe_measure_file(file, aggregate);
                                filp_close(file, 0);
                        }
                }
                else if (S_ISDIR(inode->i_mode)) {
                        fs_traverse(cur, ns, aggregate);
                }

        }
        return 0;

}

void __kprobes handler_post(struct kprobe *p, struct pt_regs *ctx, unsigned long flags)
{
        int check, length;
        unsigned int ns;
        struct task_struct *task;
        struct fs_struct *fs;
        unsigned long args;
        struct ima_max_digest_data hash;
        char *aggregate;
        char ns_buf[128]; 

	ns = current->nsproxy->uts_ns->ns.inum;
	// do not measure host NS
	if (ns == 4026531838)
		return;

        aggregate = kmalloc(sizeof(aggregate)* 64, GFP_KERNEL);

        fs = current->fs;

        check = fs_traverse(fs->pwd.dentry->d_parent, ns, aggregate);

        hash.hdr.length = hash_digest_size[4];
        hash.hdr.algo =  4;
        memset(&hash.digest, 0, sizeof(hash.digest));
        length = sizeof(hash.hdr) + hash.hdr.length;

        sprintf(ns_buf, "%u", ns);
        aggregate = strncat(aggregate, ns_buf, 32);


        check = ima_calc_buffer_hash(aggregate, sizeof(aggregate), &hash.hdr);
        if (check < 0)
                return;

        check = mutex_lock_killable(&tpm_mutex);
        ima_store_kprobe(ns, aggregate, fs->pwd.dentry->d_parent, 4, &hash, length);

        kfree(aggregate);

        mutex_unlock(&tpm_mutex);
        return;
}


int __kprobes handler_pre(struct kprobe *p, struct pt_regs *regs)
{
        return 0;
}
static struct kprobe unshare_probe = {
        .symbol_name = func_name,
};

/*
 * ima_store_measurement
 * 	struct ima_max_digest_data *hash: hash information
 * 	struct file *file: file measured
 * 	char *filename: name of measured file (ns:file path) 
 * 	int length: size of hash data
 * 	struct ima_template_desc *desc: description of IMA template
 * 	int hash_algo: algorithm used in measurement 
 *
 * 	Store file with namespaced measurement and file name
 * 	Extend to pcr 11
 */
noinline int ima_store_measurement(struct ima_max_digest_data *hash, 
		struct file *file, char *filename, int length, 
		struct ima_template_desc *desc, int hash_algo)
{

	int i, check;
	u64 i_version;
	struct inode *inode;
	struct ima_template_entry *entry;
        struct integrity_iint_cache iint = {};

	/* init inode integrity data */
	inode = file->f_inode;
	i_version = inode_query_iversion(inode);

        iint.inode = inode;
        iint.ima_hash = &hash->hdr;
        iint.ima_hash->algo =  hash_algo;
        iint.ima_hash->length = hash_digest_size[hash_algo];
        iint.version = i_version;
        
	memcpy(hash->hdr.digest, hash->digest, sizeof(hash->digest));

        memcpy(iint.ima_hash, hash, length);
        
	/* IMA event data */
	struct ima_event_data event_data = { .iint = &iint,
                                             .file = file,
                                             .filename = filename
                                           };

	/* IMA template field data */
        check = ima_alloc_init_template(&event_data, &entry, desc);
        if (check < 0) {
                return 0;
        }

	/* Store template, extend to PCR 11 */
        check = ima_store_template(entry, 0, inode, filename, 11);
        if ((!check || check == -EEXIST) && !(file->f_flags & O_DIRECT)) {
                iint.flags |= IMA_MEASURED;
                iint.measured_pcrs |= (0x1 << 11);
                return 0;
        }

	/* Clean up if needed */
        for (i = 0; i < entry->template_desc->num_fields; i++)
                kfree(entry->template_data[i].data);

        kfree(entry->digests);
        kfree(entry);

	return check;
}

/*
 * ima_file_measure
 * 	struct file *file: file to be measured
 * 	unsigned int ns: namespace 
 * 	struct ima_template_desc *decs: description of IMA template
 * 	
 * 	Measures file using ima_file_hash 
 * 	Namespaced measurements are as follows
 * 		HASH(measurement || NS) 
 * 	Measurements are logged with the format NS:file_path 
 */
noinline int ima_file_measure(struct file *file, unsigned int ns, 
		struct ima_template_desc *desc)
{
        int check, length, hash_algo;
	char buf[64];
	char *extend;
	char *path;
	char filename[128];
	char ns_buf[128];
        struct ima_max_digest_data hash;


	/* Measure file */
        hash_algo = ima_file_hash(file, buf, sizeof(buf));

	path = ima_d_path(&file->f_path, &path, filename);
	if (!path) {
		return 0;
	}
	
	/* Catch all for policy errors, todo */
	if (path[0] != '/')
		return 0;

	sprintf(ns_buf, "%u", ns);
	sprintf(filename, "%u:%s", ns, path);
	
	extend = strncat(buf, ns_buf, 32);

	hash.hdr.length = hash_digest_size[hash_algo]; 
        hash.hdr.algo =  hash_algo;
        memset(&hash.digest, 0, sizeof(hash.digest));

	length = sizeof(hash.hdr) + hash.hdr.length;
	
	/* Final measurement:
	 * HASH(measurement || NS) 
	 * Concatenate file measurement with the NS buffer
	 * Hash the concatonated string */	
	check = ima_calc_buffer_hash(extend, sizeof(extend), &hash.hdr);
	if (check < 0)
		return 0;
	
	check = ima_store_measurement(&hash, file, filename, length, 
			desc, hash_algo);

	return 0;
}

/*
 * bpf_process_measurement 
 * 	void *mem: pointer to struct ebpf_data to allow though verifier
 * 	int mem__sz: size of pointer 
 *
 * 	Function gets action from ima policy, measures, and stores
 * 	accordingly.
 * 	Exported by libbpf, called by eBPF program hooked to LSM (mmap_file)
 */
noinline int bpf_process_measurement(void *mem, int mem__sz)
{

	int ret, action, pcr;
	struct inode *inode;
	struct mnt_idmap *idmap;
	const struct cred *cred;
	u32 secid;
	struct ima_template_desc *desc = NULL;
	unsigned int allowed_algos = 0;
	struct ebpf_data *data = (struct ebpf_data *) mem;
	struct file *file = data->file;
	unsigned int ns = data->ns;
	
	if (!file || ns == 4026531838)
		return 0;
	
	inode = file->f_inode;
	if (!S_ISREG(inode->i_mode))
                return 0;


	security_current_getsecid_subj(&secid);

	cred = current_cred();
	if (!cred)
		return 0;

	idmap = file->f_path.mnt->mnt_idmap; 

	/* Get action form IMA policy */
	pcr = 10;
	action = ima_get_action(idmap, inode, cred, secid, 
			MAY_EXEC, MMAP_CHECK, &pcr, &desc, 
			NULL, &allowed_algos);
	if (!action)  
		return 0;
	
	
	if (action & IMA_MEASURE)
		ret =  ima_file_measure(file, ns, desc);

	
	return 0;
}

BTF_SET8_START(ima_kfunc_ids)
BTF_ID_FLAGS(func, bpf_process_measurement, KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_ID_FLAGS(func,  ima_file_measure, KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_ID_FLAGS(func,  ima_store_measurement, KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_SET8_END(ima_kfunc_ids)

static const struct btf_kfunc_id_set bpf_ima_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &ima_kfunc_ids,
};
static int container_ima_init(void)
{

	/* Start container IMA */
	int ret;
	
	pr_info("Starting Container IMA\n");

	
	/* Register kernel module functions wiht libbpf */
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM, &bpf_ima_kfunc_set);
	if (ret < 0)
		return ret;
	
	
	/* Attach kprobe to kaalsysms_lookup_name to 
	 * get function address (symbol no longer exported */
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);

	/* Use kallsyms_lookup_name to retrieve kernel IMA functions */
	ima_calc_buffer_hash = (int(*)(const void *, loff_t len, 
				struct ima_digest_data *)) 
		kallsyms_lookup_name("ima_calc_buffer_hash");
	if (ima_calc_buffer_hash == 0) {
		pr_err("Lookup fails\n");
		return -1;
	}
	ima_template_desc_current =  (struct ima_template_desc *(*)(void)) 
		kallsyms_lookup_name("ima_template_desc_current");
        if (ima_template_desc_current == 0) {
                pr_err("Lookup fails\n");
                return -1;
        }
	
	ima_store_template =(int(*)(struct ima_template_entry *, int, 
				struct inode *, const unsigned char *, int)) 
		kallsyms_lookup_name("ima_store_template");
        if (ima_store_template == 0) {
                pr_err("Lookup fails\n");
                return -1;
        }


	ima_alloc_init_template = (int(*)(struct ima_event_data *, 
				struct ima_template_entry **, 
				struct ima_template_desc *)) 
		kallsyms_lookup_name("ima_alloc_init_template");
        if (ima_alloc_init_template == 0) {
                pr_err("Lookup fails\n");
                return -1;
        }

	ima_calc_field_array_hash = (int(*)(struct ima_field_data *, 
				struct ima_template_entry *)) 
		kallsyms_lookup_name("ima_calc_field_array_hash");
        if (ima_calc_field_array_hash == 0) {
                pr_err("Lookup fails\n");
                return -1;
        }

	ima_d_path = (const char *(*)(const struct path *, char **, 
				char *)) kallsyms_lookup_name("ima_d_path");
        if (ima_d_path == 0) {
                pr_err("Lookup fails\n");
                return -1;
        }
	
	ima_get_action = (int (*)(struct mnt_idmap *, struct inode *, 
				const struct cred *, u32,  int,  
				enum ima_hooks,  int *, 
				struct ima_template_desc **, 
				const char *, unsigned int *)) 
		kallsyms_lookup_name("ima_get_action");
        
	if (ima_get_action == 0) {
                pr_err("Lookup fails\n");
                return -1;
        }
	
	ima_hash_algo = (int) kallsyms_lookup_name("ima_hash_algo");

	if (ima_hash_algo == 0) {
		pr_err("Lookup fails\n");
		return -1;
	}

	ima_calc_field_array_hash = (int (*)(struct ima_field_data *,
			      struct ima_template_entry *)) 
		kallsyms_lookup_name("ima_calc_field_array_hash");

        if (ima_calc_field_array_hash == 0) {
                pr_err("Lookup fails\n");
                return -1;
        }

	unshare_probe.post_handler = handler_post;
        unshare_probe.pre_handler = handler_pre;
        ret = register_kprobe(&unshare_probe);
        if (ret < 0) {
                pr_err("kprobe registration fails %d\n", ret);
                return -1;
        }


	return ret;
}

static void container_ima_exit(void)
{
	pr_info("Exiting Container IMA\n");
	synchronize_sched();
        unregister_kprobe(&unshare_probe);
	return;
}

module_init(container_ima_init);
module_exit(container_ima_exit);


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(MODULE_NAME);
MODULE_AUTHOR("Avery Blanchard");

