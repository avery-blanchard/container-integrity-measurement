/*
 * Container IMA
 *
 * File: container_ima.c
 * 	Implements namespaced IMA measurements, 
 * 	measurements of container images, 
 * 	register/unregister kprobes,
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
#include <linux/dcache.h>
#include <linux/nsproxy.h>
#include <linux/init_task.h>
#include <linux/syscalls.h>

#include "container_ima.h"
#define MODULE_NAME "ContainerIMA"

extern void security_task_getsecid(struct task_struct *p, u32 *secid);
extern const int hash_digest_size[HASH_ALGO__LAST];
extern void unregister_kprobe(struct kprobe *p);
extern char *dentry_path_raw(const struct dentry *, char *, int);
extern struct nsproxy init_nsproxy;

/*
 * kprobe_measure_file
 * 	struct file *file: file to measure
 * 	char *aggregate: running hash value over image
 *  
 *	Measures file using ima_file_hash
 *	Measurements are concatonated and re-hashed
 *	with the prior file hashes for the image
 */
noinline char *kprobe_measure_file(struct file *file, char *aggregate)
{

        int length, check, hash_algo;
        char buf[32];
        char *extend;
        struct ima_max_digest_data hash;

        hash_algo = ima_file_hash(file, buf, sizeof(buf));
	if (hash_algo < 0) {
		pr_err("container-ima: ima_file_hash returns error");
		return aggregate;
	}
	hash.hdr.length = hash_digest_size[hash_algo];
        hash.hdr.algo =  hash_algo;
        memset(&hash.digest, 0, sizeof(hash.digest));

        length = sizeof(hash.hdr) + hash.hdr.length;

        extend = strncat(aggregate, buf, hash.hdr.length);

        check = ima_calc_buffer_hash(extend, sizeof(extend), &hash.hdr);

        memcpy(aggregate, hash.digest, 32);

        return aggregate;

}

/*
 * ima_store_kprobe
 * 	unsigned int vs: namespace
 * 	int hash_algo: algorithm used in measurement
 * 	struct ima_max_digest_data *hash: hash information
 * 	int length: size of hash data
 *
 * 	Store container image measurement in the IMA logs
 * 	Extend to pcr 11
 */
noinline int ima_store_kprobe(struct dentry *root, unsigned int ns, int hash_algo,
			      struct ima_max_digest_data *hash, int length, const char * path, int filecount)
{

        int i, check;
        u64 i_version;
        struct inode *inode;
        struct ima_template_entry *entry;
        struct integrity_iint_cache iint = {};
        struct ima_template_desc *desc = NULL;
        char name[256];
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

	snprintf(name, 254, "0x%x-%d-%s", ns, filecount, path ? path : "<nopath>");

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
	check = ima_store_template(entry, 0, inode, name, 11);
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
/* 
 * ima_measure_image_fs
 * 	struct dentry *root: root directory of namespace
 * 	char *root_hash: current hash value
 *
 * 	Traverse FS tree to measure all files
 */
noinline int ima_measure_image_fs(struct dentry *root, char *pwd, char *root_hash, int * pfilecounter) 
{
	int check, length;
	struct file *file;
	struct inode *inode;
	struct dentry *cur;
	char *pathbuf = NULL;
    	char *res = NULL;
	char *abspath = NULL;

	/* Docker: get abs path (pwd+dentry path) */
	/*
	abspath = kmalloc(PATH_MAX*2, GFP_KERNEL);
    if (!abspath) {
		pr_err("container-ima: %s: abspath allocation failed", pwd);
        return -1;
	}
	*/

	/* buffer for local (dentry) path */
	/*
	pathbuf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!pathbuf) {
		pr_err("container-ima: %s: pathbuf allocation failed", pwd);
		kfree(abspath);
    	return -1;
	}
    */

	if (!root) {
		pr_err("container-ima: %s: NULL dentry in directory", pwd);
		/*kfree(pathbuf);
		kfree(abspath);*/
		return -1;
	}

	/*
    inode = d_real_inode(root);
	if (!inode) {
		pr_err("container-ima: %s: failed to find inode", pwd);
		kfree(pathbuf);
		kfree(abspath);
		return -1;
	}
	*/

	/*
    res = dentry_path_raw(root, pathbuf, PATH_MAX);
	if (IS_ERR(res) || !res) {
		kfree(pathbuf);
		kfree(abspath);
		pr_err("container-ima: dentry_path_raw failed to retrieve path");
		return -1;
	}
	*/

	/* remove trailing slash from pwd */
	/*
	if (pwd[strlen(pwd)-1] == '/')
		pwd[strlen(pwd)-1] = '\0';
		*/

	/* merge pwd and res into abspath */
	/*
	length = (strlen(pwd)+strlen(res))+2;
	check = snprintf(abspath, length, "%s%s", pwd, res);
	if (check < 1) {
		pr_err("container-ima: sprintf failed");
		kfree(pathbuf);
		kfree(abspath);
		return -1;
	}*/

	if (d_is_dir(root)) {
		pr_err("container-ima: measuring dir %s", root->d_name.name);
	    list_for_each_entry(cur, &root->d_subdirs, d_child) {
			ima_measure_image_fs(cur, abspath, root_hash, pfilecounter);
		}
	} else if (d_is_reg(root)) {
		pr_err("container-ima: measuring file %s", root->d_name.name);
		(*pfilecounter)++;
/*		file = filp_open(abspath, O_RDONLY, 0);
		if (!(IS_ERR(file))) {
            root_hash = kprobe_measure_file(file, root_hash);
			filp_close(file, 0);
        }
		*/
	}

	/*kfree(pathbuf);
    kfree(abspath);*/
	return 0;


}

noinline int bpf_image_measure(void *mem, int mem__sz)
{
        int check, length, hash_algo;
        struct task_struct *task;
        struct fs_struct *fs;
        unsigned long args;
        struct ima_max_digest_data hash;
        char *aggregate;
        char ns_buf[128]; 
	struct ebpf_data *data = (struct ebpf_data *) mem;
	struct path *path = data->path;
	char *dev_name = data->dev_name;
	char *type = data->type;
	unsigned int ns = data->ns;
	long tmp;
	char *pathbuf;
	char *res;
	int filecount=0;
	
	if (ns == init_task.nsproxy->uts_ns->ns.inum) 
		return 0;

        aggregate = kmalloc(sizeof(aggregate)* 64, GFP_KERNEL);
	if (!aggregate) {
		 pr_info("container-ima: allocation failed");
		return 0;
	}

	char *name;
	char buf[256];

	name = dentry_path_raw(path->dentry, buf, 256);

	if (!dev_name)
		return 0;

	 pr_info("NS: %u, Path: %s,Mount:%s",ns,name,dev_name);


	if (!strstr(dev_name, "merged"))
		return 0;

	fs = current->fs;
	pr_info("Measuring container image: %s\n", res);
        check = ima_measure_image_fs(path->dentry->d_parent, dev_name, aggregate, &filecount);
	if (check < 0) {
		pr_err("Container IMA: image measurement failed\n");
		goto cleanup;
	}


        hash.hdr.length = hash_digest_size[4];
        hash.hdr.algo =  4;
        memset(&hash.digest, 0, sizeof(hash.digest));
        length = sizeof(hash.hdr) + hash.hdr.length;


        check = ima_calc_buffer_hash(aggregate, sizeof(aggregate), &hash.hdr);
        if (check < 0)
		goto cleanup;

        ima_store_kprobe(path->dentry, ns, 4, &hash, length, name, filecount);

cleanup:
        kfree(aggregate);

        return 0;
}

BTF_SET8_START(ima_kfunc_ids)
BTF_ID_FLAGS(func, kprobe_measure_file, KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_ID_FLAGS(func, ima_store_kprobe, KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_ID_FLAGS(func,  bpf_image_measure, KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_ID_FLAGS(func, ima_measure_image_fs, KF_TRUSTED_ARGS | KF_SLEEPABLE)
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

	dentry_abspath = (char *(*)(const struct dentry *dentry, char *buf, int buflen))
			kallsyms_lookup_name("dentry_path");
	if (dentry_abspath == 0) {
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

	return 0;
}

static void container_ima_exit(void)
{
	pr_info("Exiting Container IMA\n");
	return;
}

module_init(container_ima_init);
module_exit(container_ima_exit);


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(MODULE_NAME);
MODULE_AUTHOR("Avery Blanchard");

