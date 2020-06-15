#include <linux/kconfig.h>
#include "include/asm_goto_workaround.h"
#include <linux/bpf.h>

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/types.h>
#include <linux/kdev_t.h>

#include "include/bpf_helpers.h"

struct data_t {
    int mode;
    u32 pid;
    u32 uid;
    u32 sz;
    u64 inode;
    u64 device;
    u64 new_inode; // destination dir inode while renaming
    u64 new_device; // destination file inode while renaming
    char comm[TASK_COMM_LEN];
    char name[32];
};


struct inode_sm {
	umode_t			i_mode;
	unsigned short		i_opflags;
	kuid_t			i_uid;
	kgid_t			i_gid;
	unsigned int		i_flags;

#ifdef CONFIG_FS_POSIX_ACL
	struct posix_acl	*i_acl;
	struct posix_acl	*i_default_acl;
#endif

	const struct inode_operations	*i_op;
	struct super_block	*i_sb;
	struct address_space	*i_mapping;

#ifdef CONFIG_SECURITY
	void			*i_security;
#endif

	/* Stat data, not accessed from path walking */
	unsigned long		i_ino;
};

struct dentry_sm {
	unsigned int d_flags;		/* protected by d_lock */
	seqcount_t d_seq;		/* per dentry seqlock */
	struct hlist_bl_node d_hash;	/* lookup hash list */
	struct dentry *d_parent;	/* parent directory */
	struct qstr d_name;
	struct inode *d_inode;
};
#define PIN_GLOBAL_NS 2

struct bpf_map_def SEC("maps/events") events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 200000,
	.map_flags = 0,
	.pinning = PIN_GLOBAL_NS,
	.namespace = "bpfink",
};

struct bpf_map_def SEC("maps/rules") rules = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(u64),
	.max_entries = 200000,
	.map_flags = 0,
	.pinning = PIN_GLOBAL_NS,
	.namespace = "bpfink",
};

SEC("kprobe/vfs_write")
int trace_write_entry(struct pt_regs *ctx){
    struct data_t data = {};
    if (bpf_get_current_comm(&data.comm, sizeof(data.comm)) == 0) {
        struct file file;
        bpf_probe_read(&file, sizeof(file), (void *)PT_REGS_PARM1(ctx));
        if (!(file.f_op))
            return 0;

        struct inode_sm inode;

        bpf_probe_read(&inode, sizeof(inode), file.f_inode);

        // don't care about writes to non-ordinary files: sockets/devices/FIFOs
        if (inode.i_ino == 0 || S_ISSOCK(inode.i_mode) || S_ISCHR(inode.i_mode) || S_ISBLK(inode.i_mode) || S_ISFIFO(inode.i_mode)) {
            return 0;
        }

        u64 *rule_exists = bpf_map_lookup_elem(&rules, &inode.i_ino);
        if (rule_exists == 0) {
            return 0;
        }

        // file is uniquely identified by the (inode, dev) pair
        // so far we catch a write event for the file with matched inode
        // we need to verify dev id is also matched to be sure we catch the event for the right file
        dev_t kdevice = 0;
        bpf_probe_read(&kdevice, sizeof(kdevice), (u64)&inode.i_sb->s_dev);
        
        // transform device_id from the kernel-space format to the user-space format
        u64 actualDeviceID = (u64)new_encode_dev(kdevice); 
        u64 expectedDeviceID = *rule_exists;
        
        if (actualDeviceID != expectedDeviceID) {
            return 0;
        }

        u64 id = bpf_get_current_pid_tgid();
        data.mode = 1; //constant defining write, will clean up later
        data.pid = id >> 32;
        data.uid = bpf_get_current_uid_gid();
        data.inode = inode.i_ino;

        u32 cpu = bpf_get_smp_processor_id();
        bpf_perf_event_output(ctx, &events, cpu, &data, sizeof(data));
    }
    return 0;
}

SEC("kprobe/vfs_rename")
int trace_vfs_rename(struct pt_regs *ctx) {
    struct data_t data = {};
    typeof(struct inode_sm) old_dir;
    typeof(struct dentry *) old_dentry;
    typeof(struct inode_sm) new_dir;
    typeof(struct dentry *) new_dentry;
    if (bpf_get_current_comm(&data.comm, sizeof(data.comm)) == 0) {
        bpf_probe_read(&old_dir, sizeof(old_dir), (void *)PT_REGS_PARM1(ctx));
        bpf_probe_read(&old_dentry, sizeof(old_dentry), (u64)&PT_REGS_PARM2(ctx));
        bpf_probe_read(&new_dir, sizeof(new_dir), (void *)PT_REGS_PARM3(ctx));
        bpf_probe_read(&new_dentry, sizeof(new_dentry), (u64)&PT_REGS_PARM4(ctx));

        u64 oldInode = ({
            typeof(dev_t) _val;
            __builtin_memset(&_val, 0, sizeof(_val));
            bpf_probe_read(&_val, sizeof(_val), (u64)&({
                typeof(struct inode *) _val;
                __builtin_memset(&_val, 0, sizeof(_val));
                bpf_probe_read(&_val, sizeof(_val), (u64)&old_dentry->d_inode);
                _val;
            })->i_ino);
            _val;
        });

        typeof(struct inode *) newInodePtr;
        __builtin_memset(&newInodePtr, 0, sizeof(newInodePtr));
        bpf_probe_read(&newInodePtr, sizeof(newInodePtr), (u64)&new_dentry->d_inode);

        u64 newInode = 0;
        if (newInodePtr != NULL) {
            bpf_probe_read(&newInode, sizeof(newInode), (u64)&newInodePtr->i_ino);
        }

        // rule exists either if we are monitoring target directory or target file
        u64 *rule_exists = newInode == 0 ? bpf_map_lookup_elem(&rules, &new_dir.i_ino)
                                         : bpf_map_lookup_elem(&rules, &newInode);
        if (rule_exists == 0) {
            return 0;
        }

        // check if the destination file or directory belongs to the same device as a
        // monitored one
        dev_t kdevice = 0;
        bpf_probe_read(&kdevice, sizeof(kdevice), (u64)&new_dir.i_sb->s_dev);

        u64 actualDeviceID = (u64)new_encode_dev(kdevice);
        u64 expectedDeviceID = *rule_exists;

        if (actualDeviceID != expectedDeviceID) {
            return 0;
        }

        bpf_probe_read(&data.name, sizeof(data.name), &new_dentry->d_name.name+2);

        u64 id = bpf_get_current_pid_tgid();
        data.mode = 0; //constant defining rename, will clean up later
        data.pid = id >> 32;
        data.uid = bpf_get_current_uid_gid();
        data.inode = old_dir.i_ino;
        data.device = oldInode;
        data.new_inode = new_dir.i_ino;
        data.new_device = newInode;

        u32 cpu = bpf_get_smp_processor_id();
        bpf_perf_event_output(ctx, &events, cpu, &data, sizeof(data));
    }

    return 0;
}

SEC("kprobe/vfs_unlink") //delete file
int trace_vfs_unlink(struct pt_regs *ctx) {
    struct data_t data = {};
    if (bpf_get_current_comm(&data.comm, sizeof(data.comm)) == 0) {

        u64 oldInode = ({
            typeof(dev_t) _val;
            __builtin_memset(&_val, 0, sizeof(_val));
            bpf_probe_read(&_val, sizeof(_val), (u64)&({
                typeof(struct inode *) _val;
                __builtin_memset(&_val, 0, sizeof(_val));
                bpf_probe_read(&_val, sizeof(_val), (u64)&({
                    typeof(struct dentry *) _val;
                    __builtin_memset(&_val, 0, sizeof(_val));
                    bpf_probe_read(&_val, sizeof(_val), (u64)&PT_REGS_PARM2(ctx));
                    _val;
                })->d_inode);
                _val;
            })->i_ino);
            _val;
        });

        u64 *rule_exists = bpf_map_lookup_elem(&rules, &oldInode);
        if (rule_exists == 0) {
            return 0;
        }

        u64 id = bpf_get_current_pid_tgid();
        data.mode = -1; //constant defining unlink, will clean up later
        data.pid = id >> 32;
        data.uid = bpf_get_current_uid_gid();
        data.inode = oldInode;

        u32 cpu = bpf_get_smp_processor_id();
        bpf_perf_event_output(ctx, &events, cpu, &data, sizeof(data));

    }

    return 0;
}

SEC("kprobe/vfs_rmdir")
int trace_vfs_rmdir(struct pt_regs *ctx) {
    struct data_t data = {};
    if (bpf_get_current_comm(&data.comm, sizeof(data.comm)) == 0) {

        u64 inode_number = ({
            typeof(dev_t) _val;
            __builtin_memset(&_val, 0, sizeof(_val));
            bpf_probe_read(&_val, sizeof(_val), (u64)&({
                typeof(struct inode *) _val;
                __builtin_memset(&_val, 0, sizeof(_val));
                bpf_probe_read(&_val, sizeof(_val), (u64)&({
                    typeof(struct dentry *) _val;
                    __builtin_memset(&_val, 0, sizeof(_val));
                    bpf_probe_read(&_val, sizeof(_val), (u64)&PT_REGS_PARM2(ctx));
                    _val;
                })->d_inode);
                _val;
            })->i_ino);
            _val;
        });

        u64 *rule_exists = bpf_map_lookup_elem(&rules, &inode_number);
        if (rule_exists == 0) {
            return 0;
        }

        u64 id = bpf_get_current_pid_tgid();
        data.mode = -2; //constant defining rmdir,
        data.pid = id >> 32;
        data.uid = bpf_get_current_uid_gid();
        data.inode = inode_number;

        u32 cpu = bpf_get_smp_processor_id();
        bpf_perf_event_output(ctx, &events, cpu, &data, sizeof(data));
    }
    return 0;
}

SEC("kprobe/done_path_create") //mkdir
int trace_done_path_create(struct pt_regs *ctx) {
    struct data_t data = {};
    if (bpf_get_current_comm(&data.comm, sizeof(data.comm)) == 0) {
        u64 parent_inode_number = ({
            typeof(dev_t) _val;
            __builtin_memset(&_val, 0, sizeof(_val));
            bpf_probe_read(&_val, sizeof(_val), (u64)&({
                typeof(struct inode *) _val;
                __builtin_memset(&_val, 0, sizeof(_val));
                bpf_probe_read(&_val, sizeof(_val), (u64)&({
                    typeof(struct dentry *) _val;
                    __builtin_memset(&_val, 0, sizeof(_val));
                    bpf_probe_read(&_val, sizeof(_val), (u64)&({
                        typeof(struct path *) _val;
                        __builtin_memset(&_val, 0, sizeof(_val));
                        bpf_probe_read(&_val, sizeof(_val), (u64)&PT_REGS_PARM1(ctx));
                        _val;
                    })->dentry);
                    _val;
                })->d_inode);
                _val;
            })->i_ino);
            _val;
        });

        u64 *rule_exists = bpf_map_lookup_elem(&rules, &parent_inode_number);
        if (rule_exists == 0) {
            return 0;
        }

        u64 child_inode_number = ({
            typeof(dev_t) _val;
            __builtin_memset(&_val, 0, sizeof(_val));
            bpf_probe_read(&_val, sizeof(_val), (u64)&({
                typeof(struct inode *) _val;
                __builtin_memset(&_val, 0, sizeof(_val));
                bpf_probe_read(&_val, sizeof(_val), (u64)&({
                    typeof(struct dentry *) _val;
                    __builtin_memset(&_val, 0, sizeof(_val));
                    bpf_probe_read(&_val, sizeof(_val), (u64)&PT_REGS_PARM2(ctx));
                    _val;
                })->d_inode);
                _val;
            })->i_ino);
            _val;
        });

        u64 flag = 0;
        u64 value = 2;
        bpf_map_update_elem(&rules, (void *)&child_inode_number, (void *)&value, flag);

         struct dentry_sm *d_child;

        bpf_probe_read(&d_child, sizeof(d_child), &PT_REGS_PARM2(ctx));

        bpf_probe_read(&data.name, sizeof(data.name), &d_child->d_name.name+2);

        u64 id = bpf_get_current_pid_tgid();
        data.mode = 3; //constant defining mkdir,
        data.pid = id >> 32;
        data.uid = bpf_get_current_uid_gid();
        data.inode = parent_inode_number;
        data.device = child_inode_number;
        u32 cpu = bpf_get_smp_processor_id();

        bpf_perf_event_output(ctx, &events, cpu, &data, sizeof(data));

    }
}
SEC("kprobe/do_dentry_open") //create file
int trace_do_dentry_open(struct pt_regs *ctx) {
    struct file file;
    unsigned int flags;
    struct inode_sm inode;
    u64 inode_num;
    u64 parent_inode_number;

    struct data_t data = {};
    if (bpf_get_current_comm(&data.comm, sizeof(data.comm)) == 0) {

        bpf_probe_read(&file, sizeof(file), (void *)PT_REGS_PARM1(ctx));

        bpf_probe_read(&flags, sizeof(flags), &file.f_flags);
        if ( !(O_CREAT & flags)) { //get better at de duping this
            return 0;
        }

        parent_inode_number = ({
            typeof(dev_t) _val;
            __builtin_memset(&_val, 0, sizeof(_val));
            bpf_probe_read(&_val, sizeof(_val), (u64)&({
                typeof(struct inode *) _val;
                __builtin_memset(&_val, 0, sizeof(_val));
                bpf_probe_read(&_val, sizeof(_val), (u64)&({
                    typeof(struct dentry *) _val;
                    __builtin_memset(&_val, 0, sizeof(_val));
                    bpf_probe_read(&_val, sizeof(_val), (u64)&file.f_path.dentry->d_parent);
                    _val;
                })->d_inode);
                _val;
            })->i_ino);
            _val;
        });

        u64 *rule_exists = bpf_map_lookup_elem(&rules, &parent_inode_number);
        if (rule_exists == 0) {
            return 0;
        }

        bpf_probe_read(&inode, sizeof(inode), (void *)PT_REGS_PARM2(ctx));

        dev_t kdevice = 0;
        bpf_probe_read(&kdevice, sizeof(kdevice), (u64)&inode.i_sb->s_dev);

        u64 actualDeviceID = (u64)new_encode_dev(kdevice);
        u64 expectedDeviceID = *rule_exists;

        if (actualDeviceID != expectedDeviceID) {
            return 0;
        }

        bpf_probe_read(&data.name, sizeof(data.name),   &file.f_path.dentry->d_name.name+2);
        bpf_probe_read(&data.device, sizeof(data.device),  &file.f_path.dentry->d_name.len);



        u64 id = bpf_get_current_pid_tgid();
        data.mode = 4; //constant defining create new file,
        data.pid = id >> 32;
        data.uid = bpf_get_current_uid_gid();
        data.inode = parent_inode_number;
        data.device = inode.i_ino;
        u32 cpu = bpf_get_smp_processor_id();
        bpf_perf_event_output(ctx, &events, cpu, &data, sizeof(data));
    }
    return 0;
}



char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
