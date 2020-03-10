#include <linux/kconfig.h>
#include "include/asm_goto_workaround.h"
#include <linux/bpf.h>

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#include "include/bpf_helpers.h"

struct data_t {
    int mode;
    u32 pid;
    u32 uid;
    u32 sz;
    u64 inode;
    u64 device; 
    char comm[TASK_COMM_LEN];
};

#define PIN_GLOBAL_NS 2

struct bpf_map_def SEC("maps/events") events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 4096,
	.map_flags = 0,
	.pinning = PIN_GLOBAL_NS,
	.namespace = "test",
};

struct bpf_map_def SEC("maps/rules") rules = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(u64),
	.max_entries = 4096,
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
        
        u64 inode_num;
        bpf_probe_read(&inode_num, sizeof(inode_num), &file.f_inode->i_ino);
        if (inode_num == 0) {
            return 0;
        }
        
        u64 *rule_exists = bpf_map_lookup_elem(&rules, &inode_num);
        if (rule_exists == 0) {
            return 0;
        }

        u64 id = bpf_get_current_pid_tgid();
        data.mode = 1; //constant defining write, will clean up later
        data.pid = id >> 32;
        data.uid = bpf_get_current_uid_gid();
        data.inode = inode_num;

        u32 cpu = bpf_get_smp_processor_id();
        bpf_perf_event_output(ctx, &events, cpu, &data, sizeof(data));
    }
    return 0;
}

SEC("kprobe/vfs_rename")
int trace_vfs_rename(struct pt_regs *ctx) {
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
                    bpf_probe_read(&_val, sizeof(_val), (u64)&PT_REGS_PARM4(ctx));
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
        data.mode = 2; //constant defining rename, will clean up later
        data.pid = id >> 32;
        data.uid = bpf_get_current_uid_gid();
        data.inode = oldInode;

        u32 cpu = bpf_get_smp_processor_id();
        bpf_perf_event_output(ctx, &events, cpu, &data, sizeof(data));
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;

