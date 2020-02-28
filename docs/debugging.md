# Debugging

Since there are many tools and blogs about debugging go lang. I will only briefly touch on this topic. 
Due to the multi threaded nature of the code. Running `go run -race` will make any race condition easy to spot. 
Other than that traditional means of debugging should work fine.

## BPF debugging

When trying to squash BPF bugs, or performance issues. There is only two way to gain any insight into what BPF is doing. 

1. Debug print statements:

    `bpf_trace_printk()` This function call prints data to `/sys/kernel/debug/tracing/trace_pipe`.
    
    **Important do not leave `bpf_trace_printk` in a production build as it will cause memory to leak**
2. BPF perf tools:
    One of the best tools we have used to debug performance issue with our BPF code is perf, and flame grahps.
    I would highly recomend reading over this post to get a better understanding [Perf](http://www.brendangregg.com/perf.html)

   To collect and generate flame graphs use this [readme](https://github.com/brendangregg/FlameGraph#1-capture-stacks) as a guide
   
   TL;DR: 
   
   1. collect data  
    ```
    # system level data collection: 
    perf record -F 99 -a -g -- sleep 60
    perf script > out.perf
    ```
    or 
    ```
    # process level
    perf record -F 99 -p <PID> -g -- sleep 60
    perf script > out.perf
    ```
    or 
    ```
    # process level
    perf record -F 99 -u <UID/UserName> -g -- sleep 60
    perf script > out.perf
    ```
   2. fold the data: `./stackcollapse-perf.pl out.perf > out.folded`
   3. Generate the svg: `./flamegraph.pl out.kern_folded > kernel.svg`

   Once you have the flame graph, you will want to use the search feature to find the traced kernel function ie `vfs_write`, or you can just search for `bpf`. 

   
