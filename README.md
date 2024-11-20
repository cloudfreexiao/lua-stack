# lua-stack

#### 介绍
来源于: https://gitee.com/lindx-code/lua-stack

这是一个基于`eBPF`实现的性能分析工具，我主要参考了[lua-perf](https://github.com/findstr/lua-perf) 以及 [unread](https://github.com/etherealvisage/unread) 来实现

能查看 c 与 lua 代码混合堆栈，并导出火焰图，目前支持 lua5.3，lua5.4，以及 skynet，可以用来分析lua死循环，以及输出火焰图，进行性能分析。 

为了能保证保证该工具能正常运行，最好采用最新的内核6.0版本以上，因为我也是在这个版本以上开发的，低版本，我没试过会不会有其他问题，主要是因为 `libbpf` 对内核要求比较高。
为了更好的学习使用这个工具，可以先看下我写过的一篇博客，大概介绍了如何通过 elf 文件的 .eh_frame 段来获取堆栈信息：[c语言 栈回溯](https://www.cnblogs.com/lindx/p/18240798)

#### 安装
1.  可以参考bcc的安装依赖，bcc也是使用到了 ebpf 技术。安装路径：[Installing BCC](https://github.com/iovisor/bcc/blob/master/INSTALL.md)
2.  `git submodule update --init --recursive`
3.  安装 `sudo apt-get install libcapstone-dev`
4.  进入 src 目录，make（注意，lua5.3，lua5.4，skynet 有不同的编译方式， **make LUA=-DLUA53|make LUA=-DLUA54|make LUA=-DLUASKY**）

#### 使用说明
1.  运行 sudo ./stack pid，在 ctrl+c 时会在当前目录生成 perf.stack 文件
2.  下载火焰图导出工具 https://github.com/brendangregg/FlameGraph.git
3.  执行 `./FlameGraph/stackcollapse-perf.pl perf.stack > perf.txt`
4.  执行 `./FlameGraph/flamegraph.pl perf.txt > perf.svg`
5.  通过浏览器查看 perf.svg 火焰图

火焰图：
![perf](./svg/skynet.svg)