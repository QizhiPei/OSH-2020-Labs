学号：PB18111793

姓名：裴启智

# lab4容器

## 挂载文件系统

* 为了挂载cgroup下的三类控制器，先挂载了cgroup下的tmpfs，后续仍然保留

## 限制capabilities

* 使用libcap库进行限制
* 由于linux版本问题，在过滤系统调用的时候没有保留`io_uring` 开头的三个系统调用和一些以`64`结尾的系统调用

## 过滤系统调用

* 程序运行开始会有子进程能力的输出

## 思考题

1.用于限制进程能够进行的系统调用的 seccomp 模块实际使用的系统调用是哪个？用于控制进程能力的 capabilities 实际使用的系统调用是哪个？尝试说明为什么本文最上面认为「该系统调用非常复杂」

* 用于控制进程能力的 capabilities 实际使用的系统调用是prctl和capset，分别对应cap_drop_bound和cap_set_proc。（也有系统调用capget，应该是用在其他与能力限制有关的函数，如cap_init,cap_set_flag和cap_to_text等)
* 用于限制进程能够进行的系统调用的 seccomp 模块实际使用的系统调用是prctl和seccomp
* 复杂性:
  * prctl复杂在：prctl系统调用的第一个参数option可以有非常多种选择，且不同的option要和后面的arg2,arg3等等参数对应
  * capset和capget复杂在：内核API可能会更改和使用这两个系统调用（导致了参数datap格式的不确定性），同时参数中夹杂了复杂的位运算，同时还涉及到结构体的使用等
  * seccomp复杂在：参数多且复杂，需要考虑根据不同的operation设置flags和args参数，遇到不同的结构（arch）可能也需要对参数进行调整

2.当你用 cgroup 限制了容器中的 CPU 与内存等资源后，容器中的所有进程都不能够超额使用资源，但是诸如 htop 等「任务管理器」类的工具仍然会显示主机上的全部 CPU 和内存（尽管无法使用）。查找资料，说明原因，尝试**提出**一种解决方案，使任务管理器一类的程序能够正确显示被限制后的可用 CPU 和内存（不要求实现）。

* 原因：有些Linux资源并没有完全被隔离，或者说没有完全被容器化，比如/proc,/sys,/dev/sd*等目录，仍然继承了主机的一些特性
* 解决方案：
  * 更改任务管理器类工具内部的实现，让其读取容器中被更改过的memory.limit_in_bytes,memory.kmem.limit_in_bytes以及cpu.shares并显示



参考：https://mp.weixin.qq.com/s?__biz=MzUxMDQxMDMyNg==&mid=2247485858&idx=1&sn=43bca8f8c7ff03b9ac075663d6705525&chksm=f902229bce75ab8df706fad9a2e919923a8056ec21940bcb2f580dea972ccfb63ad50b0fa21e&token=911969130&lang=zh_CN#rd

[
](https://osh-2020.github.io/lab-3/)