# 关于initrd和init程序

## 过程

* 编写init.c，为程序2和3配置环境，并利用fork+execv+wait实现三个测试程序的依次调用，并利用while循环和sleep函数让程序用不停止
* 对init以及给出的三个测试程序进行打包
* 利用qemu进行测试

## 遇到的问题及解决方法

* 刚开始不了解打包指令中参数的意义，以为..是省略的部分，需要自己添加。后来通过询问助教了解到..是上层目录的意思，打包指令是把本层目录打包并保存在上层

* 不了解.cpio.gz文件运行的机制，以为会顺序执行里面的可执行文件。后来了解到该文件只会默认执行init文件

* 在配置设备文件时没有放入指定的路径，后通过更改保存的路径解决问题

* 发现出现了Kernel Panic问题，报错原因是进程被杀死。刚开始以为是kernel设置的问题，尝试后无果。询问助教后发现是进程本身的问题，所有进程如果正常运行完都会这样报错。最终利用while循环和sleep函数解决问题

* 在了解了怎么调用外部可执行文件后发现system（）函数更为方便，但在实际运用时发现缺少sh文件，后来了解到system（）函数相当于在shell中运行指令，而如果想要使用该函数需要使用BusyBox

* 在使用execv函数时没有详细地了解，直接多次使用execv调用程序123，发现和预想的结果不同。后来了解到execv是对进程的替换，用子进程代替父进程，故需要相应的逻辑实现需要的功能，代码如下

  ```c
  #include <stdio.h>
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #include <unistd.h>
  #include <sys/sysmacros.h>
  #include<stdlib.h>
  #include <sys/wait.h>
  
  int main() {
      if (mknod("./dev/ttyS0", S_IFCHR | S_IRUSR | S_IWUSR, makedev(4, 64)) == -1) {
          perror("mknod() failed");
      }
  
      if (mknod("./dev/fb0", S_IFCHR | S_IRUSR | S_IWUSR, makedev(29, 0)) == -1) {
          perror("mknod() failed");
      }
      int pid , pid1 , pid2;
      pid = fork();
  
      if(pid==0){
           execv("/1" , NULL);
      }
      else
      {
           wait(NULL);
           pid1=fork();
           if(pid1 == 0){
               execv("/2",NULL);
               }
           else
           {
               wait(NULL);
               pid2 = fork();
               if(pid2 == 0){
                   execv("/3",NULL);
               }
               else
               {
                     while (1)
                     {
                         sleep(10);
                     }
                     
               }
           }
      }
      return 0;
  }
  ```

  

## 感悟及建议

* 了解到了.cpio.gz运行的机制
* 检查错误主要根据报错的信息，要从多维度考虑，Kernel Panic、杀死进程不一定就是Kernel本身的问题，还可能是进程的问题
* 建议有些地方可以给出稍为详细的说明，如.cpio.gz运行的机制