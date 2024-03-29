# 关于Linux内核

## 过程

* 在助教给定的网站上下载linux内核
* 解压文件
* 在该文件夹下运行相应的指令进行设置和内核编译
* 能在该内核中成功完成第二部分的所有任务
* 根据网上相关资料以及词典查询，了解各个设置对应的功能，对内核进行裁剪

## 遇到的问题及解决方法

* 在第一次设置完成后save时对默认名字.config进行了更改，导致后续运行出错。询问助教发现原因是更改默认名称会导致编译忽略.config。后续通过保存默认的名称解决
* 刚开始不了解内核各个部分的功能，导致裁剪过度，无法完成实验要求的所有功能。后续通过查询资料以及多次尝试，保存每次的.config文件对比差异，最终完成
* 在裁剪时发现一些general setup里的东西不能随意删减，而一些很显然的如网络、图标，以及一些support、options等选项可以适当删减

## 感悟及建议

* 第一次了解到MiB这个单位，查询资料发现其与MB表示的大小稍有不同
* 建议可以给出一些裁剪时的大致方向的建议或者参考