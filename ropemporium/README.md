# ropemporium

#### 介绍
   	ropemporium是一个练习rop的[网站](https://ropemporium.com/)，它提供了一系列的挑战（8道题目），由易到难的来练习ROP技术。做这些题目之前需要掌握一些基础的知识，例如什么是ROP？以及常用的工具包括rabin2、pwntools、ropgadget、pwndbg等。这里不对这些做深入的介绍，仅提供writeup，如有疑问可以联系来进行探讨。

#### 题目

  	所有题目基本都采用栈溢出作为切入点，开启了栈不可执行保护措施，切入点的偏移都一致，重点在如何构造ROP链上。

##### ret2win

​	入门题目，自带了ret2win函数，通过溢出控制程序跳转到ret2win函数即可。  

##### split

##### callme

##### write4

##### badchars

##### fluff

##### pivot

##### ret2csu

