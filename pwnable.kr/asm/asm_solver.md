# ASM
> Mommy! I think I know how to make shellcodes 
> ssh asm@pwnable.kr -p2222 (pw: guest)

## 题目解读
从题目中看应该是要构造shellcode。

### 文件分析
先用scp命令下载下来两个对应的文件：*asm.c*和*asm*。命令为：（`scp -P 2222 asm@pwnable.kr:/home/asm/xxx ./`）

	#include <stdio.h>
	#include <string.h>
	#include <stdlib.h>
	#include <sys/mman.h>
	#include <seccomp.h>
	#include <sys/prctl.h>
	#include <fcntl.h>
	#include <unistd.h>

	#define LENGTH 128

	void sandbox(){
		scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
		if (ctx == NULL) {
			printf("seccomp error\n");
			exit(0);
		}

		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
		seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

		if (seccomp_load(ctx) < 0){
			seccomp_release(ctx);
			printf("seccomp error\n");
			exit(0);
		}
		seccomp_release(ctx);
	}

	char stub[] = "\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff";
	unsigned char filter[256];
	int main(int argc, char* argv[]){

	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stdin, 0, _IOLBF, 0);

	printf("Welcome to shellcoding practice challenge.\n");
	printf("In this challenge, you can run your x64 shellcode under SECCOMP sandbox.\n");
	printf("Try to make shellcode that spits flag using open()/read()/write() systemcalls only.\n");
	printf("If this does not challenge you. you should play 'asg' challenge :)\n");

	char* sh = (char*)mmap(0x41414000, 0x1000, 7, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, 0);//分配内存
	memset(sh, 0x90, 0x1000);//重置内存为0x90
	memcpy(sh, stub, strlen(stub));//拷贝stub到sh
	
	int offset = sizeof(stub);
	printf("give me your x64 shellcode: ");
	read(0, sh+offset, 1000);

	alarm(10);
	chroot("/home/asm_pwn");	// you are in chroot jail. so you can't use symlink in /tmp
	sandbox();
	((void (*)(void))sh)();
	return 0;
	}

分析下源代码，里面有一些提示信息：**在沙箱中运行自己的shellcode，使用open、read、write这三个系统调用来读取flag。**，此外main函数中定义了起始地址为0x41414000,大小为0x1000的char*变量sh，然后调用memset将其中的数据置为0x90，接下来拷贝stub中的字节到sh的开始位置。最后就是准备输入自己的shellcode，并在sandbox中执行。

- 首先看一下变量stub是什么？它的值为：`\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff`,是一串字节码，翻译成对应的汇编语言为：
	
		xor     rax, rax
		xor     rbx, rbx
		xor     rcx, rcx
		xor     rdx, rdx
		xor     rsi, rsi
		xor     rdi, rdi
		xor     rbp, rbp
		xor     r8, r8
		xor     r9, r9
		xor     r10, r10
		xor     r11, r11
		xor     r12, r12
		xor     r13, r13
		xor     r14, r14
		xor     r15, r15

为清零操作，清零上述几个寄存器的值。
- 其次在初始化sh时，调用了memset函数将其内容全部置为0x90，而0x90对应的汇编代码为`nop`，是空指令。
- 重要的一步是构造自己的shellcode来从flag文件中读取flag，并且只能用open、read、write系统调用，在查看flag文件时，发现它的文件名很长`this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong`如上面显示。

## 参考答案
使用pwntools的shellcraft模块来进行编写shellcode，主要用到的函数有：`ssh`、`open`、`read`、`write`、`recv`等，具体实施细节参考asm_solver.py。


##参考引用
1. shellcode教程1 http://www.kernel-panic.it/security/shellcode/index.html
2. shellcode教程2 https://wiremask.eu/articles/shellcode-file-reader-linux-x86/
3. PwnTools文档 http://docs.pwntools.com/en/stable/intro.html