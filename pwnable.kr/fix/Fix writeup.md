# Fix writeup

## 0x01 引言

题目看着很简单，但做起来就没那么容易。考量的是对指令集和操作符的熟悉程度，最后也是参考了别人的答案才做出来的。

## 0x02 分析

题目给了源码，先分析源码。

```c
#include <stdio.h>

// 23byte shellcode from http://shell-storm.org/shellcode/files/shellcode-827.php
char sc[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
        "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

void shellcode(){
    // a buffer we are about to exploit!
    char buf[20];

    // prepare shellcode on executable stack!
    strcpy(buf, sc);

    // overwrite return address!
    *(int*)(buf+32) = buf;

    printf("get shell\n");
}

int main(){
        printf("What the hell is wrong with my shellcode??????\n");
        printf("I just copied and pasted it from shell-storm.org :(\n");
        printf("Can you fix it for me?\n");

    unsigned int index=0;
    printf("Tell me the byte index to be fixed : ");
    scanf("%d", &index);
    fflush(stdin);

    if(index > 22)  return 0;

    int fix=0;
    printf("Tell me the value to be patched : ");
    scanf("%d", &fix);

    // patching my shellcode
    sc[index] = fix;    

    // this should work..
    shellcode();
    return 0;
}
```

代码所用的shellcode对应的汇编代码为：

```asm
0:   31 c0                   xor    eax,eax
2:   50                      push   eax
3:   68 2f 2f 73 68          push   0x68732f2f
8:   68 2f 62 69 6e          push   0x6e69622f
d:   89 e3                   mov    ebx,esp
f:   50                      push   eax
10:  53                      push   ebx
11:  89 e1                   mov    ecx,esp
13:  b0 0b                   mov    al,0xb
15:  cd 80                   int    0x80
```

代码中很明确的表明了这道题目的目的，修改`shellcode`使其可用，先看看不修改时会报什么错误，运行后维持原shellcode，发现报`illegal hardware instruction (core dumped)`错误，但`shellcode`本身没什么问题，于是用gdb跟了下，发现在执行到`push eax`时`shellcode`会发生变化。这个看起来很奇怪，分析下栈空间的布局后才明白：`buf->ebp(shellcode)-28，shellcode大小占23字节，shellcode函数返回后esp->ebp(shellcode+4)`,则shellcode在栈中距当前esp的距离为`ebp(shellcode+4)+ebp(shellcode)+(28-23)=13bytes`，也就是说后面push的时候只能push入栈3次，多了的化就会覆盖原始shellcode，因此就会出错。最开始考虑将`push eax; push ebx`两条指令合并为一条指令，这样就可以不会覆盖原始shellcode了。

查找x86指令的操作码，分别得到以下几种修改方法：

1. `push eax; push ebx` -> `aad 0x53` (`aad opcode 0xd5`)
2. `push eax; push ebx` -> `aam 0x53` (`aam opcode 0xd4`)
3. `push eax; push ebx` -> `add al 0x53` (`opcode 0x04`)

但在测试时都出了问题，会报`No such file or directory`错误，发现这样修改会额外增加`/bin/sh`的参数，造成ecx指向的第二个字符串非0，想了半天还没有得到好的办法。后来参考其他解题方案时找到了两种不同的方案：

1. `push eax`-> `leave`（`opcode 0xc4`）

但同样会出现第一种方法的问题，发现其提供了一种比较好的方法来规避这个问题：***根据错误提示来新建一个和错误提示一样的文件，并在文件里执行sh，这样再次执行程序时就会执行这个文件了***。这种方法成立的前提是每次栈上的数据是不会发生变化的。

另外还有一种比较好的方法：

1. `push eax` -> `pop esp` （`opcode 0x5c`）

个人觉得这种方法比较好，先把`0x6e69622f`出到`esp`上，这样后面在执行`mov ecx, esp`时就会把`ecx`赋值为`0x6e69622f`。然而在测试时发现还是有问题，需要执行`ulimit -s unlimited`命令来栈的限制后才能生效。