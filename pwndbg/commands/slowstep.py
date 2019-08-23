#!/usr/bin/env python
# coding=utf-8
import gdb
import argparse
import pwndbg.commands
from pwndbg.emu.emulator import Emulator
import re

flags_mask = {
    'zflag': 1 << 6,
}

def get_next_addr(pc):
    """
    get address of next instruction

    pwndbg> x/2i $pc
    => 0x555555554530:	xor    ebp,ebp
    0x555555554532:	mov    r9,rdx
    """
    inst = gdb.execute("x/2i " + hex(pc), to_string=True, from_tty=False)
    insts = inst.splitlines()
    res = re.findall(r'0x[0-9a-f]+', insts[1])
    if not res:
        print("Failed to locate next instruction at address " + hex(pc))
        raise Exception

    addr = int(res[0], 16)
    return addr

def get_inst(pc):
    """
    pwndbg> x/i $pc
    => 0x555555554530:	xor    ebp,ebp
    """
    inst = gdb.execute("x/i " + hex(pc), to_string=True, from_tty=False)
    res = inst.split(":")[1].strip()
    # print('get inst ' + res)
    return res

def get_addr(inst):
    """
    Parse address from inst, like jump address or memory address
    Args:
        inst - a string from get_inst(addr)
    """
    res = re.findall(r'0x[0-9a-f]+', inst)
    if not res:
        print("Failed to find address - " + inst)
        raise Exception

    addr = int(res[0], 16)
    return addr

def get_numbers(inst):
    """
    Parse address from inst, like jump address or memory address
    Args:
        inst - a string from get_inst(addr)
    """
    res = re.findall(r'0x[0-9a-f]+', inst)
    if not res:
        print("No number is found")
        return 
    
    nums = []
    for num_str in res:
        nums.append(int(num_str, 16))

    return nums

def parse_inst(line):
    """
    split a disassembly line into two parts: address and instrution
    """
    parts = line.split(":")
    if len(parts) != 2:
        return None, None

    address = get_addr(parts[0])
    if not address:
        return None, None

    inst = parts[1].strip()
    return address, inst
    
def run_to_addr(addrs):
    """
    Since the kernel will trap into a read_hpet interrupt, it's hard to to debug the 
    kernel with gdb step command.  Luckily, breakpoint is always effective, so I first 
    disable current breakpoints that it will not stop when program resumes. Then I set 
    a breakpoint and resume program, now it should stop at the breakpoint we just set. 
    The left work is clean the temporary breakpoint and enable original breakpoints.

    NOTE: But there is a bug, that is when you debug a function that is run on multit
    -thread, the thread or function context you are debugging may change. So DON'T go
    too far or you will lose yourself.
    """
    gdb.execute("disable")
    breakpoint_ids = []
    for addr in addrs:
        res = gdb.execute("break * " + hex(addr), to_string=True, from_tty=False)
        breakpoint_ids.append(int(res.split(" ")[1]))
        print("break at " + hex(addr))

    #    input("continue?")
    gdb.execute("continue")
    for num in breakpoint_ids:
        gdb.execute("delete " + str(num))

    gdb.execute("enable")

def get_operation(inst):
    """
    get instruction operation
    """
    res = re.findall(r"^[a-z]+", inst)
    if res:
        return res[0]

    return 

def get_jmp_target(pc, inst):
    """
    get next instruction address, if not support, return two addresses:
        next instruction address and jmp address 
    """
    target = []

    """
    pwndbg> info registers $eflags
    eflags         0x2	[ ]
    """
    output = gdb.execute("info registers $eflags", to_string=True, from_tty=False)
    nums = get_numbers(output)
    if not nums:
        print("failed to read $eflags, check it with 'info registers $eflags'")
        raise Exception

    eflags = nums[0]

    operation = get_operation(inst)
    if operation in ["jne", "jnz"]:
        if eflags & flags_mask['zflag']:
            target.append(get_next_addr(pc))
        else:
            """ alters EIP if the Z flag is not set """
            target.append(get_addr(inst))

    elif operation in ["je", "jz"]:
        if eflags & flags_mask['zflag']:
            """ alters EIP if the Z flag is set """
            target.append(get_addr(inst))
        else:
            target.append(get_next_addr(pc))
        
    elif inst.startswith('j'): # jump instruction
        next_addr = get_next_addr(pc)
        jmp_addr = get_addr(inst)
        target = [next_addr, jmp_addr]

    return target


parser = argparse.ArgumentParser(description='specific step command for android kernel')
parser.add_argument('count', type=int, nargs="?", default=1, help='step next [count] instruction')
@pwndbg.commands.ArgparsedCommand(parser, aliases=["sa"])
@pwndbg.commands.OnlyWhenRunning
def stepa(count):
    if (count < 0):
        count = 1
    
    emu = Emulator()
    pc = pwndbg.regs.pc

    # don't know why I have to call single_step once
    emu.single_step(pc)
    breakpoints = []

    for _ in range(count):
        last_pc = pc
        pc, _ = emu.single_step(pc)
        if not pc:
            pc = get_next_addr(last_pc)

        inst = get_inst(last_pc)
        
        if inst.startswith("j"):
            breakpoints = get_jmp_target(last_pc, inst)
            break

    if not breakpoints:
        breakpoints.append(pc)

    run_to_addr(breakpoints)

parser = argparse.ArgumentParser(description='specific next command for android kernel')
parser.add_argument('count', type=int, nargs="?", default=1, help='stepover next [count] instruction')
@pwndbg.commands.ArgparsedCommand(parser, aliases=["na"])
@pwndbg.commands.OnlyWhenRunning
def nexta(count):
    if (count < 0):
        count = 1
    
    emu = Emulator()
    pc = pwndbg.regs.pc

    # don't know why I have to call single_step once
    emu.single_step(pc)
    breakpoints = []

    for _ in range(count):
        last_pc = pc
        pc, inst_size = emu.single_step(pc)

        if not pc:
            pc = get_next_addr(last_pc)

        inst = get_inst(last_pc)
        if inst.startswith('call'): # call instruction
            pc = get_next_addr(last_pc)

        elif inst.startswith('j'): # jump instruction
            breakpoints = get_jmp_target(last_pc, inst)
            break
    
    if not breakpoints:
        breakpoints.append(pc)

    run_to_addr(breakpoints)

parser = argparse.ArgumentParser(description='specific finish command for android kernel')
@pwndbg.commands.ArgparsedCommand(parser, aliases=["fa"])
@pwndbg.commands.OnlyWhenRunning
def finisha():
    output = gdb.execute("disassemble", to_string=True, from_tty=False)
    lines = output.splitlines()
    
    breakpoints = []
    for line in lines:
        addr, inst = parse_inst(line)
        if not addr:
            continue

        if inst.startswith("ret"):
            breakpoints.append(addr)

    if not breakpoints:
        print("Failed to locate ret instruction")
        return

    run_to_addr(breakpoints)
    gdb.execute("stepa")
