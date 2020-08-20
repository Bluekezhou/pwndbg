#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Commands for debugging qemu.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import gdb
import pwndbg.commands

parser = argparse.ArgumentParser(description='show qemu cpu state')
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def cpu():
    try:
        gdb.execute('print env', to_string=True)
        gdb.execute('set $env = env', to_string=True)
    except gdb.error:
        gdb.execute('set $env = (CPUArchState *)$rbp', to_string=True)

    regs = {}
    
    for i in range(32):
        value = gdb.parse_and_eval('$env->gpr[{}]'.format(i))
        reg = 'R{:0>2}'.format(i)
        regs[reg] = hex(value)
    
    special = ["PC", "SP", "LR"]
    for reg in special:
        value = gdb.parse_and_eval('$env->gpr[HEX_REG_{}]'.format(reg))
        regs[reg] = hex(value)

    print("regs {")
    for i in range(32):
        reg = 'R{:0>2}'.format(i)
        if i % 4 == 0:
            print("    {:>3}:{:>8}  ".format(reg, regs[reg]), end='')
        elif i % 4 == 3:
            print("{:>3}:{:>8}\n".format(reg, regs[reg]), end='')
        else:
            print("{:>3}:{:>8}  ".format(reg, regs[reg]), end='')

    for index, reg in enumerate(special):
        if index == 0:
            print("    {}: {:>8}  ".format(reg, regs[reg]), end='')
        elif index == len(special) - 1:
            print("{}: {:>8}  ".format(reg, regs[reg]))
        else:
            print("{}: {:>8}  ".format(reg, regs[reg]), end='')

    print("}")

