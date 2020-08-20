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

    cmd = r"""
printf "regs {\n"
printf "    PC: 0x%x\n", $env->gpr[HEX_REG_PC]
printf "}\n"
    """
    
    gdb.execute(cmd)
