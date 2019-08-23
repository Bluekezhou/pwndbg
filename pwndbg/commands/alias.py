#!/usr/bin/env python
# coding=utf-8
import gdb
import argparse
import pwndbg.commands
import re


parser = argparse.ArgumentParser(description='save breakpoint')
parser.add_argument('filepath', nargs="?", default="break", help='file to save breakpoints', type=str)
@pwndbg.commands.ArgparsedCommand(parser)
def sb(filepath):
    cmd = "save breakpoints " + filepath
    gdb.execute(cmd)
    print("save breakpoints to " + filepath)


parser = argparse.ArgumentParser(description='show kernel thread pid')
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def kpid():
    output = gdb.execute("p $lx_current()->pid", to_string=True, from_tty=False)
    m = re.match(r'\$\d+\s=\s(\d+)', output)
    if m:
        print(m.group(1))
    else:
        print("failed to find current pid, check it with command \"p $lx_current()->pid\"")
