#!/usr/bin/env python
# coding=utf-8
import gdb
import argparse
import pwndbg.commands


parser = argparse.ArgumentParser(description='save breakpoint')
parser.add_argument('filepath', nargs="?", default="break", help='file to save breakpoints', type=str)
@pwndbg.commands.ArgparsedCommand(parser)
def sb(filepath):
    cmd = "save breakpoints " + filepath
    gdb.execute(cmd)
    print("save breakpoints to " + filepath)

