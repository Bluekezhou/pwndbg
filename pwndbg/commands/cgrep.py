#!/usr/bin/env python
# coding=utf-8
import gdb
import argparse
import pwndbg.commands


parser = argparse.ArgumentParser(description='cgrep [format] -c command')
parser.add_argument('pattern', help='pattern string', type=str)
parser.add_argument('-c', '--command', nargs=argparse.REMAINDER, type=str)
@pwndbg.commands.ArgparsedCommand(parser)
def cgrep(pattern, command):
    cmd = " ".join(command)
    output = gdb.execute(cmd, to_string=True, from_tty=False)
    for line in output.splitlines():
        if pattern in line:
            print(line)


