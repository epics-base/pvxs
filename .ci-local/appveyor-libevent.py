#!/usr/bin/env python

from __future__ import print_function

import sys
import os
from glob import glob
import subprocess as SP

def check_call(cmd, shell=True, env=None):
    print('CALLING', repr(cmd))
    sys.stdout.flush()
    sys.stderr.flush()
    SP.check_call(cmd, shell=shell, env=env)
    sys.stdout.flush()
    sys.stderr.flush()
    print('CALLED', repr(cmd))

check_call('cmake --version')
check_call('cmake --help')

print('ENV')
[print("  ", frag) for frag in os.environ['PATH'].split(os.pathsep)]
print('PATH')
[print("  ", K, "=", V) for K, V in os.environ.items()]

# environment for sub-process
env=os.environ.copy()
CC = env.pop('CMP') # both ci-scripts and cmake use this, with different sets of values...
make = env.pop('MAKE', 'make')

if CC=='mingw':
    print('mingw versions')
    for loc in glob(r'C:\mingw-w64\*\*\bin\gcc.exe'):
        print('  ', loc)
    check_call('gcc --version')

# CMake MinGW generator doesn't like sh.exe in PATH
# NMake generator doesn't care
# strip it out
env['PATH'] = os.pathsep.join([ent for ent in env['PATH'].split(os.pathsep) if not os.path.isfile(os.path.join(ent, 'sh.exe'))])

check_call("{} -C bundle libevent".format(make),
           env=env)
