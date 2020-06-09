#!/usr/bin/env python

from __future__ import print_function

import os
import subprocess as SP

def findexe(name):
    for dir in os.environ['PATH'].split(os.pathsep):
        for ext in ('', '.exe'):
            candidate = os.path.join(dir, name+ext)
            if os.path.isfile(candidate):
                print('Found', name, candidate)
                return candidate
    raise RuntimeError("Can't find "+name)

def logcall(fn):
    def logit(*args, **kws):
        print('CALL', fn, args, kws)
        return fn(*args, **kws)
    return logit

check_call = logcall(SP.check_call)
check_output = logcall(SP.check_output)

make = findexe('make')

check_call('perl --version', shell=True)
check_call('cmake --version', shell=True)
check_call('cmake --help', shell=True)

#if check_call('cmake --build', shell=True).find('parallel')!=-1:
#    print('Enable parallel cmake')
#    with open('configure/CONFIG_SITE.local', 'a') as F:
#        F.write('\nCBUILDFLAGS += -j 2\n')

if 'LIBEVENT_TAG' in os.environ:
    tag = remote = os.environ['LIBEVENT_TAG']
    if tag.startswith('origin/'):
        remote = tag[7:]

    check_call('git fetch origin '+remote,
               shell=True, cwd='bundle/libevent')
    check_call('git reset --hard '+tag,
               shell=True, cwd='bundle/libevent')

check_call('make -C bundle libevent', shell=True)

if os.environ.get('WINE')=='64':
    print('Enable mingw64')
    with open('configure/CONFIG_SITE.local', 'a') as F:
        F.write('\nCROSS_COMPILER_TARGET_ARCHS+=windows-x64-mingw\n')

    check_call('make -C bundle libevent.windows-x64-mingw', shell=True)
