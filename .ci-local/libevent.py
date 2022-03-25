#!/usr/bin/env python

from __future__ import print_function

import sys
import os
import subprocess as SP

def inspectpath():
    for dir in os.environ['PATH'].split(os.pathsep):
        for tool in ('make', 'sh', 'gcc', 'cl'):
            for ext in ('', '.exe'):
                candidate = os.path.join(dir, tool+ext)
                if os.path.isfile(candidate):
                    print('Found', tool, candidate)
inspectpath()

def logcall(fn):
    def logit(*args, **kws):
        print('CALL', fn, args, kws)
        sys.stdout.flush()
        sys.stderr.flush()
        ret = fn(*args, **kws)
        sys.stdout.flush()
        sys.stderr.flush()
        return ret
    return logit

check_call = logcall(SP.check_call)
check_output = logcall(SP.check_output)

env=os.environ.copy()
PATH=env['PATH'].split(os.pathsep)

# CMake MinGW generator doesn't like sh.exe in PATH
# NMake generator doesn't care
# strip it out
PATH = [ent for ent in PATH if not os.path.isfile(os.path.join(ent, 'sh.exe'))]
env['PATH'] = os.pathsep.join(PATH)

print('ENV')
[print("  ", frag) for frag in env['PATH'].split(os.pathsep)]
print('PATH')
[print("  ", K, "=", V) for K, V in env.items()]

# update to specific libevent version
libevent_tag = os.environ.get('LIBEVENT_TAG', '')
if len(libevent_tag):
    if libevent_tag.startswith('origin/'):
        libevent_tag = libevent_tag[7:]

    check_call('git fetch --unshallow --tags origin',
               shell=True, cwd='bundle/libevent')
    check_call('git log -n1 '+libevent_tag+' --',
               shell=True, cwd='bundle/libevent')
    check_call('git reset --hard '+libevent_tag+' --',
               shell=True, cwd='bundle/libevent')

check_call('make -C bundle libevent', shell=True, env=env)

if os.environ.get('WINE')=='64':
    print('Enable mingw64')
    with open('configure/CONFIG_SITE.local', 'a') as F:
        F.write('\nCROSS_COMPILER_TARGET_ARCHS+=windows-x64-mingw\n')

    check_call('make -C bundle libevent.windows-x64-mingw', shell=True, env=env)

elif os.environ.get('WINE')=='32':
    print('Enable mingw32')
    with open('configure/CONFIG_SITE.local', 'a') as F:
        F.write('\nCROSS_COMPILER_TARGET_ARCHS+=win32-x86-mingw\n')

    check_call('make -C bundle libevent.win32-x86-mingw', shell=True, env=env)

elif os.environ.get('RTEMS_TARGET'):
    print('Enable RTEMS')
    with open('configure/CONFIG_SITE.local', 'a') as F:
        F.write('\nCROSS_COMPILER_TARGET_ARCHS+=%s\n'%os.environ['RTEMS_TARGET'])

    check_call('make -C bundle libevent.'+os.environ['RTEMS_TARGET'], shell=True, env=env)
