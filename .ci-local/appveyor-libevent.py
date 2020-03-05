#!/usr/bin/env python

from __future__ import print_function

import os
import subprocess as SP

def check_call(cmd):
    print('CALL', repr(cmd))
    SP.check_call(cmd, shell=True)

print("In", os.getcwd())

check_call('perl --version')
check_call('cmake --version')
check_call('cmake --help')

check_call('git clone --branch patches-2.1 https://github.com/libevent/libevent.git')

os.mkdir('host-libevent')
os.chdir('host-libevent')

env={
    'prefix':os.path.join(os.getcwd(), 'usr'),
    'include':os.path.join(os.getcwd(), 'usr', 'include'),
    'lib':os.path.join(os.getcwd(), 'usr', 'lib'),
    'src':os.path.join(os.getcwd(), '..', 'libevent'),
}

SP.check_call('cmake -DEVENT__DISABLE_OPENSSL=ON -DCMAKE_INSTALL_PREFIX:DIR={prefix} {src}'.format(**env), shell=True)
SP.check_call('cmake --build . --target install', shell=True)

if 'TRAVIS_OS_NAME' in os.environ:
    env['OS_CLASS'] = {
        'linux':'Linux',
        'osx':'Darwin',
        'windows':'WIN32',
    }[os.environ['TRAVIS_OS_NAME']]

elif 'APPVEYOR' in os.environ:
    env['OS_CLASS']='WIN32'

with open(os.path.join('..', 'configure', 'CONFIG_SITE.local'), 'a') as F:
    F.write('''
USR_CPPFLAGS_{OS_CLASS}  += -I{include}
USR_LDFLAGS_{OS_CLASS}   += -L{lib}
USR_LDFLAGS_Linux         += -Wl,-rpath,{lib}
'''.format(**env))

with open(os.path.join('..', 'configure', 'CONFIG_SITE.local'), 'r') as F:
    print('====CONFIG_SITE.local')
    print(F.read())
    print('====CONFIG_SITE.local')
