#!/bin/env python

import os

with open('configure/CONFIG_SITE', 'a') as F:
    F.write('''
OP_SYS_CPPFLAGS += -U_FORTIFY_SOURCE
OP_SYS_CFLAGS += -std=gnu99
OP_SYS_CXXFLAGS += -std=c++11
''')
print('Updated configure/CONFIG_SITE in', os.getcwd())
