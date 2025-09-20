#!/bin/env python

import os

with open('configure/CONFIG_SITE', 'a') as F:
    F.write('''
OP_SYS_CPPFLAGS += -U_FORTIFY_SOURCE
''')
print('Updated configure/CONFIG_SITE in', os.getcwd())
