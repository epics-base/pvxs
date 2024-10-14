#!/bin/env python

with open('configure/CONFIG_SITE', 'wa') as F:
    F.write('''
OP_SYS_CPPFLAGS += -U_FORTIFY_SOURCE
''')
