#!/usr/bin/env python
"""Push PRE=--pre
to the GHA environment for subsequent actions if building a pre-release.
"""

from __future__ import print_function

import os
import re

with open('setup.py', 'r') as F:
    comment, ver = re.search(r"(?m)^\s*(#)?\s*pvxs_ver\s*\+=\s*'([^']*)'.*", F.read()).groups()

if not comment:
    assert ver.find('a')!=-1, ver
    print('Is pre-release', ver)
    # https://docs.github.com/en/actions/reference/workflow-commands-for-github-actions#setting-an-environment-variable
    #echo "{name}={value}" >> $GITHUB_ENV

    if 'GITHUB_ENV' in os.environ:
        with open(os.environ['GITHUB_ENV'], 'a') as F:
            F.write('PRE=--pre\n')
    else:
        print('Would export PRE=--pre')
