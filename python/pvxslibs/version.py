"""Version information for the pvxslibs package.

Version numbers are encoded as: MAJOR.MINOR.MAINT

"""
import re
from collections import namedtuple
from pkg_resources import get_distribution, parse_version

__all__ = (
    'version',
    'version_info',
    'abi_requires',
)

version = get_distribution('pvxslibs').version # as a string

version_info  = (int(x) for x in re.match(r'([\d]+)\.([\d]+)\.([\d]+)', version).groups())

version_info = namedtuple('Version', ['major', 'minor', 'maintainance'])(*version_info)

def abi_requires():
    """Return a version requirement string which identifies
    a range of version which will be ABI compatible with this one.
    For use by modules with non-python dependencies on our libraries.

    eg. "pvxslibs >=1.0.4, <1.1.0"
    """
    nextminor = version_info.minor+1

    return 'pvxslibs >={0.major}.{0.minor}.{0.maintainance}, <{0.major}.{1}.0a1'.format(version_info, nextminor)
