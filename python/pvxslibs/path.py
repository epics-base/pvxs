import os
from setuptools_dso import dylink_prepare_dso

__all__ = (
    'include_path',
)

include_path = os.path.join(os.path.dirname(__file__), 'include')

dylink_prepare_dso("pvxslibs.lib.pvxs")
