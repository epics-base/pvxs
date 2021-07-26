
import os
import ctypes
import unittest

class TestLoad(unittest.TestCase):
    def test_load(self):
        from setuptools_dso.runtime import find_dso
        from ..path import include_path
        self.assertTrue(os.path.isdir(include_path))

        lib = ctypes.CDLL(find_dso('...lib.pvxs'), ctypes.RTLD_GLOBAL)
        pvxs_version_int = lib.pvxs_version_int
        pvxs_version_int.argtypes = []
        pvxs_version_int.restype = ctypes.c_ulong

        self.assertNotEqual(0, pvxs_version_int())

class TestVersion(unittest.TestCase):
    def test_ver(self):
        from ..version import version_info, abi_requires
        self.assertGreater(version_info, (0,0,0))
        self.assertLess(version_info, (99,0,0))

        self.assertNotEqual('', abi_requires())
