# Release Process

1. Check version number in configure/CONFIG_PVXS_VERSION
2. Remove pre-release suffix in setup.py
3. Finalize section in documentation/releasenotes.rst
4. Search/replace `UNRELEASED` tags in doxygen comments

  git grep -l UNRELEASED */pvxs/*.h documentation/*.rst | xargs sed -i -e 's|UNRELEASED|0.0.0|g'

Don't change in details.rst and releasenotes.rst

## Post Release

1. Update configure/CONFIG_PVXS_VERSION
   Increment PVXS_MAINTENANCE_VERSION and add new PVXS_#_#_#
2. Add pre-release suffix in setup.py
3. New section in documentation/releasenotes.rst
