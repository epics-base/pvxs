# Preparation

1. Generate ABI change report from previous release tag to latest commit.
   Ensure `PVXS_MINOR_VERSION` incrementes if not 100% (or if other ABI change
   is known)

```sh
./abi-diff.sh A.A.A HEAD
```

# Release Process

1. Check version number in `configure/CONFIG_PVXS_VERSION`
2. Remove pre-release suffix in `setup.py`
3. Finalize section in `documentation/releasenotes.rst`
4. Search/replace `UNRELEASED` tags in doxygen comments

```sh
git grep -l UNRELEASED */pvxs/*.h documentation/*.rst | xargs sed -i -e 's|UNRELEASED|B.B.B|g'
```

Don't change in `details.rst` and `releasenotes.rst`

5. Create Git tag.

```sh
git tag -s -m B.B.B B.B.B
```

6. Generate ABI change report for upload

```sh
./abi-diff.sh A.A.A B.B.B
```

7. Generate test coverage report for upload

```sh
./coverage.sh B.B.B
```

8. Generate documentation and update `gh-pages` branch.

```sh
make
make -C documentation clean
make -C documentation commit
```

9. Push branches/tag (point of no return...)

```sh
git push origin B.B.B master +gh-pages
```

10. Verify GHA builds and pypi uploads

```sh
virtualenv /tmp/p4p-bin
/tmp/p4p-bin/bin/pip install pvxslibs
cd /tmp && /tmp/p4p-bin/bin/python -m nose2 -v pvxslibs nose2

virtualenv /tmp/p4p-src
/tmp/p4p-src/bin/pip install --no-binary epicscorelibs,pvxslibs pvxslibs nose2
cd /tmp && /tmp/p4p-src/bin/python -m nose2 -v pvxslibs
```


11. Create github.com release B.B.B

Summarize changes and attach coverage and ABI difference reports.

12. Announce on tech-talk

Reply to previous announcement mail.

## Post Release

1. Update `configure/CONFIG_PVXS_VERSION`
   Increment `PVXS_MAINTENANCE_VERSION` and add new `PVXS_#_#_#`
2. Add pre-release suffix in `setup.py`
3. New section in `documentation/releasenotes.rst`
