PYTHON?=python3

# documentation generation requires Doxygen and Sphinx with the breathe extension
#
# apt-get install doxygen python3-sphinx python3-breathe

all: gen

clean:
	rm -rf xml pvxs.tag
	rm -rf html _build

# conf.py reads CONFIG_PVXS_VERSION to extract version number
gen: ../cfg/CONFIG_PVXS_VERSION
	doxygen
	$(PYTHON) -m sphinx -j auto -b html . html

commit: gen
	./commit-gh.sh documentation/html/ html/.nojekyll html/*.* html/_*/*.*

.PHONY: all clean gen commit
