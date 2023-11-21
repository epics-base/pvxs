PYTHON?=python3
CURL?=curl
INKSCAPE?=inkscape

# documentation generation requires Doxygen and Sphinx with the breathe extension
#
# apt-get install doxygen python3-sphinx python3-breathe

all: gen

clean:
	rm -rf xml default pvxs.tag
	rm -rf html _build _image

# conf.py reads CONFIG_PVXS_VERSION to extract version number
gen: ../include/pvxs/version.h
	doxygen
	$(PYTHON) -m sphinx -j auto -b html . html
	cp pvalink-schema-0.json qsrv2-schema-0.json html/

gen: _image/nt_table1.svg
gen: _image/nt_table2.svg
gen: _image/nt_table3.svg
gen: _image/nt_table4.svg

commit: gen
	./commit-gh.sh documentation/html/ html/.nojekyll html/*.* html/_*/*.*

_image/%.svg: %.svg
	install -d _image
	$(INKSCAPE) -l -o $@ $<

.PHONY: all clean fetch gen commit
