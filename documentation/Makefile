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
	@if ! command -v doxygen >/dev/null 2>&1; then \
		echo "Error: doxygen is required but not found."; \
		echo "Install with: sudo apt-get install doxygen"; \
		echo "Or: sudo yum install doxygen"; \
		exit 1; \
	fi
	doxygen
	$(PYTHON) -m sphinx -j auto -b html . html
	cp pvalink-schema-0.json qsrv2-schema-0.json html/

gen: _image/nt_table1.svg
gen: _image/nt_table2.svg
gen: _image/nt_table3.svg
gen: _image/nt_table4.svg

commit: gen
	./commit-gh.sh documentation/html/ html/.nojekyll html/*.* html/_*/*.*

_image/%.svg: images/%.svg
	install -d _image
	@if command -v $(INKSCAPE) >/dev/null 2>&1; then \
		$(INKSCAPE) -l -o $@ $<; \
	else \
		echo "Warning: $(INKSCAPE) not found, copying SVG directly"; \
		cp $< $@; \
	fi

.PHONY: all clean fetch gen commit
