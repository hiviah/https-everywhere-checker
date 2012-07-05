# HTTPS Everywhere Rule Checker

## Installation and requirements

You'll need following packages commonly present in distros:

* lxml
* PyCURL

Also some modules in the 3rd_party/ directory need to be installed, e.g.:

    (cd 3rd_party/cx_bsdiff-1.1/ && python setup.py install --user)
    (cd 3rd_party/python-Levenshtein-0.10.1/ && python setup.py install --user)
    (cd 3rd_party/regex-0.1.20120613/ && python setup.py install --user)

The `regex` module replace python-builtin `re` module because the latter
doesn't work with some substitutions (e.g. if optional capture group like
`(www\.)?` does match empty string).

## Configuration

Copy `checker.config.sample` to `checker.config` and change the `rulesdir`
under `[rulesets]` to point to a directory with the XML files of HTTPS
Everywhere rules (usually the `src/chrome/content/rules` of locally checked out
git tree of HTTPS Everywhere).
