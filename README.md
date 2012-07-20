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

## Known bugs

### Varnish/proxy_html

PyCURL has some weird interaction with HTTPS and Varnish/proxy_html module that
causes some HTTP 400 responses. Response is OK for the first request to the
cache, the second one returns HTTP 400. Here are sample URLs that show the
behavior:

`https://wiki.vorratsdatenspeicherung.de/`  
`https://www.vorratsdatenspeicherung.de/`

If you fetch the two URLs above in any order, the first URL fetched will return
HTTP 200, the second will return HTTP 400.

For some obscure reason, setting "c.setopt(c.SSL_VERIFYPEER, 0)" makes it work
correctly (c is a pycurl.Curl() object). However, that turns of certchain
validation and is thus not of much use. In both cases the HTTP headers seem
identical, SNI is sent in both cases, ciphersuite is identical...beats me.

Maybe curl being compiled with NSS has something to do with it?

### At most 9 capture groups in rule supported

This is a workaround for ambiguous rewrites in rules such as:

    <rule from="^http://(www\.)?01\.org/" to="https://$101.org/" />

The $101 would actually mean 101-st group, so we assume that only first digit
after $ denotes the group (which is how it seems to work in javascript).
