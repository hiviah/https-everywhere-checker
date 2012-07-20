# HTTPS Everywhere Rule Checker

Author: Ondrej Mikle, CZ.NIC (ondrej.mikle |at_sign| nic.cz)

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

## Running

Once you have modified the config, run:

    python check_rules.py checker.config

Output will be written to selected log file, infos/warnings/errors contain the
useful information.

## Features

 * Attempts to follow Firefox behavior as closely as possible (including
   rewriting HTTP redirects according to rules; well except for Javascript and
   meta-redirects)
 * IDN domain support
 * Currently two metrics on "distance" of two resources implemented, one is
   purely string-based, the other tries to measure "similarity of the shape
   of DOM tree"
 * Multi-threaded scanner
 * Support for various "platforms" (e.g. CAcert), i.e. sets of CA certificate
   sets which can be switched during following of redirects

## What errors in rulesets can be detected

 * big difference in HTML page structure
 * error in ruleset - declared target that no rule rewrites, bad regexps
   (usually capture groups are wrong), incomplete FQDNs, non-existent domains
 * HTTP 200 in original page, while rewritten page returns 4xx/5xx
 * cycle detection in redirects
 * transvalid certificates (incomplete chains)
 * other invalid certificate detection (self-signed, expired, CN mismatch...)
 
## False positives and shortcomings

 * Some pages deliberately have different HTTP and HTTPS page, some for example
   redirect to different page under https
 * URLs to scan are naively guessed from target hosts, having test set of URLs
   in a ruleset would improve it (better coverage)

## Known bugs

### CURL/NSS weird interaction in certificate verification

PyCURL has some weird interaction with HTTPS and Varnish/proxy_html module that
causes some HTTP 400 responses. Response is OK for the first request to the
cache, the second one returns HTTP 400. Here are sample URLs that show the
behavior:

`https://wiki.vorratsdatenspeicherung.de/`  
`https://www.vorratsdatenspeicherung.de/`

If you fetch the two URLs above in any order, the first URL fetched will return
HTTP 200, the second will return HTTP 400.

For some obscure reason, setting `c.setopt(c.SSL_VERIFYPEER, 0)` makes it work
correctly (c is a pycurl.Curl() object). However, that turns off certchain
validation and is thus not of much use. In both cases the HTTP headers seem
identical, SNI is sent in both cases, ciphersuite is identical.

I tried to build curl/libcurl with `--without-nss` and the problem goes away.
Apparently NSS does not like how CA certs are setup, but I can't find the right
way to do it. NSS takes `$SSL_DIR` containing its own database of certs (seems
that it can't be changed at runtime).

### At most 9 capture groups in rule supported

This is a workaround for ambiguous rewrites in rules such as:

    <rule from="^http://(www\.)?01\.org/" to="https://$101.org/" />

The $101 would actually mean 101-st group, so we assume that only first digit
after $ denotes the group (which is how it seems to work in javascript).

### May not work under Windows

According to [PyCURL documentation](http://curl.haxx.se/libcurl/c/curl_easy_setopt.html#CURLOPTCAPATH),
using CAPATH may not work under Windows. I'd guess it's due to openssl's
`c_rehash` utility that creates symlinks to PEM certificates. Hypothetically
it could work if the symlinks were replaced by regular files with identical
names, but haven't tried.
