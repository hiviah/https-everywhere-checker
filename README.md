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

### CURL+NSS can't handle hosts with SNI sharing same IP address

PyCURL and NSS incorrectly handle the case when two FQDNs have identical IP
address, use Server Name Indication and try to resume TLS session with the
same session ID. Even turning off SSL session cache via setting
`pycurl.SSL_SESSIONID_CACHE` to zero won't help (it's ignored by libcurl/pycurl
for some reason). PyCURL+NSS fail to see that server didn't acknowledge SNI in
response (see RFC 4366 reference below), thus 'Host' header in HTTP and SNI seen
by server are different, thus HTTP 404. 

This one issue was especially insidious bug, many thanks to Pavel Janík for
helping hunt this bug down.

#### Testcase - example hosts

Connect to first URL, close connection, then GET second URL:

`https://wiki.vorratsdatenspeicherung.de/`  
`https://www.vorratsdatenspeicherung.de/`

#### Technical details

PyCURL sends TLS handshake with SNI for the first host. This works. Connection
is then closed, but PyCURL+NSS remembers the SSL session ID. It will attempt to
use the same session ID when later connecting to second host on the same IP.

However, the server won't acknowledge what client requested with new SNI,
because client attempts to resume during TLS handshake using the incorrect
session ID. Thus the session is "resumed" to the first host's SNI.

Side observation: When validation is turned off in PyCURL+NSS, it also turns off
session resume as a side effect (the code is in curl's nss.c).

#### Workaround

Set config to use SSLv3 instead of default TLSv1 (option `ssl_version` under
`http` section).

#### Normative reference

See last four paragraphs of [RFC 4366, section
3.1](https://tools.ietf.org/html/rfc4366#section-3.1). Contrast with [RFC 6066
section 3](https://tools.ietf.org/html/rfc6066#section-3), last two paragraphs.
In TLS 1.2 the logic is reversed - server must not resume such connection and
must go through full handshake again.

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

### Threading bugs and workarounds

There are some race conditions with Python threads and OpenSSL/GnuTLS that cause
about due to SIGPIPE or SIGSEGV. While libcurl code seems to have implemented
the necessary callbacks, there's a bug somewhere :-)

Workaround: set `fetch_in_subprocess` under `http` section in config to true
when using multiple threads for fetching.

You might have to set PYTHONPATH if working dir is different from code dir with
python scripts.

If underlying SSL library is NSS, threading looks fine.

As a side effect, the CURL+NSS SNI bug does not happen with subprocesses (SSL
session ID cache is not kept among process invocations).

### Generic bugs/quirks of SSL libraries

Each of the three possible libraries (OpenSSL, GnuTLS, NSS) has different set of
quirks. GnuTLS seems to be the most strict one regarding relevant RFCs and will
not for instance tolerate certificate chain in wrong order or forgive server not
sending `close_notify` alert.

Thus it's entirely possible that while a server chain and SSL/TLS handshake
seems OK when using one lib, it may break with the other.

## Transvalid certificates (transitive closure of root and intermediate certs)

The `platform_certs/FF_transvalid.tar.bz2` attempts to simulate common browser
behavior of caching intermediate certs. The directory contains FF's builtin
certs and all intermediate certs that validate from FF's builtin certs (a
transitive closure).

The certs above are in a tarball (need to be unpacked and c_rehash'd for use).

The script is in `certs_transitive_closure/build_closure.sh` and is rather
crude, definitely needs some double-checking of sanity (see comments inside the
script).

Quick outline of the script's algorithm:

1. IntermediateSet\_0 := {trusted builtin certs from clean install of Firefox}
2. Certs that have basic constraints CA=true or are X509 version 1 are exported
   from some DB like SSL Observatory
3. Iterate over all exported certs, add new unique certificates not yet
   contained in IntermediateSet\_n validate against latest IntermediateSet\_n,
   forming IntermediateSet\_{n+1}
4. n += 1
5. If any certs were added in step 3, goto 3, else end

Last IntermediateSet is the closure. 


