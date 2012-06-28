#!/usr/bin/env python

import sys
import os
import glob
import logging

from cStringIO import StringIO
from ConfigParser import SafeConfigParser

from lxml import etree

import http_client
from rules import Ruleset
from rule_trie import RuleTrie

if len(sys.argv) < 2:
	print >> sys.stderr, "check_rules.py checker.config"
	sys.exit(1)

config = SafeConfigParser()
config.read(sys.argv[1])

ruledir = config.get("rulesets", "rulesdir")
certdir = config.get("certificates", "basedir")

xmlFnames = glob.glob(os.path.join(ruledir, "*.xml"))
trie = RuleTrie()


for xmlFname in xmlFnames:
	ruleset = Ruleset(etree.parse(file(xmlFname)).getroot())
	#print ruleset
	#print "=====", ruleset.rules
	trie.addRuleset(ruleset)

#trie.prettyPrint()

matching = trie.matchingRulesets("yandex.ru")
#matching = trie.matchingRulesets("www.google.com")
print matching
rule = matching.pop()
print rule.uniqueTargetFQDNs()
print rule.excludes("http://api-maps.yandex.ru/ladfhglaskdjgh/xcvxzcv.zxcv")
print rule.excludes("http://fffuuu.yandex.ru/iugyosidfgy")
print rule.excludes("http://www.google.com/search/zbla&fu=blue&tbs=shop&zzz=ggg")

fetchOptions = http_client.FetchOptions(config)
platforms = http_client.CertificatePlatforms(certdir)
fetcher = http_client.HTTPFetcher(rule.platform, platforms, fetchOptions)

p1 = fetcher.fetchHtml("http://www.yandex.ru")

t1 = etree.parse(StringIO(p1), etree.HTMLParser())

urls = t1.xpath("//a/@href | //img/@src | //link/@href")

for url in urls:
	url = unicode(url)
	if not url.startswith("http://"):
		continue
	newUrl = rule.apply(url)
	if url != newUrl:
		print url, "========>", newUrl
	
