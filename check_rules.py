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

def convertLoglevel(levelString):
	"""Converts string 'debug', 'info', etc. into corresponding
	logging.XXX value which is returned.
	
	@raises ValueError if the level is undefined
	"""
	try:
		return getattr(logging, levelString.upper())
	except AttributeError:
		raise ValueError("No such loglevel - %s" % levelString)

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print >> sys.stderr, "check_rules.py checker.config"
		sys.exit(1)
	
	config = SafeConfigParser()
	config.read(sys.argv[1])
	
	logfile = config.get("log", "logfile")
	loglevel = convertLoglevel(config.get("log", "loglevel"))
	if logfile == "-":
		logging.basicConfig(stream=sys.stderr, level=loglevel,
			format="%(asctime)s %(levelname)s %(message)s [%(pathname)s:%(lineno)d]")
	else:
		logging.basicConfig(filename=logfile, level=loglevel,
			format="%(asctime)s %(levelname)s %(message)s [%(pathname)s:%(lineno)d]")
		
	ruledir = config.get("rulesets", "rulesdir")
	certdir = config.get("certificates", "basedir")
	
	xmlFnames = glob.glob(os.path.join(ruledir, "*.xml"))
	trie = RuleTrie()
	
	# set of main pages to test
	mainPages = set()
	
	for xmlFname in xmlFnames:
		ruleset = Ruleset(etree.parse(file(xmlFname)).getroot())
		if ruleset.defaultOff:
			logging.debug("Skipping rule '%s', reason: %s", ruleset.name, ruleset.defaultOff)
		for target in ruleset.uniqueTargetFQDNs():
			targetHTTPLangingPage = "http://%s/" % target
			if not ruleset.excludes(targetHTTPLangingPage):
				mainPages.add(targetHTTPLangingPage)
			else:
				logging.debug("Skipping landing page %s", targetHTTPLangingPage)
		trie.addRuleset(ruleset)
	
	#trie.prettyPrint()
	
	matching = trie.matchingRulesets("yandex.ru")
	#matching = trie.matchingRulesets("www.google.com")
	rule = matching.pop()
	
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
		
