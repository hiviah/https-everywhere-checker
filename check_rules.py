#!/usr/bin/env python

import sys
import os
import glob
import logging

from cStringIO import StringIO
from ConfigParser import SafeConfigParser

from lxml import etree

import http_client
import metrics
from rules import Ruleset
from rule_trie import RuleTrie
import Levenshtein

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
			if not ruleset.excludes(targetHTTPLangingPage) and "*" not in targetHTTPLangingPage:
				mainPages.add(targetHTTPLangingPage)
			else:
				logging.debug("Skipping landing page %s", targetHTTPLangingPage)
		trie.addRuleset(ruleset)
	
	fetchOptions = http_client.FetchOptions(config)
	
	platforms = http_client.CertificatePlatforms(certdir)
	havePlatforms = ["cacert"]
	for platform in havePlatforms:
		platforms.addPlatform(platform, os.path.join(certdir, platform))
	
	fetcher = http_client.HTTPFetcher("default", platforms, fetchOptions, trie)
	fetcherCACert = http_client.HTTPFetcher("cacert", platforms, fetchOptions, trie)
	fetcherPlain = http_client.HTTPFetcher("default", platforms, fetchOptions)
	
	for plainUrl in mainPages:
		try:
			transformedUrl = trie.transformUrl(plainUrl)
		except:
			logging.error("Failed to transform plain URL %s", plainUrl)
			continue
		
		if plainUrl == transformedUrl:
			logging.warn("Identical URL: %s", plainUrl)
			continue
		
		try:
			logging.info("=**= Start %s => %s ****", plainUrl, transformedUrl)
			logging.info("Fetching plain page %s", plainUrl)
			plainRcode, plainPage = fetcherPlain.fetchHtml(plainUrl)
			logging.info("Fetching transformed page %s", transformedUrl)
			transformedRcode, transformedPage = fetcher.fetchHtml(transformedUrl)
			
			bsMetric = metrics.BSDiffMetric()
			markupMetric = metrics.MarkupMetric()
			
			bsDistance = bsMetric.distanceNormed(plainPage, transformedPage)
			markupDistance = markupMetric.distanceNormed(plainPage, transformedPage)
			
			logging.info("==== %s (%d) -> %s (%d) =====", plainUrl, len(plainPage), transformedUrl, len(transformedPage))
			logging.info(">>>> BS: %0.4f Markup: %0.4f", bsDistance, markupDistance)
		except KeyboardInterrupt:
			raise
		except:
			logging.exception("Failed to process %s", plainUrl)
		
		
