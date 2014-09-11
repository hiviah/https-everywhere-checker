#!/usr/bin/env python

import sys
import os
import glob
import logging
import threading
import Queue
import time

from ConfigParser import SafeConfigParser

from lxml import etree

import http_client
import metrics
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

def getMetricClass(metricType):
	"""Get class for metric type from config file.
	
	@raises ValueError if the metric type is unknown
	"""
	metricMap = {
		"markup": metrics.MarkupMetric,
		"bsdiff": metrics.BSDiffMetric,
	}
	
	if metricType not in metricMap:
		raise ValueError("Metric type '%s' is not known" % metricType)
	
	return metricMap[metricType]


class ComparisonTask(object):
	"""Container for objects necessary for one plain/rewritten URL comparison.
	"""
	
	def __init__(self, plainUrl, transformedUrl, fetcherPlain, fetcherRewriting, ruleFname):
		self.plainUrl = plainUrl
		self.transformedUrl = transformedUrl
		self.fetcherPlain = fetcherPlain
		self.fetcherRewriting = fetcherRewriting
		self.ruleFname = ruleFname
	
class UrlComparisonThread(threading.Thread):
	"""Thread worker for comparing plain and rewritten URLs.
	"""
	
	def __init__(self, taskQueue, metric, thresholdDistance):
		"""
		Comparison thread running HTTP/HTTPS scans.
		
		@param taskQueue: Queue.Queue filled with ComparisonTask objects
		@param metric: metric.Metric instance
		@param threshold: min distance that is reported as "too big"
		"""
		self.taskQueue = taskQueue
		self.metric = metric
		self.thresholdDistance = thresholdDistance
		threading.Thread.__init__(self)

	def run(self):
		while True:
			task = self.taskQueue.get()
			
			plainUrl = task.plainUrl
			transformedUrl = task.transformedUrl
			fetcherPlain = task.fetcherPlain
			fetcherRewriting = task.fetcherRewriting
			ruleFname = task.ruleFname
			
			try:
				logging.debug("=**= Start %s => %s ****", plainUrl, transformedUrl)
				logging.debug("Fetching plain page %s", plainUrl)
				plainRcode, plainPage = fetcherPlain.fetchHtml(plainUrl)
				logging.debug("Fetching transformed page %s", transformedUrl)
				transformedRcode, transformedPage = fetcherRewriting.fetchHtml(transformedUrl)
				
				#Compare HTTP return codes - if original page returned 2xx,
				#but the transformed didn't, consider it an error in ruleset
				#(note this is not symmetric, we don't care if orig page is broken).
				#We don't handle 1xx codes for now.
				if plainRcode//100 == 2 and transformedRcode//100 != 2:
					logging.error("Non-2xx HTTP code: %s (%d) => %s (%d). Rulefile: %s",
						plainUrl, plainRcode, transformedUrl, transformedRcode,
						ruleFname)
					continue
				
				distance = self.metric.distanceNormed(plainPage, transformedPage)
				
				logging.debug("==== D: %0.4f; %s (%d) -> %s (%d) =====",
					distance,plainUrl, len(plainPage), transformedUrl, len(transformedPage))
				
				if distance >= self.thresholdDistance:
					logging.info("Big distance %0.4f: %s (%d) -> %s (%d). Rulefile: %s =====",
						distance, plainUrl, len(plainPage), transformedUrl, len(transformedPage), ruleFname)
			except Exception, e:
				logging.exception("Failed to process %s: %s. Rulefile: %s",
					plainUrl, e, ruleFname)
			finally:
				self.taskQueue.task_done()
				logging.info("Finished comparing %s -> %s. Rulefile: %s.",
					plainUrl, transformedUrl, ruleFname)


def cli():
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
	
	threadCount = config.getint("http", "threads")
	
	#get all platform dirs, make sure "default" is among them
	certdirFiles = glob.glob(os.path.join(certdir, "*"))
	havePlatforms = set([os.path.basename(fname) for fname in certdirFiles if os.path.isdir(fname)])
	logging.debug("Loaded certificate platforms: %s", ",".join(havePlatforms))
	if "default" not in havePlatforms:
		raise RuntimeError("Platform 'default' is missing from certificate directories")
	
	metricName = config.get("thresholds", "metric")
	thresholdDistance = config.getfloat("thresholds", "max_distance")
	metricClass = getMetricClass(metricName)
	metric = metricClass()
	
	urlList = []
	if config.has_option("http", "url_list"):
		with file(config.get("http", "url_list")) as urlFile:
			urlList = [line.rstrip() for line in urlFile.readlines()]
			
	# Debugging options, graphviz dump
	dumpGraphvizTrie = False
	if config.has_option("debug", "dump_graphviz_trie"):
		dumpGraphvizTrie = config.getboolean("debug", "dump_graphviz_trie")
	if dumpGraphvizTrie:
		graphvizFile = config.get("debug", "graphviz_file")
		exitAfterDump = config.getboolean("debug", "exit_after_dump")
	
	
	xmlFnames = glob.glob(os.path.join(ruledir, "*.xml"))
	trie = RuleTrie()
	
	# set of main pages to test
	mainPages = set(urlList)
	
	for xmlFname in xmlFnames:
		ruleset = Ruleset(etree.parse(file(xmlFname)).getroot(), xmlFname)
		if ruleset.defaultOff:
			logging.debug("Skipping rule '%s', reason: %s", ruleset.name, ruleset.defaultOff)
			continue
		#if list of URLs to test/scan was not defined, guess URLs from target elements
		if not urlList:
			for target in ruleset.uniqueTargetFQDNs():
				targetHTTPLangingPage = "http://%s/" % target
				if not ruleset.excludes(targetHTTPLangingPage):
					mainPages.add(targetHTTPLangingPage)
				else:
					logging.debug("Skipping landing page %s", targetHTTPLangingPage)
		trie.addRuleset(ruleset)
	
	# Trie is built now, dump it if it's set in config
	if dumpGraphvizTrie:
		logging.debug("Dumping graphviz ruleset trie")
		graph = trie.generateGraphizGraph()
		if graphvizFile == "-":
			graph.dot()
		else:
			with file(graphvizFile, "w") as gvFd:
				graph.dot(gvFd)
		if exitAfterDump:
			sys.exit(0)
	
	fetchOptions = http_client.FetchOptions(config)
	fetcherMap = dict() #maps platform to fetcher
	
	platforms = http_client.CertificatePlatforms(os.path.join(certdir, "default"))
	for platform in havePlatforms:
		#adding "default" again won't break things
		platforms.addPlatform(platform, os.path.join(certdir, platform))
		fetcher = http_client.HTTPFetcher(platform, platforms, fetchOptions, trie)
		fetcherMap[platform] = fetcher
	
	#fetches pages with unrewritten URLs
	fetcherPlain = http_client.HTTPFetcher("default", platforms, fetchOptions)
	
	taskQueue = Queue.Queue(1000)
	startTime = time.time()
	testedUrlPairCount = 0
	
	for i in range(threadCount):
		t = UrlComparisonThread(taskQueue, metric, thresholdDistance)
		t.setDaemon(True)
		t.start()
	
	for plainUrl in mainPages:
		try:
			ruleFname = None
			ruleMatch = trie.transformUrl(plainUrl)
			transformedUrl = ruleMatch.url
			
			if plainUrl == transformedUrl:
				logging.info("Identical URL: %s", plainUrl)
				continue
			
			#URL was transformed, thus ruleset must exist that did it
			ruleFname = os.path.basename(ruleMatch.ruleset.filename)
			fetcher = fetcherMap.get(ruleMatch.ruleset.platform)
			if not fetcher:
				logging.warn("Unknown platform '%s', using 'default' instead. Rulefile: %s.",
					ruleMatch.ruleset.platform, ruleFname)
				fetcher = fetcherMap["default"]
				
		except:
			logging.exception("Failed to transform plain URL %s. Rulefile: %s.",
				plainUrl, ruleFname)
			continue
		
		testedUrlPairCount += 1
		task = ComparisonTask(plainUrl, transformedUrl, fetcherPlain, fetcher, ruleFname)
		taskQueue.put(task)
		
	taskQueue.join()
	logging.info("Finished in %.2f seconds. Loaded rulesets: %d, URL pairs: %d.",
		time.time() - startTime, len(xmlFnames), testedUrlPairCount)

if __name__ == '__main__':
	sys.exit(cli())
