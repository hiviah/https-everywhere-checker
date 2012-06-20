#!/usr/bin/env python

import sys
import os
import glob
import logging

from ConfigParser import SafeConfigParser

import pycurl
from lxml import etree

from rules import Ruleset
from rule_trie import RuleTrie

if len(sys.argv) < 2:
	print >> sys.stderr, "check_rules.py checker.config"
	sys.exit(1)

config = SafeConfigParser()
config.read(sys.argv[1])

ruledir = config.get("rulesets", "rulesdir")

xmlFnames = glob.glob(os.path.join(ruledir, "*.xml"))
trie = RuleTrie()


for xmlFname in xmlFnames:
	ruleset = Ruleset(etree.parse(file(xmlFname)))
	#print ruleset
	#print "=====", ruleset.rules
	
	trie.addRuleset(ruleset)
trie.prettyPrint()

print trie.matchingRulesets("www.google.com")
