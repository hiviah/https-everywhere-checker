#Metrics for measuring similarity of two strings, HTML/XML DOM trees, etc.
#They are likely not "proper metrics" in calculus sense.

import logging
from lxml import etree
from cStringIO import StringIO

import struct
import bsdiff
import Levenshtein

class BSDiffMetric(object):
	"""String similarity metric based on BSDiff."""

	def __init__(self):
		pass
	
	def distanceNormed(self, s1, s2):
		
		#bsdiff is not symmetric, so take max from both diffs
		control, diffBlock, extra = bsdiff.Diff(s1, s2)
		extraRatio1 = float(len(extra))/float(max(len(s1), len(s2)))
		
		control, diffBlock, extra = bsdiff.Diff(s2, s1)
		extraRatio2 = float(len(extra))/float(max(len(s1), len(s2)))
		
		return max(extraRatio1, extraRatio2)

class MarkupMetric(object):
	"""Metric for tree-like hierarchical languages - XML, HTML."""
	
	def __init__(self):
		pass
	
	def tagNameToCharMap(self, doc1, doc2, minIndex=0):
		"""Returns a dict that maps element names to unicode characters uniquely.
		
		@param doc1: html/xml tree string as lxml Element or ElementTree
		@param doc2: html/xml tree string as lxml Element or ElementTree
		@param minIndex: start numbering with this unicode value
		"""
		tags = set((elem.tag for elem in doc1.xpath("//*")))
		tags.update((elem.tag for elem in doc2.xpath("//*")))
		
		#Number them consistently among those two documents.
		#Hackish way to map custom alphabet onto unicode chars, but works for
		#up to >= 55000 element names which should be more than enough.
		unicodeAlphabet = (struct.pack("<H", index).decode('utf-16') \
			for index in range(minIndex, minIndex+len(tags)))
		numberedTags = zip(tags, unicodeAlphabet)
		
		return dict(numberedTags)
	
	def mapTree(self, elem, tagToCharMap):
		"""Map element to unicode character. If it has no children, it'll be mapped
		to a single char, otherwise mapped as "(X + Y + Z)" where X, Y, Z is
		mapping of its children (+ is concatenation).
		
		@param elem: lxml Element
		@param tagToCharMap: dict from tag name to unicode char
		"""
		children = list(elem)
		thisElem = tagToCharMap.get(elem.tag)
		#TODO: weed out comments and processing instructions
		if not thisElem:
			return u""
		if children:
			childrenMap = [self.mapTree(child, tagToCharMap) for child in children]
			return thisElem + u'(' + "".join(childrenMap) + u')'
		else:
			return thisElem
			
	def mappedTrees(self, doc1, doc2):
		"""Returns unicode string that represents the tree structure of
		the HTML/XML documents. Only tag names are considered.
		
		@returns: tuple of two unicode strings
		"""
		#The 42 is first char after parentheses in unicode encoding
		tagToCharMap = self.tagNameToCharMap(doc1, doc2, 42)
		
		return (self.mapTree(doc1, tagToCharMap), self.mapTree(doc2, tagToCharMap))
	
	def distanceNormed(self, s1, s2):
		"""
		"""
		doc1 = etree.parse(StringIO(s1), etree.HTMLParser())
		doc2 = etree.parse(StringIO(s2), etree.HTMLParser())
		
		mapped1, mapped2 = self.mappedTrees(doc1, doc2)
		
		return Levenshtein.ratio(mapped1, mapped2)
		
