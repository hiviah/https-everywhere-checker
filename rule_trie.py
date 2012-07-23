import urlparse

## Rule trie
#
# Rule trie is a suffix tree that resolves which rulesets should apply for a
# given FDQN. FQDN is first tranformed from potential IDN form into punycode
# ASCII. Every node in the tree has a list of rulesets that maps the part of 
# FQDN between dots to list/set of rulesets.
#
# Children subdomains are mapped using dict.
#
#
#                               +--------+
#                           +---| root . |----+
#                           |   +--------+    |
#                           |                 |
#                           |                 |
#                           v                 v
#                        +-----+           +-----+
#                  +-----|  *  |     +-----| com |-----+
#                  |     +-----+     |     +-----+     |
#                  |                 |                 |
#                  v                 v                 v
#              +------+          +------+            +----+
#           +--|google|---+      |google|-+      +---|blee|---+
#           |  +------+   |      +------+ |      |   +----+   |
#           |     |       |       |       |      |     |      |
#           |     |       |       |       |      |     |      |
#           v     v       v       v       v      v     v      v
#         +---+ +---+ +----+    +---+   +---+  +---+ +----+ +---+
#         | * | |www| |docs|    | * |   |www|  |www| |www2| |ssl|
#         +---+ +---+ +----+    +---+   +---+  +---+ +----+ +---+
#
# At every node of the tree, there might be rulesets present. If a domain
# a.b.c is looked up, at every location of * the search is branched into
# multiple children - one with * and the other matching the domain part
# exactly.
#
# Assuming complexity of lookup in dict is O(1), lookup of FQDN consisting
# of N parts is O(N) if there are no * in the tree. Otherwise in theory
# it could be O(2^N), but the HTTPS Everywhere rules require only one *, so we
# still get O(N).

class RuleTransformError(ValueError):
	"""Thrown when invalid scheme like file:/// is attempted to be
	transformed.
	"""
	pass

class DomainNode(object):
	"""Node of suffix trie for searching of applicable rulesets."""
	
	def __init__(self, subDomain, rulesets):
		"""Create instance for part of FQDN.
		@param subDomain: part of FQDN between "dots"
		@param rulesets: rules.Ruleset list that applies for this node in tree
		"""
		self.subDomain = subDomain
		self.rulesets = rulesets
		self.children = {}
	
	def addChild(self, subNode):
		"""Add DomainNode for more-specific subdomains of this one."""
		self.children[subNode.subDomain] = subNode
	
	def matchingRulesets(self, domain):
		"""Find matching rulesets for domain in this subtree.
		@param domain: domain to search for in this node's subtrees;
		empty string matches this node. Must not contain wildcards.
		@return: set of applicate rulesets
		"""
		#we are the leaf that matched
		if domain == "":
			return self.rulesets
		
		#make sure domain is in ASCII - either "plain old domain" or
		#punycode-encoded IDN domain
		if not isinstance(domain, unicode):
			domain = domain.decode("utf-8")
		domain = domain.encode("idna")
		
		parts = domain.rsplit(".", 1)
		
		if len(parts) == 1: #direct match on children
			childDomain = domain
			subLevelDomain = ""
		else:
			subLevelDomain, childDomain = parts
		
		wildcardChild = self.children.get("*")
		ruleChild = self.children.get(childDomain)
		
		applicableRules = set()
		
		#we need to consider direct matches as well as wildcard matches so
		#that match for things like "bla.google.*" work
		if ruleChild:
			applicableRules.update(ruleChild.matchingRulesets(subLevelDomain))
		if wildcardChild:
			applicableRules.update(wildcardChild.matchingRulesets(subLevelDomain))
			
		return applicableRules
	
	def prettyPrint(self, offset=0):
		"""Pretty print for debugging"""
		print " "*offset,
		print unicode(self)
		for child in self.children.values():
			child.prettyPrint(offset+3)
	
	def __str__(self):
		return "<DomainNode for '%s', rulesets: %s>" % (self.subDomain, self.rulesets)
	
	def __repr__(self):
		return "<DomainNode for '%s>" % (self.subDomain,)


class RuleMatch(object):
	"""Result of a rule match, contains transformed url and ruleset that
	matched (might be None if no match was found).
	"""
	
	def __init__(self, url, ruleset):
		"""Create instance that records url and ruleset that matched.
		
		@param url: transformed url after applying ruleset
		@param ruleset: ruleset that was used for the transform
		"""
		self.url = url
		self.ruleset = ruleset
	
class RuleTrie(object):
	"""Suffix trie for rulesets."""
	
	def __init__(self):
		self.root = DomainNode("", [])
	
	def matchingRulesets(self, fqdn):
		"""Return rulesets applicable for FQDN. Wildcards not allowed.
		"""
		return self.root.matchingRulesets(fqdn)
	
	def addRuleset(self, ruleset):
		"""Creates structure for given ruleset in the trie.
		@param ruleset: rules.Ruleset instance
		"""
		for target in ruleset.targets:
			node = self.root
			#enumerate parts so we know when we hit leaf where
			#rulesets are to be stored
			parts = list(enumerate(target.split(".")))
			
			for (idx, part) in reversed(parts):
				partNode = node.children.get(part)
				
				#create node if not existing already and stuff
				#the rulesets in leaf
				if not partNode:
					partNode = DomainNode(part, [])
					node.addChild(partNode)
				if idx == 0:
					#there should be only one ruleset, but...
					partNode.rulesets.append(ruleset)
				
				node = partNode
	
	def acceptedScheme(self, url):
		"""Returns True iff the scheme in URL is accepted (http, https).
		"""
		parsed = urlparse.urlparse(url)
		return parsed.scheme in ("http", "https")
		
	def transformUrl(self, url):
		"""Look for rules applicable to URL and apply first one. If no
		ruleset matched, resulting RuleMatch object will have None set
		as the matching ruleset.
		
		@returns: RuleMatch with tranformed URL and ruleset that applied
		@throws: RuleTransformError if scheme is wrong (e.g. file:///)
		"""
		parsed = urlparse.urlparse(url)
		if parsed.scheme not in ("http", "https"):
			raise RuleTransformError("Unknown scheme '%s' in '%s'" % \
				(parsed.scheme, url))
			
		fqdn = parsed.netloc.lower()
		matching = self.matchingRulesets(fqdn)
		
		for ruleset in matching:
			newUrl = ruleset.apply(url)
			if newUrl != url:
				return RuleMatch(newUrl, ruleset)
		return RuleMatch(url, None)
	
	def prettyPrint(self):
		self.root.prettyPrint()


