import urlparse

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
		"""Look for rules applicable to URL and apply first one.
		
		@returns: url transformed by rules in this trie
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
				return newUrl
		return url
	
	def prettyPrint(self):
		self.root.prettyPrint()


