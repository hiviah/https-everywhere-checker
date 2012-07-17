import regex

class Rule(object):
	"""Represents one from->to rule element."""
	
	def __init__(self, ruleElem):
		"""Convert one <rule> element.
		@param: etree <rule>Element
		"""
		attrs = ruleElem.attrib
		self.fromPattern = attrs["from"]
		#Switch $1, $2... JS capture patterns to Python \g<1>, \g<2>...
		#The \g<1> named capture is used instead of \1 because it would
		#break for rules whose domain begins with a digit.
		self.toPattern = regex.sub(r"\$(\d)", r"\\g<\1>", attrs["to"])
		self.fromRe = regex.compile(self.fromPattern)
	
	def apply(self, url):
		"""Apply rule to URL string and return result."""
		return self.fromRe.sub(self.toPattern, url)
	
	def __repr__(self):
		return "<Rule from '%s' to '%s'>" % (self.fromRegex, self.toRegex)
	
	def __str__(self):
		return self.__repr__()
	
	def _id(self):
		"""Indentity for __eq__ and __hash__"""
		return (self.fromPattern, self.toPattern)
	
	def __eq__(self, other):
		return self._id() == other._id()
	
	def __hash__(self):
		return hash(self._id())

class Exclusion(object):
	"""Exclusion rule for <exclusion pattern=""> element"""
	
	def __init__(self, exclusionElem):
		"""Create instance from <exclusion> element
		@param exclusionElem: <exclusion> element from lxml tree
		"""
		self.exclusionPattern = exclusionElem.attrib["pattern"]
		self.exclusionRe = regex.compile(self.exclusionPattern)
	
	def matches(self, url):
		"""Returns true iff this exclusion rule matches given url
		@param url: URL to check as string
		"""
		return self.exclusionRe.match(url) is not None
	
class Ruleset(object):
	"""Represents one XML ruleset file."""
	
	#extracts value of first attribute in list as a string
	_strAttr = lambda attrList: unicode(attrList[0])
	
	#extract attribute value and decode to ASCII with IDN punycode encoding
	_idnAttrs = lambda attrList: tuple(unicode(attr).encode("idna") for attr in attrList)
	
	#convert each etree Element of list into Rule
	_rulesConvert = lambda elemList: [Rule(elem) for elem in elemList]
	
	#convert each etree Element of list into Exclusion
	_exclusionConvert = lambda elemList: [Exclusion(elem) for elem in elemList]
	
	#functional description of converting XML elements/attributes into
	#instance variables. Tuples are:
	#(attribute name in this class, XPath expression, conversion function into value)
	_attrConvert = [
		("name",	"@name", 		_strAttr),
		("platform",	"@platform", 		_strAttr),
		("defaultOff",	"@default_off", 	_strAttr),
		("targets",	"target/@host",		_idnAttrs),
		("rules",	"rule", 		_rulesConvert),
		("exclusions",	"exclusion", 		_exclusionConvert),
	]
	
	def __init__(self, xmlTree, filename):
		"""Create instance from given XML (sub)tree.
		
		@param xmlTree: XML (sub)tree corresponding to the <ruleset> element
		@param filename: filename this ruleset originated from (for
		reporting purposes)
		"""
		root = xmlTree
		#set default values for rule attributes, makes it easier for
		#code completion
		self.name = None
		self.platform = "default"
		self.defaultOff = None
		self.rules = []
		self.targets = []
		self.exclusions = []
		self.filename = filename
		
		for (attrName, xpath, conversion) in self._attrConvert:
			elems = root.xpath(xpath)
			if elems:
				setattr(self, attrName, conversion(elems))
			
		
	
	def excludes(self, url):
		"""Returns True iff one of exclusion patterns matches the url."""
		return any((exclusion.matches(url) for exclusion in self.exclusions))
	
	def apply(self, url):
		"""Apply rules from this ruleset on the given url. Exclusions
		are checked.
		
		@param url: string URL
		"""
		if self.excludes(url):
			return url
		
		for rule in self.rules:
			newUrl = rule.apply(url)
			if url != newUrl:
				return newUrl #only one rewrite
		
		return url #nothing rewritten
		
	def uniqueTargetFQDNs(self):
		"""Returns unique FQDNs found in <target> elements.
		Any FQDNs with wildcard part are skipped.
		
		@returns: iterable of FQDN strings
		"""
		uniqueFQDNs = set()
		for target in self.targets:
			if '*' in target:
				continue
			uniqueFQDNs.add(target)
		
		return uniqueFQDNs
	
	def __repr__(self):
		return "<Ruleset(name=%s, platform=%s)>" % (repr(self.name), repr(self.platform))
	
	def __str__(self):
		return self.__repr__()
	
	def __eq__(self, other):
		"""We consider name to be unique identifier."""
		return self.name == other.name
	
	def __hash__(self):
		return hash(self.name)
