from lxml import etree

class Rule(object):
	"""Represents one from->to rule element."""
	
	def __init__(self, ruleElem):
		"""Convert one <rule> element.
		@param: etree <rule>Element
		"""
		attrs = ruleElem.attrib
		self.fromRegex = attrs["from"]
		self.toRegex = attrs["to"]
	
	def __repr__(self):
		return "<Rule from '%s' to '%s'>" % (self.fromRegex, self.toRegex)
	
	def __str__(self):
		return self.__repr__()
	
	def _id(self):
		"""Indentity for __eq__ and __hash__"""
		return (self.fromRegex, self.toRegex)
	
	def __eq__(self, other):
		return self._id() == other._id()
	
	def __hash__(self):
		return hash(self._id())

class Ruleset(object):
	"""Represents one XML ruleset file."""
	
	#extracts value of first attribute in list as a string
	_strAttr = lambda attrList: unicode(attrList[0])
	
	#extract attribute value and convert to strings
	_strAttrs = lambda attrList: tuple(unicode(attr) for attr in attrList)
	
	#convert each etree Element of list into Rule
	_rulesConvert = lambda elemList: [Rule(elem) for elem in elemList]
	
	#functional description of converting XML elements/attributes into
	#instance variables. Tuples are:
	#(attribute name in this class, XPath expression, conversion function into value)
	_attrConvert = [
		("name",	"/ruleset/@name", 		_strAttr),
		("platform",	"/ruleset/@platform", 		_strAttr),
		("defaultOff",	"/ruleset/@default_off", 	_strAttr),
		("targets",	"/ruleset/target/@host",	_strAttrs),
		("rules",	"/ruleset/rule", 		_rulesConvert),
	]
	
	def __init__(self, xmlTree):
		"""Create instance from given XML (sub)tree.
		@param xmlTree: XML (sub)tree with rules element
		"""
		root = xmlTree
		#set default values for rule attributes, makes it easier for
		#code completion
		self.name = None
		self.platform = None
		self.defaultOff = None
		self.rules = []
		self.targets = []
		
		for (attrName, xpath, conversion) in self._attrConvert:
			elems = root.xpath(xpath)
			if elems:
				setattr(self, attrName, conversion(elems))
			
		
	
	def __repr__(self):
		return "<Ruleset(name=%s, platform=%s)>" % (repr(self.name), repr(self.platform))
	
	def __str__(self):
		return self.__repr__()
	
	def __eq__(self, other):
		"""We consider name to be unique identifier."""
		return self.name == other.name
	
	def __hash__(self):
		return hash(self.name)
