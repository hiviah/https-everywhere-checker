import logging
import pycurl
import cStringIO
import re

class CertificatePlatforms(object):
	"""Maps platform names from rulesets to CA certificate sets"""
	
	def __init__(self, defaultCAPath):
		"""Initialize with default path for CA certificates.
		
		@param defaultCAPath: directory with PEM certificates of trusted
		CA certificates that have been run throug openssl's c_rehash
		"""
		self.defaultCAPath = defaultCAPath
		self.platformPaths = {"default": defaultCAPath}
	
	def addPlatform(self, platform, caPath):
		"""Add a directory with CA certificates for given platform.
		
		@param platform: string name that matches the "platform"
		attribute in <ruleset> element
		@param caPath: path to dir with c_rehash'd PEM certificates
		"""
		self.platformPaths["platform"] = caPath
	
	def getCAPath(self, platform):
		"""Return path to CA certs for chosen platform. If it does not
		exist, return default CA path.
		"""
		return self.platformPaths.get(platform) or self.defaultCAPath

class FetchOptions(object):
	"""HTTP fetcher options like timeouts."""
	
	def __init__(self, config):
		"""Parse options from [http] section
		
		@param config: ConfigParser object - a config with [http] section
		"""
		self.connectTimeout = config.getint("http", "connect_timeout")
		self.readTimeout = config.getint("http", "read_timeout")
		self.redirectDepth = config.getint("http", "redirect_depth")
	
class HTTPFetcherError(RuntimeError):
	pass

class HTTPFetcher(object):
	"""Fetches HTTP(S) pages via PyCURL. CA certificates can be configured.
	"""
	
	_headerRe = re.compile(r"(?P<name>\S+?): (?P<value>.*?)\r\n")
	
	def __init__(self, platform, certPlatforms, fetchOptions, ruleTrie=None):
		"""Create fetcher that validates certificates using selected
		platform.
		
		@param platform: platform name to use for TLS cert verification
		@param certPlatforms: CertificatePlatforms instance with caPaths
		for known platforms
		@param ruleTrie: rules.RuleTrie to apply on URLs for following.
		Set to None if redirects should not be rewritten
		"""
		self.platformPath = certPlatforms.getCAPath(platform)
		self.certPlatforms = certPlatforms
		self.options = fetchOptions
		self.ruleTrie = ruleTrie
	
	def fetchHtml(self, url):
		"""Fetch HTML from given http/https URL. Return codes 301 and
		302 are followed, URLs rewritten using HTTPS Everywhere rules.
		
		@param url: string URL of http(s) resource
		@returns: tuple (httpResponseCode, htmlData)
		
		@throws pycurl.error: on failed fetch
		@throws HTTPFetcherError: on failed fetch/redirection
		"""
		newUrl = url
	
		#handle 301/302 redirects while also rewriting them with HTE rules
		#limit redirect depth
		for depth in range(self.options.redirectDepth):
			buf = cStringIO.StringIO()
			headerBuf = cStringIO.StringIO()
			
			try:
				c = pycurl.Curl()
				c.setopt(c.URL, newUrl)
				c.setopt(c.WRITEFUNCTION, buf.write)
				c.setopt(c.HEADERFUNCTION, headerBuf.write)
				c.setopt(c.CONNECTTIMEOUT, self.options.connectTimeout)
				c.setopt(c.TIMEOUT, self.options.readTimeout)
				c.setopt(c.CAPATH, self.platformPath)
				c.perform()
			
				#shitty HTTP header parsing
				headerStr = headerBuf.getvalue()
				httpCode = c.getinfo(pycurl.HTTP_CODE)
				if httpCode == 0:
					raise HTTPFetcherError("Pycurl fetch failed for '%s'" % newUrl)
				elif httpCode in (301, 302):
					#'Location' should be present only once, so the dict won't hurt
					headers = dict(self._headerRe.findall(headerStr))
					location = headers.get('Location')
					if not location:
						raise HTTPFetcherError("Redirect for '%s' missing Location" % newUrl)
					logging.debug("Following redirect %s => %s", newUrl, location)
					
					if self.ruleTrie:
						newUrl = self.ruleTrie.transformUrl(location)
						if newUrl != location:
							logging.debug("Redirect rewritten: %s => %s", location, newUrl)
					else:
						newUrl = location
					continue
				
				return (httpCode, buf.getvalue())
			finally:
				buf.close()
				headerBuf.close()
			
		raise HTTPFetcherError("Too many redirects while fetching '%s'" % url)

