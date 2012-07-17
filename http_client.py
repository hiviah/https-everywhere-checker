import logging
import pycurl
import urlparse
import cStringIO
import regex

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
		self.platformPaths[platform] = caPath
	
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
	
	_headerRe = regex.compile(r"(?P<name>\S+?): (?P<value>.*?)\r\n")
	
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
	
	def idnEncodedUrl(self, url):
		"""Encodes URL so that IDN domains are punycode-escaped. Has no
		effect on plain old ASCII domain names.
		"""
		p = urlparse.urlparse(url)
		netloc = isinstance(p.netloc, unicode) and p.netloc or p.netloc.decode("utf-8")
		newNetloc = netloc.encode("idna")
		parts = list(p)
		parts[1] = newNetloc
		return urlparse.urlunparse(parts)
		
	def absolutizeUrl(self, base, url):
		"""Returns absolutized URL in respect to base URL as per
		RFC 3986. If url is already absolute (with scheme), return url.
		
		@param base: base URL of original document
		@param url: URL to be resolved against base URL
		"""
		#urljoin fails for some of the abnormal examples in section 5.4.2
		#of RFC 3986 if there are too many ./ or ../
		#See http://bugs.python.org/issue3647
		resolved = urlparse.urljoin(base, url)
		resolvedParsed = urlparse.urlparse(resolved)
		path = resolvedParsed.path
		
		#covers corner cases like "g:h" relative URL
		if path == "" or not path.startswith("/"):
			return resolved
		
		#strip any leading ./ or ../
		pathParts = path[1:].split("/")
		while len(pathParts) > 0 and pathParts[0] in (".", ".."):
			pathParts = pathParts[1:]
		
		if len(pathParts) > 0:
			newPath = "/" + "/".join(pathParts)
		else:
			newPath = "/"
			
		#replace old path and unparse into URL
		urlParts = resolvedParsed[0:2] + (newPath,) + resolvedParsed[3:6]
		newUrl = urlparse.urlunparse(urlParts)
		
		return newUrl
		
	def fetchHtml(self, url):
		"""Fetch HTML from given http/https URL. Return codes 301 and
		302 are followed, URLs rewritten using HTTPS Everywhere rules.
		
		@param url: string URL of http(s) resource
		@returns: tuple (httpResponseCode, htmlData)
		
		@throws pycurl.error: on failed fetch
		@throws HTTPFetcherError: on failed fetch/redirection
		"""
		newUrl = url
		#While going through 301/302 redirects we might encounter URL
		#that was rewritten using different platform and need to use
		#that platform's certs for the next fetch.
		newUrlPlatformPath = self.platformPath
		
		#set of URLs seen in redirects for cycle detection
		seenUrls = set()
	
		#handle 301/302 redirects while also rewriting them with HTE rules
		#limit redirect depth
		for depth in range(self.options.redirectDepth):
			buf = cStringIO.StringIO()
			headerBuf = cStringIO.StringIO()
			
			try:
				c = pycurl.Curl()
				newUrl = self.idnEncodedUrl(newUrl)
				seenUrls.add(newUrl)
				c.setopt(c.URL, newUrl)
				c.setopt(c.WRITEFUNCTION, buf.write)
				c.setopt(c.HEADERFUNCTION, headerBuf.write)
				c.setopt(c.CONNECTTIMEOUT, self.options.connectTimeout)
				c.setopt(c.TIMEOUT, self.options.readTimeout)
				c.setopt(c.CAPATH, newUrlPlatformPath)
				#c.setopt(c.VERBOSE, 1)
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
					
					location = self.absolutizeUrl(newUrl, location)
					logging.debug("Following redirect %s => %s", newUrl, location)
					
					if self.ruleTrie:
						ruleMatch = self.ruleTrie.transformUrl(location)
						newUrl = ruleMatch.url
						
						#Platform for cert validation might have changed.
						#Record CA path for the platform or reset if not known.
						if ruleMatch.ruleset:
							newUrlPlatformPath = self.certPlatforms.getCAPath(ruleMatch.ruleset.platform)
						else:
							newUrlPlatformPath = self.platformPath
							
						if newUrl != location:
							logging.debug("Redirect rewritten: %s => %s", location, newUrl)
					else:
						newUrl = location
				
					if newUrl in seenUrls:
						raise HTTPFetcherError("Cycle detected - URL already encountered: %s" % newUrl)
					
					continue #fetch redirected location
					
				return (httpCode, buf.getvalue())
			finally:
				buf.close()
				headerBuf.close()
				c.close()
			
		raise HTTPFetcherError("Too many redirects while fetching '%s'" % url)

