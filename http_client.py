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
	
class HTTPFetcher(object):
	"""Fetches HTTP(S) pages via PyCURL. CA certificates can be configured.
	"""
	
	_headerRe = re.compile(r"(?P<name>.*?): (?P<value>.*?)\r\n")
	
	def __init__(self, platform, certPlatforms, fetchOptions):
		"""Create fetcher that validates certificates using selected
		platform.
		
		@param platform: platform name to use for TLS cert verification
		@param certPlatforms: CertificatePlatforms instance with caPaths
		for known platforms
		"""
		self.platformPath = certPlatforms.getCAPath(platform)
		self.certPlatforms = certPlatforms
		self.options = fetchOptions
	
	def fetchHtml(self, url):
		"""Fetch HTML from given http/https URL.
		
		@param url: string URL of http(s) resource
		@throws pycurl.error: on failed fetch
		"""
	
		buf = cStringIO.StringIO()
		headerBuf = cStringIO.StringIO()
		
		try:
			c = pycurl.Curl()
			c.setopt(c.URL, url)
			c.setopt(c.WRITEFUNCTION, buf.write)
			c.setopt(c.HEADERFUNCTION, headerBuf.write)
			c.setopt(c.CONNECTTIMEOUT, self.options.connectTimeout)
			c.setopt(c.TIMEOUT, self.options.readTimeout)
			c.setopt(c.CAPATH, self.platformPath)
			c.perform()
		
			#headers = self._headerRe.findall(headerBuf.getvalue())
			return buf.getvalue()
		finally:
			buf.close()
			headerBuf.close()

