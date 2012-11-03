import os
import sys
import logging
import pycurl
import urlparse
import cStringIO
import regex
import cPickle
import traceback
import subprocess

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
		self.userAgent = None
		self.curlVerbose = False
		self.sslVersion = pycurl.SSLVERSION_DEFAULT
		self.useSubprocess = False

		if config.has_option("http", "user_agent"):
			self.userAgent = config.get("http", "user_agent")
		if config.has_option("http", "curl_verbose"):
			self.curlVerbose = config.getboolean("http", "curl_verbose")
		if config.has_option("http", "fetch_in_subprocess"):
			self.useSubprocess = config.getboolean("http", "fetch_in_subprocess")
		if config.has_option("http", "ssl_version"):
			versionStr = config.get("http", "ssl_version")
			try:
				self.sslVersion = getattr(pycurl, 'SSLVERSION_' + versionStr)
			except AttributeError:
				raise ValueError("SSL version '%s' specified in config is unsupported." % versionStr)
	
class FetcherInArgs(object):
	"""Container for parameters necessary to be passed to CURL fetcher when
	invoked in subprocess to workaround openssl/gnutls+curl threading bugs.
	"""
	
	def __init__(self, url, options, platformPath):
		"""
		@param url: IDNA-encoded URL
		@param options: FetchOptions instance
		@param platformPath: directory with platform certificates
		"""
		self.url = url
		self.options = options
		self.platformPath = platformPath
	
	def check(self):
		"""Throw HTTPFetcherError unless attributes are set and sane."""
		if not isinstance(self.url, str) or not self.url:
			raise HTTPFetcherError("URL missing or bad type")
		if not isinstance(self.options, FetchOptions):
			raise HTTPFetcherError("Options have bad type")
		if not isinstance(self.platformPath, str) or not self.platformPath:
			raise HTTPFetcherError("Platform path missing or bad type")
	
class FetcherOutArgs(object):
	"""Container for data returned from fetcher. Picklable object to use
	with subprocess PyCURL invocation.
	"""
	
	def __init__(self, httpCode=None, data=None, headerStr=None, errorStr=None):
		"""
		@param httpCode: return HTTP code as int
		@param data: data fetched from URL as str
		@param headerStr: HTTP headers as str
		@param errorStr: formatted backtrace from exception as str
		"""
		self.httpCode = httpCode
		self.data = data
		self.headerStr = headerStr
		self.errorStr = errorStr
	
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
		
	@staticmethod
	def _doFetch(url, options, platformPath):
		"""
		Fetch data from URL. If options.useSubprocess is True, spawn
		subprocess for fetching.
		
		@see HTTPFetcher.staticFetch() for parameter description
		
		@throws: anything staticFetch() throws
		@throws: HTTPFetcherError in case of problem in subprocess invocation
		@throws: cPickle.UnpicklingError when we get garbage from subprocess
		"""
		if not options.useSubprocess:
			return HTTPFetcher.staticFetch(url, options, platformPath)
		
		inArgs = FetcherInArgs(url, options, platformPath)
		
		# Workaround for cPickle seeing module name as __main__ if we
		# just directly executed this script.
		# TODO: check PYTHONPATH etc if not in the same dir as script
		trampoline = 'import http_client; http_client.subprocessFetch()'
		
		# Spawn subprocess, call this module as "main" program. I tried
		# also using python's multiprocessing module, but for some
		# reason it was a hog on CPU and RAM (maybe due to the queues?)
		# Also, logging module didn't play along nicely.
		args = [sys.executable, '-c', trampoline]
		#logging.debug("Spawning subprocess with args %s", args)
		p = subprocess.Popen(args, stdin=subprocess.PIPE,
			stdout=subprocess.PIPE,	stderr=subprocess.PIPE)
		
		# Hopefully we shouldn't deadlock here: first all data is written
		# to subprocess's stdin, it will unpickle them first. Then we
		# wait for resulting pickled data from stdout. In case of trouble,
		# try using big bufsize or bufsize=-1 in Popen invocation.
		#
		# Doc page for subprocess says "don't use communicate() with big
		# or unlimited data", but doesn't say what is the alternative
		(outData, errData) = p.communicate(cPickle.dumps(inArgs))
		exitCode = p.wait()
		
		if exitCode != 0:
			raise HTTPFetcherError("Subprocess failed with exit code %d" % exitCode)
			
		#logging.debug("Subprocess finished OK")
		unpickled = cPickle.loads(outData)
		if not isinstance(unpickled, FetcherOutArgs):
			raise HTTPFetcherError("Unexpected datatype received from subprocess: %s" % \
				type(unpickled))
		if unpickled.errorStr: #chained exception tracebacks are bit ugly/long
			raise HTTPFetcherError("Fetcher subprocess error: %s" % unpickled.errorStr)
			
		return unpickled
		
	@staticmethod
	def staticFetch(url, options, platformPath):
		"""Construct a PyCURL object and fetch given URL.
		
		@param url: IDNA-encoded URL
		@param options: FetchOptions instance
		@param platformPath: directory with platform certificates
		@returns: FetcherOutArgs instance with fetched URL data
		
		@throws: anything PyCURL can throw (SSL error, timeout, etc.)
		"""
		try:
			buf = cStringIO.StringIO()
			headerBuf = cStringIO.StringIO()
			
			c = pycurl.Curl()
			c.setopt(c.URL, url)
			c.setopt(c.WRITEFUNCTION, buf.write)
			c.setopt(c.HEADERFUNCTION, headerBuf.write)
			c.setopt(c.CONNECTTIMEOUT, options.connectTimeout)
			c.setopt(c.TIMEOUT, options.readTimeout)
			# Validation should not be disabled except for debugging
			#c.setopt(c.SSL_VERIFYPEER, 0)
			#c.setopt(c.SSL_VERIFYHOST, 0)
			c.setopt(c.CAPATH, platformPath)
			if options.userAgent:
				c.setopt(c.USERAGENT, options.userAgent)
			c.setopt(c.SSLVERSION, options.sslVersion)
			c.setopt(c.VERBOSE, options.curlVerbose)
			c.perform()
			
			bufValue = buf.getvalue()
			headerStr = headerBuf.getvalue()
			httpCode = c.getinfo(pycurl.HTTP_CODE)
		finally:
			buf.close()
			headerBuf.close()
			c.close()
			
		fetched = FetcherOutArgs(httpCode, bufValue, headerStr)
		return fetched
	
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
		
		options = self.options
		
		#handle 301/302 redirects while also rewriting them with HTE rules
		#limit redirect depth
		for depth in range(options.redirectDepth):
			newUrl = self.idnEncodedUrl(newUrl)
			seenUrls.add(newUrl)
			
			fetched = HTTPFetcher._doFetch(newUrl, options, newUrlPlatformPath)
			
			httpCode = fetched.httpCode
			bufValue = fetched.data
			headerStr = fetched.headerStr
			
			#shitty HTTP header parsing
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
					#Not really sure fallback to first CA platform is always
					#correct, but it's expected that the platforms would be
					#same as the originating site.
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
				
			return (httpCode, bufValue)
			
		raise HTTPFetcherError("Too many redirects while fetching '%s'" % url)


def subprocessFetch():
	"""
	Used for invocation in fetcher subprocess. Reads cPickled FetcherInArgs
	from stdin and write FetcherOutArgs to stdout. Implementation of the
	subprocess URL fetch.
	"""
	outArgs = None
	
	try:
		inArgs = cPickle.load(sys.stdin)
		inArgs.check()
		outArgs = HTTPFetcher.staticFetch(inArgs.url, inArgs.options, inArgs.platformPath)
	except:
		errorStr = traceback.format_exc()
		outArgs = FetcherOutArgs(errorStr=errorStr)

	if outArgs is None:
		errorStr = traceback.format_exception_only(HTTPFetcherError,
			HTTPFetcherError("Subprocess logic error - no output args"))
		outArgs = FetcherOutArgs(errorStr=errorStr)
	
	try:
		cPickle.dump(outArgs, sys.stdout)
	except:
		cPickle.dump(None, sys.stdout) #catch-all case
