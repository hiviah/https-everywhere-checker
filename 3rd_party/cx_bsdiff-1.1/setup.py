"""Distutils script for bsdiff.

Windows platforms:
    python setup.py build --compiler=mingw32 install

Unix platforms
    python setup.py build install

"""

import sys

from distutils.core import setup
from distutils.extension import Extension
from distutils import sysconfig

# setup extra compilation and linking args
extraLinkArgs = ["-s"]
if sys.platform == "win32":
    import win32api
    extraLinkArgs.append("-Wl,--add-stdcall-alias")
    extraLinkArgs.append(win32api.GetModuleFileName(sys.dllhandle))

# define the list of files to be included as documentation for Windows
dataFiles = None
if sys.platform in ("win32", "cygwin"):
    baseName = "cx_bsdiff-doc"
    dataFiles = [ (baseName, [ "LICENSE.TXT", "README.TXT" ]) ]
    allFiles = []
    for fileName in open("MANIFEST").readlines():
        allFiles.append(fileName.strip())
    for dir in ["html"]:
        files = []
        for name in allFiles:
            if name.startswith(dir):
                files.append(name)
        dataFiles.append( ("%s/%s" % (baseName, dir), files) )

# setup the extension
extension = Extension(
        name = "bsdiff",
        extra_link_args = extraLinkArgs,
        sources = ["bsdiff.c"])

# perform the setup
setup(
        name = "cx_bsdiff",
        version = "1.1",
        data_files = dataFiles,
        description = "Python interface for bsdiff",
        license = "See LICENSE.txt",
        long_description = "Python interface for bsdiff",
        author = "Anthony Tuininga",
        author_email = "anthony.tuininga@gmail.com",
        url = "http://www.computronix.com/utilities.shtml",
        ext_modules = [extension])

