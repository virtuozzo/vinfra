import sys

# pylint: disable=no-name-in-module,import-error,unused-import,redefined-builtin,invalid-name

if sys.version_info[0] == 2:
    from urlparse import urlparse
    from urllib2 import urlopen, addinfourl
    from httplib import HTTPResponse
    from urllib import urlencode

    basestring = basestring
    PLATFORM_LINUX = 'linux2'

elif sys.version_info[0] == 3:
    from urllib.parse import urlparse, urlencode
    from urllib.request import urlopen, addinfourl
    from http.client import HTTPResponse

    basestring = str
    PLATFORM_LINUX = 'linux'
