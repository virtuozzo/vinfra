import ipaddress
import json
import sys


# pylint: disable=no-name-in-module,import-error,unused-import,redefined-builtin,invalid-name

if sys.version_info[0] == 2:
    from urlparse import parse_qs, urlparse
    from urllib2 import urlopen
    import cookielib

    def get_ipaddress_version(ipstr):
        return ipaddress.ip_address(unicode(ipstr)).version

    basestring = basestring
    PLATFORM_LINUX = 'linux2'

elif sys.version_info[0] == 3:
    from urllib.parse import parse_qs, urlparse
    from urllib.request import urlopen
    from http import cookiejar as cookielib

    def get_ipaddress_version(ipstr):
        return ipaddress.ip_address(ipstr).version

    basestring = str
    PLATFORM_LINUX = 'linux'

JSONDecodeError = ValueError
try:
    # python3
    JSONDecodeError = json.decoder.JSONDecodeError
except AttributeError:
    pass

try:
    # python2 is fine
    long = long
except NameError:
    # python3 has no long
    long = int
