#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests

from requests.packages.urllib3.contrib import pyopenssl as reqs


def https_cert_subject_alt_names(host, port):
    """Read subject domains in https cert from remote server"""

    x509 = reqs.OpenSSL.crypto.load_certificate(
        reqs.OpenSSL.crypto.FILETYPE_PEM,
        reqs.ssl.get_server_certificate((host, port))
    )
    return reqs.get_subj_alt_name(x509)

if __name__ == '__main__':
    domains = https_cert_subject_alt_names("www.yahoo.com", 443)
    print(domains)