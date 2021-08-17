#!/usr/bin/env python3

# Script to generate 500+ access requests to the My Health Record
# For testing use
# Copyright © 2020 David Adam <mail@davidadam.com.au>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import sys

sys.path.insert(0, "src")

import mhr
import requests, requests.sessions
import sys, os
import xmlsec
import zeep
from nehta_signature import NehtaXMLSignature
from requests.adapters import HTTPAdapter
from OpenSSL.crypto import load_pkcs12
from datetime import datetime, timezone
from lxml import etree
from config import mhr_config

target_ihi = open("secret/test-ihi.txt", "r").read().strip()
pkcs12_bytes = open("secret/test-fac_sign.p12", "rb",).read()
cert_password = open("secret/test-password.txt", "r").read().strip()
pkcs_os = load_pkcs12(pkcs12_bytes, cert_password.encode("utf-8"))

cert_os = pkcs_os.get_certificate()
pkey_os = pkcs_os.get_privatekey()
pkcs_os.set_ca_certificates(None)
cert_xmlsec = xmlsec.Key.from_memory(
    pkcs_os.export(passphrase=None), xmlsec.KeyFormat.PKCS12_PEM, password=None
)

hpio, orgname = mhr.hpio_from_certificate(cert_os)

import urllib3
from urllib3 import PoolManager
from urllib3.util.ssl_ import create_urllib3_context

urllib3.contrib.pyopenssl.inject_into_urllib3()

ctx = create_urllib3_context()
ctx.set_default_verify_paths()
ctx._ctx.use_certificate(cert_os)
ctx._ctx.use_privatekey(pkey_os)
# Set up a requests session object that uses this context
s = requests.sessions.Session()
c = mhr.HTTPSAdapterWithContext(ssl_context=ctx)
s.mount("https://", c)

# Create a Zeep transport that uses this requests session
transport = zeep.transports.Transport(session=s)
# Set up a WS-Security-like object that implements the XML signature
wss_mhr = NehtaXMLSignature(cert_xmlsec)

history = zeep.plugins.HistoryPlugin()

client = zeep.Client(
    "PCEHR_Schemas-20160218 v4.0.0-WithMod/wsdl/External/B2B_PCEHRProfile.wsdl",
    transport=transport,
    wsse=wss_mhr,
    plugins=[history, mhr.WsaAnonymisePlugin()],
)

serv = client.create_service(
    "{http://ns.electronichealth.net.au/pcehr/b2b/svc/PCEHRProfile/1.1}PCEHRProfileServiceSOAP12Binding",
    mhr_config["endpoints"]["gainPCEHRAccess"],
)

PCEHRHeader = client.get_element(
    "{http://ns.electronichealth.net.au/pcehr/xsd/common/CommonCoreElements/1.0}PCEHRHeader"
)

headerdict = {
    "User": {
        "IDType": "LocalSystemIdentifier",
        "ID": os.getlogin(),
        "userName": os.getlogin(),
        "useRoleForAudit": False,
    },
    "ihiNumber": target_ihi,
    "productType": {
        "productName": mhr_config["productName"],
        "productVersion": mhr_config["productVersion"],
        "vendor": mhr_config["vendor"],
        "platform": sys.platform,
    },
    "clientSystemType": "CIS",
    "accessingOrganisation": {"organisationID": hpio, "organisationName": orgname,},
}

header = PCEHRHeader(**headerdict)

PCEHRTimestamp = client.get_element(
    "{http://ns.electronichealth.net.au/pcehr/xsd/common/CommonCoreElements/1.0}timestamp"
)
timestamp = PCEHRTimestamp(created=datetime.now(timezone.utc))

record = {"authorisationDetails": {"accessType": "EmergencyAccess",}}

for i in range(500):
    print(i)
    try:
        ret = serv.gainPCEHRAccess(PCEHRRecord=record, _soapheaders=[header, timestamp])
    except zeep.exceptions.Fault as fault:
        print(etree.tostring(history.last_sent["envelope"], pretty_print=True).decode())
        print(
            etree.tostring(
                history.last_received["envelope"], pretty_print=True
            ).decode()
        )
