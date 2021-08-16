# My Health Record Organisational Audit Tool (Porridge) - My Health Record connection
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

import sys, os, os.path
import requests, urllib3
from OpenSSL.crypto import load_pkcs12, X509, Error
import urllib3.contrib.pyopenssl
from urllib3.util.ssl_ import create_urllib3_context
import zeep, zeep.plugins
import xmlsec
from nehta_signature import NehtaXMLSignature
from datetime import datetime, timezone
import logging

# Required to make urllib use PyOpenSSL, which supports PKCS#12 handling
urllib3.contrib.pyopenssl.inject_into_urllib3()


class HTTPSAdapterWithContext(requests.adapters.HTTPAdapter):
    """Transport adapter with custom SSL context"""

    def __init__(self, *args, ssl_context=None, **kwargs):
        if ssl_context:
            self.ssl_context = ssl_context
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = urllib3.PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=self.ssl_context,
        )


def hpio_from_certificate(certificate):
    if not isinstance(certificate, X509):
        raise TypeError(
            "Certificate must be of type OpenSSL.crypto.X509, not", type(certificate)
        )
    subj = certificate.get_subject().get_components()
    # HPIO is in the CN, which is formatted as general.<HPI-O>.id.electronichealth.net.au
    # per DHS policy 1.20.1.1 (Certificate Policy for the digital NASH PKI Certificate for Healthcare Provider Organisations)
    hpio = [x[1].decode() for x in subj if x[0] == b"CN"][0].split(".")[1]
    orgname = [x[1] for x in subj if x[0] == b"O"][0].decode("utf-8")
    return hpio, orgname


def parse_asn1_time(time_bytes):
    return datetime.strptime(time_bytes.decode(), "%Y%m%d%H%M%SZ")


class WsaAnonymisePlugin(zeep.plugins.Plugin):
    """Plugin to force the WS-Addressing To: header to the anonymous value
    
    This is required in MHR messages per section 4.2 of the PCEHR Implementation guide
    and (apparently) ATS 5820-2010 section 2.

    Zeep defaults to setting the To: header to the remote address.
    """

    def egress(self, envelope, http_headers, operation, binding_options):
        wsa_to = envelope.find(
            "{http://www.w3.org/2003/05/soap-envelope}Header/{http://www.w3.org/2005/08/addressing}To"
        )
        wsa_to.text = "http://www.w3.org/2005/08/addressing/anonymous"

        return envelope, http_headers


class MyHealthRecordError(Exception):
    """Base class for exceptions in the My Health Record interface."""

    pass


class CertificateLoadException(MyHealthRecordError):
    """Error loading certificate files."""

    pass


class TooManyEntriesError(MyHealthRecordError):
    """Too many records were requested."""

    pass


class MyHealthRecordInterface:
    """Object to interface with My Health Record web services"""

    def __init__(self, cert_file, cert_password, config):
        self.log = logging.getLogger(__name__)

        self.config = config

        self.log.info("Loading certificate...")
        # Load the certificate
        # This is a bit of a mess at present as the certificate is required in two different formats:
        # an OpenSSL.crypto.X509 object which can be used with OpenSSL security contexts, and
        # an xmlsec.Key object.
        # cryptography is getting support for pkcs12 loading, and requests for the X509 adapter.
        with open(cert_file, "rb") as f:
            pkcs12_bytes = f.read()
            try:
                pkcs_os = load_pkcs12(pkcs12_bytes, cert_password.encode("utf-8"))
            except Error as e:  # OpenSSL.crypto.Error
                self.log.error(
                    "Could not load certificate; check the supplied password."
                )
                raise CertificateLoadException

        # SHA-1 certificates just come with a certificate and a private key
        # SHA-256 certificates come with a whole chain
        # xmlsec puts all the information about the chain into the signature but this is
        # not permitted by ATS 5821-2010, so wipe the chain and re-encode it before turning it into
        # an xmlsec object
        cert_os = pkcs_os.get_certificate()
        pkey_os = pkcs_os.get_privatekey()
        pkcs_os.set_ca_certificates(None)
        cert_xmlsec = xmlsec.Key.from_memory(
            pkcs_os.export(passphrase=None), xmlsec.KeyFormat.PKCS12_PEM, password=None
        )

        self.hpio, self.orgname = hpio_from_certificate(cert_os)
        self.log.info("Got HPI-O %s for organisation %s.", self.hpio, self.orgname)

        if parse_asn1_time(cert_os.get_notAfter()) < datetime.now():
            self.log.warn("Certificate appears to be expired.")
        if parse_asn1_time(cert_os.get_notBefore()) > datetime.now():
            self.log.warn("Certificate does not appear to be valid yet.")

        # Create a PyOpenSSL context that can be used with requests with a client certificate
        ctx = create_urllib3_context()
        ctx.set_default_verify_paths()
        ctx._ctx.use_certificate(cert_os)
        ctx._ctx.use_privatekey(pkey_os)

        # Set up a requests session object that uses this context
        s = requests.sessions.Session()
        c = HTTPSAdapterWithContext(ssl_context=ctx)
        s.mount("https://", c)

        # Create a Zeep transport that uses this requests session
        transport = zeep.transports.Transport(session=s)

        # Set up a WS-Security-like object that implements the XML signature
        wss_mhr = NehtaXMLSignature(cert_xmlsec)

        self.log.info("Loading SOAP interface...")

        self._getAuditView_client = zeep.Client(
            os.path.join(config["schema_path"], "wsdl/External/B2B_GetAuditView.wsdl"),
            transport=transport,
            wsse=wss_mhr,
            plugins=[WsaAnonymisePlugin(),],
        )
        self.log.info("Creating service...")
        serv = self._getAuditView_client.create_service(
            "{http://ns.electronichealth.net.au/pcehr/svc/GetAuditView/1.1}getAuditViewServiceSOAP12Binding",
            self.config["endpoints"]["getAuditView"],
        )
        self._getAuditView = serv.getAuditView

    def create_header(self):
        PCEHRHeader = self._getAuditView_client.get_element(
            "{http://ns.electronichealth.net.au/pcehr/xsd/common/CommonCoreElements/1.0}PCEHRHeader"
        )
        headerdict = {
            "User": {
                "IDType": "LocalSystemIdentifier",
                "ID": os.getlogin(),
                "userName": os.getlogin(),
                "useRoleForAudit": False,
            },
            "productType": {
                "productName": self.config["productName"],
                "productVersion": self.config["productVersion"],
                "vendor": self.config["vendor"],
                "platform": sys.platform,
            },
            "clientSystemType": "CIS",
            "accessingOrganisation": {
                "organisationID": self.hpio,
                "organisationName": self.orgname,
            },
        }
        return PCEHRHeader(**headerdict)

    def create_timestamp(self, timestamp=None):
        if not timestamp:
            timestamp = datetime.now(timezone.utc)
        PCEHRTimestamp = self._getAuditView_client.get_element(
            "{http://ns.electronichealth.net.au/pcehr/xsd/common/CommonCoreElements/1.0}timestamp"
        )
        return PCEHRTimestamp(created=datetime.now(timezone.utc))

    def getAuditView(self, date_from, date_to):
        self.log.info("Preparing metadata...")
        timestamp = self.create_timestamp()
        header = self.create_header()
        self.log.info(
            "Sending request for audit records from %s to %s...", date_from, date_to
        )

        try:
            av = self._getAuditView(
                date_from, date_to, _soapheaders=[header, timestamp]
            )

        except zeep.exceptions.Fault as f:
            errmessage = f.detail.find(
                "stderr:standardError/stderr:message",
                {
                    "stderr": "http://ns.electronichealth.net.au/wsp/xsd/StandardError/2010"
                },
            ).text
            self.log.error("Request failed: %s", errmessage)
            return None

        self.log.info(
            "Received response: %s %s",
            av.body.responseStatus.code,
            av.body.responseStatus.description,
        )

        if av.body.responseStatus.code == "PCEHR_ERROR_1600":
            raise TooManyEntriesError
        elif av.body.responseStatus.code == "PCEHR_SUCCESS" and av.body.auditView:
            return av.body.auditView.eventTrail
        else:
            return None
