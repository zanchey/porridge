"""Functions for My Health Record-compatible signature creation and verification."""

# My Health Record Organisational Audit Tool (Porridge) - My Health Record-compatible signature creation and verification

# Copyright © 2020 David Adam <mail@davidadam.com.au>
#
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
#
# Derived from Zeep's MemorySignature module.
#
# This file incorporates work covered by the following copyright and permission notice:
# Copyright (c) 2016-2017 Michael van Tellingen
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from lxml import etree
from lxml.etree import QName
from lxml.builder import ElementMaker

from zeep.exceptions import SignatureVerificationFailed
from zeep.utils import detect_soap_env
from zeep.wsse.utils import get_unique_id

from zeep.wsdl.utils import get_or_create_header
from zeep.wsse.signature import _make_sign_key, _make_verify_key

import xmlsec
import os

NSMAP = {
    "h": "http://ns.electronichealth.net.au/pcehr/xsd/common/CommonCoreElements/1.0",
    "xml": "http://www.w3.org/XML/1998/namespace",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}
NehtaHeader = ElementMaker(namespace=NSMAP["h"], nsmap=NSMAP)
ID_ATTR = "{http://www.w3.org/XML/1998/namespace}id"


def get_nehta_signature_header(header):
    """Return the NEHTA signature header. If the header doesn't exist it will be
    created.

    """
    signature = header.find("h:signature", namespaces=NSMAP)
    if signature is None:
        signature = NehtaHeader.signature()
        header.append(signature)
    return signature


class NehtaXMLSignature(object):
    """Sign given SOAP envelope with XML signature using given xmlsec.Key object
    as specified in the PCEHR View Service Technical Service Specification 1.7 and
    AS 5551-2015 (E-health XML secured payload profiles).

    """

    def __init__(self, key):
        if not isinstance(key, xmlsec.Key):
            raise TypeError("key not an instance of xmlsec.Key")
        self.key = key

        # For debugging/NOC validation use
        # Done here rather than as a Zeep plugin as plugins are run before WSSE, so the
        # plugin only ever sees the unsigned version
        if "MHR_LOG" in os.environ:
            self.egress_file = open(os.environ["MHR_LOG"] + "-request.xml", "wb")
            self.ingress_file = open(os.environ["MHR_LOG"] + "-response.xml", "wb")
        else:
            self.egress_file = None
            self.ingress_file = None

    def apply(self, envelope, headers):
        _sign_envelope_with_key(envelope, self.key)
        if self.egress_file:
            self.egress_file.write(etree.tostring(envelope, pretty_print=True))
        return envelope, headers

    def verify(self, envelope):
        # Don't verify the envelope for now; it is not required by the standards,
        # the whole exchange is protected by TLS anyway, and there is no way of
        # confirming the assertion of identity.
        if self.ingress_file:
            self.ingress_file.write(etree.tostring(envelope, pretty_print=True))
        return envelope

        _verify_envelope_with_key(envelope, self.key)
        return envelope


def _sign_envelope_with_key(envelope, key):
    """Prepare envelope and sign."""
    soap_env = detect_soap_env(envelope)

    # Create the Signature node.
    signature = xmlsec.template.create(
        envelope, xmlsec.Transform.EXCL_C14N, xmlsec.Transform.RSA_SHA1
    )

    # Add a KeyInfo node with X509Data child to the Signature. XMLSec will fill
    # in this template with the actual certificate details when it signs.
    key_info = xmlsec.template.ensure_key_info(signature)
    x509_data = xmlsec.template.add_x509_data(key_info)
    xmlsec.template.x509_data_add_issuer_serial(x509_data)
    xmlsec.template.x509_data_add_certificate(x509_data)

    # Insert the Signature node in the NehtaSignature header.
    header = get_or_create_header(envelope)
    sig_header = get_nehta_signature_header(header)
    sig_header.insert(0, signature)

    # Perform the actual signing.
    ctx = xmlsec.SignatureContext()
    ctx.key = key

    # Sign the body of the request: requirement VIEW-T 34
    _sign_node(ctx, signature, envelope.find(QName(soap_env, "Body")))
    # Sign the PCEHR header: requirement VIEW-T 36
    _sign_node(ctx, signature, header.find("h:PCEHRHeader", NSMAP))
    # Sign the timestamp: requirement VIEW-T 38
    _sign_node(ctx, signature, header.find("h:timestamp", NSMAP))
    ctx.sign(signature)


def _verify_envelope_with_key(envelope, key):
    soap_env = detect_soap_env(envelope)

    header = envelope.find(QName(soap_env, "Header"))
    if header is None:
        raise SignatureVerificationFailed

    signature = header.find("h:signature/ds:Signature", NSMAP)
    if signature is None:
        raise SignatureVerificationFailed
    xmlsec.enable_debug_trace(True)

    ctx = xmlsec.SignatureContext()

    # xmlsec finds the right identifiers by default
    # Find each signed element and register its ID with the signing context.
    # refs = signature.findall('ds:SignedInfo/ds:Reference', NSMAP)
    # for ref in refs:
    #    # Get the reference URI and cut off the initial '#'
    #    referenced_id = ref.get('URI')[1:]
    #    referenced = envelope.xpath(
    #        "//*[@xml:id='%s']" % referenced_id,
    #        namespaces=NSMAP,
    #    )[0]
    # ctx.register_id(referenced, 'id', NSMAP['xml'])

    ctx.key = key

    try:
        ctx.verify(signature)
    except xmlsec.Error:
        # Sadly xmlsec gives us no details about the reason for the failure, so
        # we have nothing to pass on except that verification failed.
        raise SignatureVerificationFailed


def ensure_id(node):
    """Ensure given node has an xml:id attribute; add unique one if not.
    Return found/created attribute value.
    """
    assert node is not None
    id_val = node.get(ID_ATTR)
    if not id_val:
        id_val = get_unique_id()
        node.set(ID_ATTR, id_val)
    return id_val


def _sign_node(ctx, signature, target):
    """Add sig for ``target`` in ``signature`` node, using ``ctx`` context.

    Doesn't actually perform the signing; ``ctx.sign(signature)`` should be
    called later to do that.

    Adds a Reference node to the signature with URI attribute pointing to the
    target node, and registers the target node's ID so XMLSec will be able to
    find the target node by ID when it signs.

    """

    # Ensure the target node has an xml:Id attribute and get its value.
    node_id = ensure_id(target)

    # xmlsec uses the xml:id attribute by default, so there's no need to register it

    # Add reference to signature with URI attribute pointing to that ID.
    ref = xmlsec.template.add_reference(
        signature, xmlsec.Transform.SHA1, uri="#" + node_id
    )
    # This is an XML normalization transform which will be performed on the
    # target node contents before signing. This ensures that changes to
    # irrelevant whitespace, attribute ordering, etc won't invalidate the
    # signature.
    xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)
