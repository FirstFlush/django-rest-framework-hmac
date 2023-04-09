import base64
import hashlib
import hmac
import json

from rest_framework_hmac.hmac_key.models import HMACKey


class BaseHMAC(object):
    """
    Base class for HMAC Client cryptographic signing. Use
    this class if the programmer wants to implement thier
    own lookup for the HMAC `secret` cryptographic key
    """
    def __init__(self, hmac_obj:HMACKey):
        self.secret = hmac_obj.secret
        self.key    = hmac_obj.key


    def _calc_signature_from_str(self, string_to_sign):
        byte_key = bytes.fromhex(self.secret)
        lhmac = hmac.new(byte_key, digestmod=hashlib.sha256)
        lhmac.update(string_to_sign.encode('utf8'))
        return base64.b64encode(lhmac.digest())



class HMACAuthenticator(BaseHMAC):
    """
    Concrete class for HMACAuthenticator cryptographic signing.
    Use this class if the programmer has registered the HMACKey
    Model to be created via a signal
    """
    def calc_signature(self, request):
        """
        Calculates the HMAC Signature based upon the headers and data
        """
        string_to_sign = self.string_to_sign(request)
        signature = self._calc_signature_from_str(string_to_sign)
        return signature


    def string_to_sign(self, request):
        """
        Calcuates the string to sign using the HMAC secret
        """
        string_to_sign = ''
        # Don't add in case of a 'GET' request
        if getattr(request, 'data', None):
            string_to_sign += json.dumps(request.data, separators=(',', ':'))
        return string_to_sign



class HMACSigner(BaseHMAC):
    """
    Conveince class for signing HMAC request Signatures
    using a `dict` instead of a `request`, which is what
    `HMACAuthenticator` relies on for calculating the HMAC
    Signatures
    """
    def __init__(self, hmac_obj:HMACKey, data:dict):
        self.data = data
        super(HMACSigner, self).__init__(hmac_obj)


    def _calc_signature(self):
        """Calculates the HMAC Signature based upon the headers and data"""
        string_to_sign = self._string_to_sign()
        signature = self._calc_signature_from_str(string_to_sign)

        return signature


    def _string_to_sign(self):
        """Calcuates the string to sign using the HMAC secret"""
        string_to_sign = ''
        if self.data:
            string_to_sign += json.dumps(self.data, separators=(',', ':'))

        return string_to_sign


    def add_hmac_headers(self, headers:dict):
        """Sign outgoing requests and add the signature/key to the HMAC headers.
        
        Important: The key is not used to create the signature. The key is merely 
        used as a reference to look up the "secret" value, which is used to sign requests.
        """
        signature = self._calc_signature()
        hmac_headers = {
            'KEY': self.key,
            'SIGNATURE': signature,
        }
        new_headers = headers | hmac_headers

        return new_headers
