import hmac

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from .client import HMACAuthenticator
from rest_framework_hmac.hmac_key.models import HMACKey



class HMACAuthentication(BaseAuthentication):

    def authenticate(self, request):

        signature = self.get_signature(request)
        hmac_obj = self.get_hmac_object(request)
        b64 = HMACAuthenticator(hmac_obj).calc_signature(request)
        if not hmac.compare_digest(b64, signature):
            raise AuthenticationFailed()
                
        return (hmac_obj.user, None)


    @staticmethod
    def get_hmac_object(request):
        hmac_key = request.META['HTTP_KEY']
        try:
            return HMACKey.objects.get(key=hmac_key)
        except (KeyError, HMACKey.DoesNotExist):
            raise AuthenticationFailed()


    @staticmethod
    def get_signature(request):
        try:
            signature = bytes(request.META['HTTP_SIGNATURE'], 'utf-8')
        except KeyError:
            raise AuthenticationFailed()

        if not isinstance(signature, bytes):
            raise AuthenticationFailed()

        return signature
