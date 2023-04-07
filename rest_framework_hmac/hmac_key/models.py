import binascii
import os
import hashlib

from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _



class HMACKey(models.Model):
    """
    The default HMACKey model that can auto generate a
    key/secret for HMAC Auth via a signal
    """
    
    key = models.CharField(_("Key"), primary_key=True, max_length=40)
    secret = models.CharField(_("Secret"), max_length=40)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, related_name='hmac_key',
        on_delete=models.CASCADE, verbose_name=_("User")
    )
    created = models.DateTimeField(_("Created"), auto_now_add=True)

    class Meta:
        # Only create a DB table for this Model if this app is registered
        abstract = 'rest_framework_hmac.hmac_key' \
            not in settings.INSTALLED_APPS
        verbose_name = _("HMACKey")
        verbose_name_plural = _("HMACKey")


    def __str__(self):
        return self.key


    @staticmethod
    def generate_secret():
        """
        Returns a 40 character hex string based on binary random data
        """
        return binascii.hexlify(os.urandom(20)).decode()


    @staticmethod
    def generate_key(key):
        """Generate key by hashing the secret value. This way if the key
        is forgotten by client, it can be easily regenerated from the secret.
        """
        return hashlib.sha1(key.encode()).hexdigest()


    def save(self, *args, **kwargs):
        if self.secret is None:
            self.secret = self.generate_secret()
        if self.key is None:
            self.key = self.generate_key(self.secret)
        super(HMACKey, self).save(*args, **kwargs)