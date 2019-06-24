import base64
import hashlib
import hmac
import json
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.views.generic import View
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.http import HttpResponse


@method_decorator(csrf_exempt, name='dispatch')
class DeauthView(View):

    INVALID_REQUEST_ERR = 'Invalid Request'
    DECODE_ERR = 'Could not decode payload'

    def post(self, request):
        base64_tail = '=='
        try:
            signed_request = request.POST['signed_request']
            encoded_sig, payload = signed_request.split('.')
        except (ValueError, KeyError):
            return HttpResponse(status=400, content=self.INVALID_REQUEST_ERR)

        try:
            decoded_payload = base64.urlsafe_b64decode(payload + base64_tail).decode('utf-8')
            decoded_payload = json.loads(decoded_payload)
        except (ValueError, json.JSONDecodeError):
            return HttpResponse(status=400, content=self.DECODE_ERR)

        secret = settings.SOCIAL_AUTH_FACEBOOK_SECRET
        sig = base64.urlsafe_b64decode(encoded_sig + base64_tail)
        expected_sig = hmac.new(bytes(secret, 'utf-8'), bytes(payload, 'utf-8'), hashlib.sha256)

        if not hmac.compare_digest(expected_sig.digest(), sig):
            return HttpResponse(status=400, content=self.INVALID_REQUEST_ERR)

        if 'user_id' not in decoded_payload.keys():
            return HttpResponse(status=400, content=self.INVALID_REQUEST_ERR)
        user_id = decoded_payload['user_id']
        user = User.objects.get(user_id=user_id)
        user.is_active = False
        user.save()
        return HttpResponse(status=200)


def login(request):
    return render(request, 'login.html')


@login_required
def home(request):
    return render(request, 'home.html')
