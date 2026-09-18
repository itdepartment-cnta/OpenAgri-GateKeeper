# views/auth_views.py

import requests

# from django import forms
from django.conf import settings
from django.http import HttpResponseRedirect
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.generic.edit import FormView

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

from django.contrib.auth import login as django_login
from rest_framework_simplejwt.tokens import RefreshToken

from aegis.forms import UserLoginForm


# PARCHE CNTA
def authenticate_user_model():
    from django.contrib.auth import get_user_model
    return get_user_model()


# PARCHE CNTA
def _emitir_tokens(user):
    """Tokens para un usuario ya identificado, sin volver a pedir contrasena.

    Replica los claims que pone authenticate_user() en aegis/services, que
    exige usuario y contrasena y por tanto no sirve cuando la identidad viene
    de una sesion ya abierta.
    """
    refresh = RefreshToken.for_user(user)
    refresh["username"] = user.username
    refresh["email"] = user.email
    refresh["first_name"] = user.first_name
    refresh["last_name"] = user.last_name
    refresh["uuid"] = str(user.uuid)
    refresh["tenant"] = str(user.tenant_id) if user.tenant_id else None
    return str(refresh.access_token), str(refresh)


# PARCHE CNTA
def _redirigir_con_tokens(next_url, access_token, refresh_token, por_defecto):
    """Monta la redireccion al post_auth del servicio con los tokens."""
    if next_url in settings.AVAILABLE_SERVICES:
        next_url = settings.AVAILABLE_SERVICES[next_url].get('post_auth')
    elif not next_url:
        next_url = por_defecto
    partes = list(urlparse(str(next_url)))
    query = parse_qs(partes[4])
    query["access_token"] = access_token
    query["refresh_token"] = refresh_token
    partes[4] = urlencode(query, doseq=True)
    return HttpResponseRedirect(urlunparse(partes))


@method_decorator(never_cache, name='dispatch')
class LoginView(FormView):
    template_name = "auth/login.html"
    form_class = UserLoginForm
    success_url = reverse_lazy('home')
    # success_url = reverse_lazy("aegis:dashboard")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["next"] = self.request.GET.get("next", "") or self.request.POST.get("next", "")
        return context

    def get(self, request, *args, **kwargs):
        # PARCHE CNTA: esto es lo que convierte a GateKeeper en un inicio de
        # sesion UNICO. Upstream mostraba el formulario siempre, asi que cada
        # servicio que redirigiera aqui volvia a pedir credenciales: entrabas
        # en SheepCare y al pulsar "Ver en Calendario" te las pedia de nuevo.
        next_url = request.GET.get("next", "")
        if request.user.is_authenticated and next_url:
            access_token, refresh_token = _emitir_tokens(request.user)
            return _redirigir_con_tokens(
                next_url, access_token, refresh_token, self.success_url
            )

        form = self.form_class()
        context = self.get_context_data(form=form)
        return self.render_to_response(context)

    def post(self, request, *args, **kwargs):
        next_url = request.POST.get("next") or request.GET.get("next", "")

        if not next_url:
            return HttpResponseRedirect(self.success_url)

        form = self.form_class(request.POST)

        if form.is_valid():
            username = form.cleaned_data["username"]
            password = form.cleaned_data["password"]
            # service_name = form.cleaned_data["service_name"]

            login_url = f"{settings.INTERNAL_GK_URL}api/login/"

            try:
                response = requests.post(
                    login_url,
                    data={"username": username, "password": password}
                )
            except requests.RequestException as e:
                form.add_error(None, f"Could not connect to Gatekeeper: {str(e)}")
                return self.render_to_response(self.get_context_data(form=form))

            if response.status_code == status.HTTP_200_OK:
                data = response.json()
                access_token = data["access"]
                refresh_token = data["refresh"]

                # Determine the redirect URL
                # PARCHE CNTA: upstream comparaba next_url con literales, uno
                # por servicio, asi que dar de alta uno nuevo obligaba a tocar
                # este fichero ademas de settings. Las ramas eran identicas
                # entre si, de modo que una busqueda en el diccionario hace lo
                # mismo y deja el alta de servicios en pura configuracion.
                # Es lo que el propio comentario de AVAILABLE_SERVICES apunta
                # como intencion.
                if next_url in settings.AVAILABLE_SERVICES:
                    next_url = settings.AVAILABLE_SERVICES[next_url].get('post_auth')
                elif not next_url:
                    next_url = self.success_url

                # Parse and update the URL with the access token
                url_parts = list(urlparse(next_url))
                query = parse_qs(url_parts[4])  # Parse the existing query string

                query["access_token"] = access_token
                query["refresh_token"] = refresh_token
                url_parts[4] = urlencode(query, doseq=True)

                # Final redirect URL with tokens
                redirect_url = urlunparse(url_parts)

                # PARCHE CNTA: abrir sesion de navegador. Upstream no la creaba
                # —solo pedia los tokens a su propia API y redirigia—, de modo
                # que la siguiente visita volvia a pedir credenciales.
                # authenticate() no vale aqui: la contrasena ya la valido la
                # API, asi que se indica el backend expresamente.
                usuario = authenticate_user_model().objects.filter(
                    username=username, status=1
                ).first() or authenticate_user_model().objects.filter(
                    email=username, status=1
                ).first()
                if usuario is not None:
                    django_login(
                        request, usuario,
                        backend='aegis.auth_backends.EmailOrUsernameModelBackend',
                    )

                return HttpResponseRedirect(redirect_url)

            else:
                form.add_error(None, "Invalid credentials")

        return self.render_to_response(self.get_context_data(form=form))


class WhoAmIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        return Response({"user": str(request.user)}, status=200)
