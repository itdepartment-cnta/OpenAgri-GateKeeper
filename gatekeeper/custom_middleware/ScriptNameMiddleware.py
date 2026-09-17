# PARCHE CNTA
#
# Permite servir GateKeeper bajo un subdirectorio (p.ej. /gatekeeper/) del
# dominio que ya existe, en vez de exigirle un subdominio propio con su
# certificado.
#
# Copiado del equivalente de Farm Calendar, que ya se sirve asi bajo
# /farmcalendar/. El proxy manda la cabecera X-Script-Name y aqui se fija el
# prefijo, de modo que {% url %} y reverse() generen rutas correctas.
#
# Debe ir EL PRIMERO en MIDDLEWARE: el prefijo tiene que estar puesto antes de
# que cualquier otro middleware o vista genere una redireccion o renderice una
# plantilla.
from django.urls import set_script_prefix


class ScriptNameMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        script_name = request.META.get("HTTP_X_SCRIPT_NAME", "").rstrip("/")
        if script_name:
            set_script_prefix(script_name)
        return self.get_response(request)
