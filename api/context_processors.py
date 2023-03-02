from django.conf import settings # import the settings file

def webapp_documentation_url(request):
    # return the value you want as a dictionnary. you may add multiple values in there.
    return {'WEBAPP_DOCUMENTATION_URL': settings.WEBAPP_DOCUMENTATION_URL}