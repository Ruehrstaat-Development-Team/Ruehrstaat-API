from django.conf import settings # import the settings file

def webapp_version(request):
    # return the value you want as a dictionnary. you may add multiple values in there.
    return {'WEBAPP_VERSION': settings.WEBAPP_VERSION}

def webapp_name(request):
    # return the value you want as a dictionnary. you may add multiple values in there.
    return {'WEBAPP_NAME': settings.WEBAPP_NAME}

def webapp_branch(request):
    # return the value you want as a dictionnary. you may add multiple values in there.
    return {'WEBAPP_BRANCH': settings.WEBAPP_BRANCH}