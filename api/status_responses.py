from rest_framework.response import Response
from rest_framework import status

from django.conf import settings

def error_400(exception_number):
    """400 Bad Request
    :param exception_number: The number of the exception as int, see below:
    1 - No carrier id provided
    2 - No carrier id or callsign provided
    3 - Invalid carrier id provided, to create a carrier please use POST request
    4 - No type provided
    5 - Invalid type provided
    6 - No body provided
    7 - No access provided
    8 - No previous location found
    9 - No operation provided
    10 - No service provided
    11 - Carrier id provided, use PUT request to edit carrier
    12 - Invalid access provided
    13 - Invalid operation provided
    """
    data = {}
    match exception_number:
        case 1:
            data["error"] = "No carrier id provided"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=no-carrier-id-provided"
        case 2:
            data["error"] = "No carrier id or callsign provided"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=no-carrier-id-or-callsign-provided"
        case 3:
            data["error"] = "Invalid carrier id provided, to create a carrier please use POST request"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=invalid-carrier-id-provided-to-create-a-carrier-please-use-post-request"
        case 4:
            data["error"] = "No type provided"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=no-type-provided"
        case 5:
            data["error"] = "Invalid type provided"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=invalid-type-provided"
        case 6:
            data["error"] = "No body provided"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=no-body-provided"
        case 7:
            data["error"] = "No access provided"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=no-access-provided"
        case 8:
            data["error"] = "No previous location found"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=no-previous-location-found"
        case 9:
            data["error"] = "No operation provided"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=no-operation-provided"
        case 10:
            data["error"] = "No service provided"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=no-service-provided"
        case 11:
            data["error"] = "Carrier id provided, use PUT request to edit carrier"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=carrier-id-provided-use-put-request-to-edit-carrier"
        case 12:
            data["error"] = "Invalid access provided"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=invalid-access-provided"
        case 13:
            data["error"] = "Invalid operation provided"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=invalid-operation-provided"
        case _:
            data["error"] = "Unknown error"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=_400-bad-request"
    return Response(data, status=status.HTTP_400_BAD_REQUEST)

def error_401(exception_number):
    """
    401 Unauthorized
    :param exception_number: The number of the exception as int, see below:
    1 - Carrier not allowed
    2 - No read access
    3 - Not allowed to create new carriers
    """
    data = {}
    match exception_number:
        case 1:
            data["error"] = "Carrier not allowed"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=carrier-not-allowed"
        case 2:
            data["error"] = "No read access"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=no-read-access"
        case 3:
            data["error"] = "Not allowed to create new carriers"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=not-allowed-to-create-new-carriers"
        case _:
            data["error"] = "Unknown error"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=_401-unauthorized"
    return Response(data, status=status.HTTP_401_UNAUTHORIZED)

def error_403(exception_number):
    """
    403 Forbidden
    :param exception_number: The number of the exception as int, see below:
    1 - Authentication credentials were not provided.
    """
    data = {}
    match exception_number:
        case 1:
            data["error"] = "Authentication credentials were not provided."
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=authentication-credentials-were-not-provided"
        case _:
            data["error"] = "Unknown error"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=_403-forbidden"
    return Response(data, status=status.HTTP_403_FORBIDDEN)

def error_404(exception_number):
    """
    404 Not Found
    :param exception_number: The number of the exception as int, see below:
    1 - Invalid carrier id provided
    2 - Invalid carrier service provided
    """
    data = {}
    match exception_number:
        case 1:
            data["error"] = "Invalid carrier id provided"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=invalid-carrier-id-provided"
        case 2:
            data["error"] = "Invalid carrier service provided"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=invalid-carrier-service-provided"
        case _:
            data["error"] = "Unknown error"
            data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=_404-not-found"
    return Response(data, status=status.HTTP_404_NOT_FOUND)

def status_200(message):
    """
    200 OK
    :param message: The message to return
    """
    data = {}
    data["success"] = message
    data["reference"] = settings.WEBAPP_DOCUMENTATION_URL + "/#/api/errors/?id=_2xx-success"
    return Response(data, status=status.HTTP_200_OK)
