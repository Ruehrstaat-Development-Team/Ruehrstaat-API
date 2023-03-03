from .status_responses import error_400, error_401, error_403, error_404

class ValidationException(Exception):
    def __init__(self, errorNumber=None):
        self.response = error_400(errorNumber)

class Validation400Exception(ValidationException):
    def __init__(self, errorNumber=None):
        self.response = error_400(errorNumber)

class Validation401Exception(ValidationException):
    def __init__(self, errorNumber=None):
        self.response = error_401(errorNumber)

class Validation403Exception(ValidationException):
    def __init__(self, errorNumber=None):
        self.response = error_403(errorNumber)

class Validation404Exception(ValidationException):
    def __init__(self, errorNumber=None):
        self.response = error_404(errorNumber)