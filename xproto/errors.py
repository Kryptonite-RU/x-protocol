class Error(Exception):
    pass

class UsrIDError(Error):
    pass

class SrcIDError(Error):
    pass

class InspIDError(Error):
    pass

class CertificateError(Error):
    pass

class UsrLoadError(Error):
    pass

class SrcLoadError(Error):
    pass

class InspLoadError(Error):
    pass

class AuthLoadError(Error):
    pass
