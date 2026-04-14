"""
Excepciones customizadas para el sistema de seguridad criptográfico.
"""


class SecurityException(Exception):
    """Excepción base para errores de seguridad."""
    pass


class InvalidCredentialsError(SecurityException):
    """Credenciales inválidas (usuario no existe o contraseña incorrecta)."""
    pass


class WeakPasswordError(SecurityException):
    """Contraseña no cumple con los requisitos de seguridad."""
    pass


class UserNotFoundError(SecurityException):
    """Usuario no encontrado en la base de datos."""
    pass


class UserAlreadyExistsError(SecurityException):
    """El usuario ya existe en la base de datos."""
    pass


class PermissionDeniedError(SecurityException):
    """El usuario no tiene permisos para realizar esta acción."""
    pass


class InvalidDataError(SecurityException):
    """Los datos proporcionados no son válidos."""
    pass


class EncryptionError(SecurityException):
    """Error durante operación de encriptación."""
    pass


class DecryptionError(SecurityException):
    """Error durante operación de desencriptación."""
    pass


class ConfigurationError(SecurityException):
    """Error en la configuración del sistema."""
    pass


class RateLimitExceededError(SecurityException):
    """Se ha excedido el límite de intentos."""
    pass

class CertificateError(SecurityException):
    """Error relacionado con certificados de usuario."""
    pass

class KeyManagementError(SecurityException):
    """Error relacionado con gestión y rotación de claves."""
    pass
