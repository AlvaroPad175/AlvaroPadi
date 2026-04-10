"""
Sistema de Gestión Segura para ONG - Módulo de Seguridad Criptográfica
"""

__version__ = "1.0.0"
__author__ = "Sistema de Seguridad ONG"

# Importar componentes principales
from .exceptions import (
    SecurityException,
    InvalidCredentialsError,
    WeakPasswordError,
    UserNotFoundError,
    PermissionDeniedError,
)
from .user_manager import UserManager, PasswordValidator, DataValidator
from .crypto_security import CryptoManager, KeyDerivationManager
from .audit_logger import audit_logger

__all__ = [
    "UserManager",
    "PasswordValidator",
    "DataValidator",
    "CryptoManager",
    "KeyDerivationManager",
    "audit_logger",
    "SecurityException",
    "InvalidCredentialsError",
    "WeakPasswordError",
    "UserNotFoundError",
    "PermissionDeniedError",
]
