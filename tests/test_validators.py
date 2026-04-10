"""
Tests para validadores de contraseña y datos.
"""
import pytest
import sys
from pathlib import Path

# Agregar src al path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from user_manager import PasswordValidator, DataValidator
from exceptions import WeakPasswordError


class TestPasswordValidator:
    """Tests para validación de contraseñas."""

    def test_valid_password(self):
        """Contraseña válida cumple todos los requisitos."""
        is_valid, msg = PasswordValidator.validate("Admin@2024!Secure")
        assert is_valid is True
        assert msg == ""

    def test_too_short(self):
        """Contraseña muy corta es rechazada."""
        is_valid, msg = PasswordValidator.validate("Short1!")
        assert is_valid is False
        assert "12 caracteres" in msg

    def test_no_uppercase(self):
        """Contraseña sin mayúsculas es rechazada."""
        is_valid, msg = PasswordValidator.validate("admin@2024!secure")
        assert is_valid is False
        assert "mayúscula" in msg

    def test_no_lowercase(self):
        """Contraseña sin minúsculas es rechazada."""
        is_valid, msg = PasswordValidator.validate("ADMIN@2024!SECURE")
        assert is_valid is False
        assert "minúscula" in msg

    def test_no_digits(self):
        """Contraseña sin números es rechazada."""
        is_valid, msg = PasswordValidator.validate("Admin@Secure!")
        assert is_valid is False
        assert "número" in msg

    def test_no_special_chars(self):
        """Contraseña sin caracteres especiales es rechazada."""
        is_valid, msg = PasswordValidator.validate("Admin2024Secure")
        assert is_valid is False
        assert "especial" in msg

    def test_multiple_violations(self):
        """Contraseña con múltiples violaciones reporta todas."""
        is_valid, msg = PasswordValidator.validate("short")
        assert is_valid is False
        # Debe reportar múltiples problemas


class TestDataValidator:
    """Tests para validación de datos históricos."""

    def test_valid_age(self):
        """Edad válida (0-150)."""
        assert DataValidator.validate_age(25) is True
        assert DataValidator.validate_age("30") is True
        assert DataValidator.validate_age(0) is True
        assert DataValidator.validate_age(150) is True

    def test_invalid_age(self):
        """Edades fuera de rango son rechazadas."""
        assert DataValidator.validate_age(-1) is False
        assert DataValidator.validate_age(151) is False
        assert DataValidator.validate_age("invalid") is False

    def test_valid_country(self):
        """País válido es string no vacío."""
        assert DataValidator.validate_country("México") is True
        assert DataValidator.validate_country("Colombia") is True

    def test_invalid_country(self):
        """País inválido."""
        assert DataValidator.validate_country("") is False
        assert DataValidator.validate_country(None) is False

    def test_valid_user_id(self):
        """ID de usuario válido (3-50 caracteres alfanuméricos)."""
        assert DataValidator.validate_user_id("user123") is True
        assert DataValidator.validate_user_id("admin_master") is True
        assert DataValidator.validate_user_id("user-001") is True

    def test_invalid_user_id(self):
        """ID de usuario inválido."""
        assert DataValidator.validate_user_id("ab") is False  # Muy corto
        assert DataValidator.validate_user_id("user@name") is False  # Carácter especial
        assert DataValidator.validate_user_id("") is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
