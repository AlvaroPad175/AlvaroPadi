"""
Tests para gestión de usuarios.
"""
import pytest
import sys
from pathlib import Path
import sqlite3
import tempfile

# Agregar src al path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from user_manager import UserManager, PasswordValidator, DataValidator
from exceptions import (
    UserAlreadyExistsError,
    WeakPasswordError,
    InvalidCredentialsError,
    UserNotFoundError,
)


class TestUserManager:
    """Tests para gestión de usuarios."""

    @pytest.fixture
    def temp_db(self):
        """Proporciona BD temporal para tests."""
        # Crear DB temporal
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name

        # Reemplazar ruta en config
        import config
        original_path = config.DATABASE_PATH
        config.DATABASE_PATH = db_path

        yield db_path

        # Limpiar
        import os
        os.remove(db_path)
        config.DATABASE_PATH = original_path

    def test_create_user_success(self, temp_db):
        """Crear usuario con datos válidos."""
        um = UserManager()
        result = um.create_user(
            "usuario_test",
            "PassWord@2024!",
            "analista",
            "SISTEMA",
        )
        assert result is True

    def test_create_user_duplicate(self, temp_db):
        """No se pueden crear usuarios duplicados."""
        um = UserManager()
        um.create_user("usuario_test", "PassWord@2024!", "analista", "SISTEMA")

        with pytest.raises(UserAlreadyExistsError):
            um.create_user("usuario_test", "Other@2024!", "admin", "SISTEMA")

    def test_create_user_weak_password(self, temp_db):
        """Contraseña débil es rechazada."""
        um = UserManager()
        with pytest.raises(WeakPasswordError):
            um.create_user("usuario_test", "weak", "analista", "SISTEMA")

    def test_authenticate_success(self, temp_db):
        """Autenticación exitosa devuelve rol."""
        um = UserManager()
        um.create_user("usuario_test", "PassWord@2024!", "analista", "SISTEMA")

        success, rol = um.authenticate("usuario_test", "PassWord@2024!")
        assert success is True
        assert rol == "analista"

    def test_authenticate_wrong_password(self, temp_db):
        """Contraseña incorrecta falla."""
        um = UserManager()
        um.create_user("usuario_test", "PassWord@2024!", "analista", "SISTEMA")

        with pytest.raises(InvalidCredentialsError):
            um.authenticate("usuario_test", "WrongPassWord@2024!")

    def test_authenticate_user_not_found(self, temp_db):
        """Usuario no existente falla."""
        um = UserManager()
        with pytest.raises(InvalidCredentialsError):
            um.authenticate("no_existe", "PassWord@2024!")

    def test_change_password(self, temp_db):
        """Cambiar contraseña con contraseña actual válida."""
        um = UserManager()
        um.create_user("usuario_test", "OldPass@2024!", "analista", "SISTEMA")

        # Cambiar contraseña
        result = um.change_password(
            "usuario_test",
            "OldPass@2024!",
            "NewPass@2024!",
        )
        assert result is True

        # Verificar que la nueva funciona
        success, rol = um.authenticate("usuario_test", "NewPass@2024!")
        assert success is True

    def test_change_password_wrong_old(self, temp_db):
        """Cambiar contraseña con contraseña vieja incorrecta falla."""
        um = UserManager()
        um.create_user("usuario_test", "OldPass@2024!", "analista", "SISTEMA")

        with pytest.raises(InvalidCredentialsError):
            um.change_password("usuario_test", "WrongOld@2024!", "NewPass@2024!")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
