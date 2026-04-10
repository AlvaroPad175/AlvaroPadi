"""
Tests para operaciones criptográficas.
"""
import pytest
import sys
from pathlib import Path

# Agregar src al path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from crypto_security import KeyDerivationManager, CryptoManager
from exceptions import DecryptionError, EncryptionError


class TestKeyDerivation:
    """Tests para derivación de claves."""

    def test_derive_key_deterministic(self):
        """Derivación con mismo salt produce misma clave."""
        master_password = "MiContraseña@2024!"
        salt = b"fixed_salt_for_test_32bytes_long"

        key1, _ = KeyDerivationManager.derive_key(master_password, salt=salt)
        key2, _ = KeyDerivationManager.derive_key(master_password, salt=salt)

        assert key1 == key2

    def test_derive_key_different_passwords(self):
        """Contraseñas diferentes producen claves diferentes."""
        salt = b"fixed_salt_for_test_32bytes_long"

        key1, _ = KeyDerivationManager.derive_key("Password1@2024", salt=salt)
        key2, _ = KeyDerivationManager.derive_key("Password2@2024", salt=salt)

        assert key1 != key2

    def test_derive_key_different_salts(self):
        """Salts diferentes producen claves diferentes."""
        master_password = "SamePassword@2024"
        salt1 = b"salt1_32bytes____________long!!"
        salt2 = b"salt2_32bytes____________long!!"

        key1, _ = KeyDerivationManager.derive_key(master_password, salt=salt1)
        key2, _ = KeyDerivationManager.derive_key(master_password, salt=salt2)

        assert key1 != key2

    def test_derive_key_generates_salt(self):
        """Si no se proporciona salt, genera uno."""
        master_password = "Password@2024!"
        key1, salt1 = KeyDerivationManager.derive_key(master_password)
        key2, salt2 = KeyDerivationManager.derive_key(master_password)

        # Claves diferentes (porque salts diferentes)
        assert key1 != key2
        assert salt1 != salt2


class TestCryptoManager:
    """Tests para operaciones de encriptación."""

    @pytest.fixture
    def crypto(self):
        """Proporciona instancia de CryptoManager para tests."""
        return CryptoManager(master_password="TestPassword@2024!")

    def test_encrypt_decrypt_roundtrip(self, crypto):
        """Encriptar y desencriptar recupera el valor original."""
        key = crypto.get_or_create_key("test_key")
        original = "Datos sensibles para encriptar"

        encrypted = crypto.encrypt_value(original, key)
        decrypted = crypto.decrypt_value(encrypted, key)

        assert decrypted == original

    def test_encrypt_none_value(self, crypto):
        """Encriptar None devuelve None."""
        key = crypto.get_or_create_key("test_key")
        encrypted = crypto.encrypt_value(None, key)
        assert encrypted is None

    def test_encrypt_different_values_different_ciphertexts(self, crypto):
        """Dos valores iguales producen ciphertexts diferentes (por nonce aleatorio)."""
        key = crypto.get_or_create_key("test_key")
        value = "Mismo valor"

        encrypted1 = crypto.encrypt_value(value, key)
        encrypted2 = crypto.encrypt_value(value, key)

        assert encrypted1 != encrypted2  # Diferentes nonces

    def test_decrypt_invalid_ciphertext(self, crypto):
        """Desencriptar ciphertext corrupto levanta error."""
        key = crypto.get_or_create_key("test_key")
        invalid_ciphertext = "aW52YWxpZA=="  # base64("invalid")

        with pytest.raises(DecryptionError):
            crypto.decrypt_value(invalid_ciphertext, key)

    def test_decrypt_with_wrong_key(self, crypto):
        """Desencriptar con clave incorrecta levanta error."""
        key1 = crypto.get_or_create_key("key1")
        key2 = crypto.get_or_create_key("key2")

        encrypted = crypto.encrypt_value("Datos secretos", key1)

        with pytest.raises(DecryptionError):
            crypto.decrypt_value(encrypted, key2)

    def test_get_or_create_key_consistent(self, crypto):
        """Obtener misma clave devuelve valor consistente."""
        key1 = crypto.get_or_create_key("my_key")
        key2 = crypto.get_or_create_key("my_key")

        assert key1 == key2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
