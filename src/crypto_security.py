"""
Módulo de gestión de criptografía y derivación de claves.
Implementa cifrado AES-GCM con PBKDF2 para derivación de claves.
"""
import base64
import sqlite3
from pathlib import Path
from typing import Optional, Tuple
from hashlib import pbkdf2_hmac

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

from config import (
    KEY_DERIVATION_ALGORITHM,
    KEY_DERIVATION_ITERATIONS,
    KEY_SIZE,
    PBKDF2_HASH_ALGORITHM,
    CRYPTO_MASTER_PASSWORD,
    DATABASE_PATH,
)
from exceptions import EncryptionError, DecryptionError, ConfigurationError
from audit_logger import audit_logger


class KeyDerivationManager:
    """
    Gestiona derivación de claves a partir de contraseña maestra.
    Usa PBKDF2 para derivación determinística y segura.
    """

    @staticmethod
    def derive_key(
        master_password: str,
        salt: Optional[bytes] = None,
        key_size: int = KEY_SIZE,
        iterations: int = KEY_DERIVATION_ITERATIONS,
    ) -> Tuple[bytes, bytes]:
        """
        Deriva una clave a partir de contraseña maestra usando PBKDF2.
        
        Args:
            master_password: Contraseña maestra del sistema
            salt: Salt (bytes). Si None, genera uno aleatorio
            key_size: Tamaño de la clave en bytes (default: 32 = 256 bits)
            iterations: Número de iteraciones PBKDF2
            
        Returns:
            Tupla (clave_derivada, salt_usado)
        """
        if not master_password:
            raise ConfigurationError("Contraseña maestra no configurada")

        # Generar salt si no existe
        if salt is None:
            salt = get_random_bytes(32)  # 256 bits de salt

        try:
            # Derivar clave usando PBKDF2
            key = pbkdf2_hmac(
                PBKDF2_HASH_ALGORITHM,
                master_password.encode(),
                salt,
                iterations,
                dklen=key_size,
            )
            return key, salt
        except Exception as e:
            audit_logger.log_error(
                "SISTEMA",
                "derive_key",
                "KeyDerivationError",
                str(e),
            )
            raise ConfigurationError(f"Error derivando clave: {e}")

    @staticmethod
    def store_key_metadata(key_name: str, salt: bytes, iterations: int = KEY_DERIVATION_ITERATIONS):
        """
        Almacena metadatos de la clave en la BD para recuperación.
        
        Args:
            key_name: Nombre identificador de la clave (ej: "basica", "admin")
            salt: Salt usado en la derivación
            iterations: Iteraciones PBKDF2 usadas
        """
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            c = conn.cursor()

            # Crear tabla si no existe
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS key_metadata (
                    key_name TEXT PRIMARY KEY,
                    salt BLOB NOT NULL,
                    iterations INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            # Insertar o actualizar
            c.execute(
                "INSERT OR REPLACE INTO key_metadata (key_name, salt, iterations) VALUES (?, ?, ?)",
                (key_name, salt, iterations),
            )
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            audit_logger.log_error("SISTEMA", "store_key_metadata", "DBError", str(e))
            raise ConfigurationError(f"Error almacenando metadatos de clave: {e}")

    @staticmethod
    def retrieve_key_metadata(key_name: str) -> Optional[Tuple[bytes, int]]:
        """
        Recupera metadatos de clave almacenados.
        
        Args:
            key_name: Nombre de la clave
            
        Returns:
            Tupla (salt, iterations) o None si no existe
        """
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            c = conn.cursor()
            c.execute("SELECT salt, iterations FROM key_metadata WHERE key_name = ?", (key_name,))
            result = c.fetchone()
            conn.close()
            return result
        except sqlite3.Error as e:
            audit_logger.log_error("SISTEMA", "retrieve_key_metadata", "DBError", str(e))
            return None


class CryptoManager:
    """
    Gestión de cifrado/descifrado AES-GCM con derivación PBKDF2.
    Proporciona interfaz segura para operaciones criptográficas.
    """

    def __init__(self, master_password: str = CRYPTO_MASTER_PASSWORD):
        """
        Inicializa el gestor de criptografía.
        
        Args:
            master_password: Contraseña maestra del sistema
        """
        if not master_password:
            raise ConfigurationError(
                "Contraseña maestra no configurada. "
                "Configura CRYPTO_MASTER_PASSWORD en variables de entorno"
            )
        self.master_password = master_password
        self.key_derivation = KeyDerivationManager()
        audit_logger.log_encryption_operation("init_crypto_manager", success=True)

    def get_or_create_key(self, key_name: str, key_size: int = KEY_SIZE) -> bytes:
        """
        Obtiene o crea una clave derivada.
        Si la clave existe (metadatos almacenados), usa el mismo salt para reproducibilidad.
        Si no existe, crea una nueva clave y almacena sus metadatos.
        
        Args:
            key_name: Identificador de la clave (ej: "basica", "admin")
            key_size: Tamaño de la clave en bytes
            
        Returns:
            Clave derivada (bytes)
        """
        # Intentar recuperar metadatos existentes
        metadata = self.key_derivation.retrieve_key_metadata(key_name)

        if metadata:
            # Clave existente: derivar con mismo salt
            salt, iterations = metadata
            key, _ = self.key_derivation.derive_key(
                self.master_password, salt=salt, key_size=key_size, iterations=iterations
            )
        else:
            # Nueva clave: derivar y almacenar metadatos
            key, salt = self.key_derivation.derive_key(
                self.master_password, key_size=key_size
            )
            self.key_derivation.store_key_metadata(key_name, salt)
            audit_logger.log_encryption_operation(f"create_key:{key_name}", success=True)

        return key

    def encrypt_value(self, value: str, key: bytes) -> str:
        """
        Encripta un valor usando AES-256-GCM.
        
        Args:
            value: Valor a encriptar (string)
            key: Clave de encriptación (bytes)
            
        Returns:
            Valor encriptado en base64
            
        Raises:
            EncryptionError: Si hay error durante encriptación
        """
        try:
            if not value or (isinstance(value, float) and value != value):  # NaN check
                return None

            data = str(value).encode()
            cipher = AES.new(key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(data)

            # Formato: nonce (16) + tag (16) + ciphertext
            encrypted = cipher.nonce + tag + ciphertext
            return base64.b64encode(encrypted).decode()

        except Exception as e:
            audit_logger.log_error("SISTEMA", "encrypt_value", "EncryptionError", str(e))
            raise EncryptionError(f"Error durante encriptación: {e}")

    def decrypt_value(self, encrypted_value: str, key: bytes) -> str:
        """
        Desencripta un valor encriptado con AES-256-GCM.
        
        Args:
            encrypted_value: Valor encriptado en base64
            key: Clave de desencriptación (bytes)
            
        Returns:
            Valor desencriptado (string)
            
        Raises:
            DecryptionError: Si desencriptación falla (integridad violada, tag inválido)
        """
        try:
            if not encrypted_value or encrypted_value is None:
                return None

            raw = base64.b64decode(encrypted_value)
            if len(raw) < 32:  # Mínimo: nonce (16) + tag (16)
                raise DecryptionError("Datos encriptados inválidos (muy cortos)")

            nonce = raw[:16]
            tag = raw[16:32]
            ciphertext = raw[32:]

            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            return data.decode()

        except ValueError as e:
            # ValueError es levantado si la autenticación falla
            audit_logger.log_error(
                "SISTEMA", "decrypt_value", "AuthenticationError", "Tag de autenticación inválido"
            )
            raise DecryptionError(f"Falló verificación de integridad: {e}")
        except Exception as e:
            audit_logger.log_error("SISTEMA", "decrypt_value", "DecryptionError", str(e))
            raise DecryptionError(f"Error durante desencriptación: {e}")

    def encrypt_dataframe(self, df, level1_cols: list, level2_cols: list, use_admin_key: bool = True) -> object:
        """
        Encripta columnas específicas de un DataFrame.
        
        Args:
            df: DataFrame de pandas
            level1_cols: Columnas nivel 1 (analista, clave básica)
            level2_cols: Columnas nivel 2 (admin, clave admin)
            use_admin_key: Si usar clave admin para level2
            
        Returns:
            DataFrame con columnas encriptadas
        """
        try:
            df_enc = df.copy()

            # Obtener claves
            key_basica = self.get_or_create_key("basica")
            key_admin = self.get_or_create_key("admin") if use_admin_key else key_basica

            # Encriptar nivel 1
            for col in level1_cols:
                if col in df_enc.columns:
                    df_enc[col] = df_enc[col].apply(lambda x: self.encrypt_value(x, key_basica))

            # Encriptar nivel 2
            for col in level2_cols:
                if col in df_enc.columns:
                    df_enc[col] = df_enc[col].apply(lambda x: self.encrypt_value(x, key_admin))

            audit_logger.log_encryption_operation("encrypt_dataframe", success=True)
            return df_enc

        except Exception as e:
            audit_logger.log_error("SISTEMA", "encrypt_dataframe", "EncryptionError", str(e))
            raise EncryptionError(f"Error encriptando DataFrame: {e}")

    def decrypt_dataframe(self, df, level1_cols: list = None, level2_cols: list = None, use_admin_key: bool = True) -> object:
        """
        Desencripta columnas específicas de un DataFrame.
        
        Args:
            df: DataFrame de pandas con datos encriptados
            level1_cols: Columnas nivel 1 (analista)
            level2_cols: Columnas nivel 2 (admin)
            use_admin_key: Si usar clave admin para level2
            
        Returns:
            DataFrame con columnas desencriptadas
        """
        try:
            df_dec = df.copy()

            # Obtener claves
            key_basica = self.get_or_create_key("basica")
            key_admin = self.get_or_create_key("admin") if use_admin_key else key_basica

            # Desencriptar nivel 1
            if level1_cols:
                for col in level1_cols:
                    if col in df_dec.columns:
                        df_dec[col] = df_dec[col].apply(lambda x: self.decrypt_value(x, key_basica) if x else None)

            # Desencriptar nivel 2
            if level2_cols:
                for col in level2_cols:
                    if col in df_dec.columns:
                        df_dec[col] = df_dec[col].apply(lambda x: self.decrypt_value(x, key_admin) if x else None)

            audit_logger.log_encryption_operation("decrypt_dataframe", success=True)
            return df_dec

        except Exception as e:
            audit_logger.log_error("SISTEMA", "decrypt_dataframe", "DecryptionError", str(e))
            raise DecryptionError(f"Error desencriptando DataFrame: {e}")
