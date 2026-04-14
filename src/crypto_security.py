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
        self._init_key_versions_table()
        audit_logger.log_encryption_operation("init_crypto_manager", success=True)

    def _init_key_versions_table(self):
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS key_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_name TEXT NOT NULL,
            version INTEGER NOT NULL,
            salt BLOB NOT NULL,
            iterations INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            created_by TEXT NOT NULL DEFAULT 'SISTEMA',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used_at TIMESTAMP,
            last_used_by TEXT,
            UNIQUE(key_name, version)
        )
        """)
        conn.commit()
        conn.close()

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
            key_basica = self.get_or_create_key("basica", requested_by="SISTEMA")
            key_admin = self.get_or_create_key("admin", requested_by="SISTEMA") if use_admin_key else key_basica

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
            key_basica = self.get_or_create_key("basica", requested_by="SISTEMA")
            key_admin = self.get_or_create_key("admin", requested_by="SISTEMA") if use_admin_key else key_basica

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
    
    def _get_active_key_record(self, key_name: str):
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT version, salt, iterations
            FROM key_versions
            WHERE key_name = ? AND status = 'active'
            ORDER BY version DESC
            LIMIT 1
        """, (key_name,))
        row = c.fetchone()
        conn.close()
        return row

    def _touch_key_usage(self, key_name: str, version: int, used_by: str):
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        c.execute("""
            UPDATE key_versions
            SET last_used_at = CURRENT_TIMESTAMP,
                last_used_by = ?
            WHERE key_name = ? AND version = ?
        """, (used_by, key_name, version))
        conn.commit()
        conn.close()

    def get_or_create_key(self, key_name: str, key_size: int = KEY_SIZE, requested_by: str = "SISTEMA") -> bytes:
        record = self._get_active_key_record(key_name)

        if record:
            version, salt, iterations = record
            key, _ = self.key_derivation.derive_key(
                self.master_password,
                salt=salt,
                key_size=key_size,
                iterations=iterations
            )
            audit_logger.log_key_usage(requested_by, key_name, version, "load_active")
            self._touch_key_usage(key_name, version, requested_by)
            return key

        key, salt = self.key_derivation.derive_key(
            self.master_password,
            key_size=key_size
        )

        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        c.execute("""
            INSERT INTO key_versions
            (key_name, version, salt, iterations, status, created_by)
            VALUES (?, 1, ?, ?, 'active', ?)
        """, (key_name, salt, KEY_DERIVATION_ITERATIONS, requested_by))
        conn.commit()
        conn.close()

        audit_logger.log_key_usage(requested_by, key_name, 1, "create_active")
        return key

    def rotate_key(self, key_name: str, rotated_by: str = "SISTEMA") -> int:
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()

        c.execute("""
            SELECT COALESCE(MAX(version), 0)
            FROM key_versions
            WHERE key_name = ?
        """, (key_name,))
        current_max = c.fetchone()[0]
        new_version = current_max + 1

        key, salt = self.key_derivation.derive_key(
            self.master_password,
            key_size=KEY_SIZE
        )

        c.execute("""
            UPDATE key_versions
            SET status = 'inactive'
            WHERE key_name = ? AND status = 'active'
        """, (key_name,))

        c.execute("""
            INSERT INTO key_versions
            (key_name, version, salt, iterations, status, created_by)
            VALUES (?, ?, ?, ?, 'active', ?)
        """, (key_name, new_version, salt, KEY_DERIVATION_ITERATIONS, rotated_by))

        conn.commit()
        conn.close()

        audit_logger.log_key_usage(rotated_by, key_name, new_version, "rotate")
        return new_version
