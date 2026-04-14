"""
Módulo de auditoría y logging estructurado.
Registra cada operación en archivo de logs y base de datos.
"""
import logging
import sqlite3
from datetime import datetime
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from config import LOG_FILE, LOG_LEVEL, LOG_FORMAT, LOG_DATE_FORMAT, DATABASE_PATH


class AuditLogger:
    """
    Gestiona logging estructurado a archivo y base de datos.
    
    Cada evento importante se registra en:
    1. Archivo de logs rotativo (`audit.log`)
    2. Tabla `auditoria` en la BD SQLite
    """

    def __init__(self):
        """Inicializa el logger con configuración estructurada."""
        self.logger = self._setup_file_logger()

    def _setup_file_logger(self) -> logging.Logger:
        """Configura logger a archivo con rotación."""
        logger = logging.getLogger("AuditLogger")
        logger.setLevel(LOG_LEVEL)

        # Evitar duplicados si ya existe handler
        if logger.handlers:
            return logger

        # Handler a archivo
        file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
        file_handler.setLevel(LOG_LEVEL)

        formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
        file_handler.setFormatter(formatter)

        logger.addHandler(file_handler)

        # También imprimir en consola para debugging
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        return logger

    @contextmanager
    def _get_db_connection(self):
        """Gestor de contexto para conexiones a BD."""
        conn = sqlite3.connect(DATABASE_PATH)
        try:
            yield conn
        finally:
            conn.close()

    def log_login(self, user_id: str, success: bool, reason: str = ""):
        """
        Registra intento de inicio de sesión.
        
        Args:
            user_id: ID del usuario que intenta iniciar sesión
            success: True si fue exitoso, False si falló
            reason: Razón del fallo (contraseña incorrecta, usuario no existe, etc.)
        """
        status = "✅ ÉXITO" if success else "❌ FALLO"
        message = f"Login {status} para usuario: {user_id}"
        if reason:
            message += f" ({reason})"

        self.logger.info(message)
        self._insert_audit_record(user_id, "LOGIN", success, reason)

    def log_user_creation(self, created_by: str, new_user_id: str, rol: str):
        """
        Registra creación de nuevo usuario.
        
        Args:
            created_by: ID del admin que crea el usuario
            new_user_id: ID del nuevo usuario
            rol: Rol asignado al nuevo usuario
        """
        message = f"usuario creado por {created_by}: {new_user_id} (rol: {rol})"
        self.logger.info(f"🆕 Nuevo {message}")
        self._insert_audit_record(created_by, f"CREATE_USER:{new_user_id}", True, f"rol={rol}")

    def log_password_change(self, user_id: str, changed_by: str):
        """Registra cambio de contraseña."""
        message = f"Cambio de contraseña para {user_id}"
        if changed_by and changed_by != user_id:
            message += f" (requerido por {changed_by})"
        self.logger.info(f"🔐 {message}")
        self._insert_audit_record(changed_by, f"CHANGE_PASSWORD:{user_id}", True)

    def log_data_access(self, user_id: str, rol: str, action: str, details: str = ""):
        """
        Registra acceso a datos.
        
        Args:
            user_id: Usuario que accede
            rol: Rol del usuario
            action: Acción realizada (view_level1, view_level2, etc.)
            details: Detalles adicionales
        """
        message = f"[{rol}] {action}"
        if details:
            message += f" - {details}"
        self.logger.info(f"📊 Acceso a datos por {user_id}: {message}")
        self._insert_audit_record(user_id, action, True, details)

    def log_error(self, user_id: str, action: str, error_type: str, message: str):
        """
        Registra error de seguridad o operación.
        
        Args:
            user_id: Usuario asociado (puede ser "SISTEMA" para errores sistémicos)
            action: Acción que causó el error
            error_type: Tipo de error
            message: Descripción del error
        """
        log_message = f"❌ ERROR [{error_type}] durante {action}: {message}"
        self.logger.error(log_message)
        self._insert_audit_record(user_id, action, False, f"ERROR:{error_type}:{message}")

    def log_encryption_operation(self, operation: str, user_id: str = "SISTEMA", success: bool = True):
        """
        Registra operaciones de encriptación.
        
        Args:
            operation: Tipo de operación (derive_keys, encrypt_data, decrypt_data)
            user_id: Usuario responsable
            success: Resultado de la operación
        """
        status = "✅" if success else "❌"
        self.logger.info(f"{status} Operación criptográfica: {operation}")
        self._insert_audit_record(user_id, f"CRYPTO:{operation}", success)

    def log_key_usage(
        self,
        used_by: str,
        key_name: str,
        version: int,
        action: str,
        details: str = ""
        ):
        message = f"🔑 KEY_USE usuario={used_by} clave={key_name} v{version} acción={action}"
        if details:
            message += f" - {details}"

        self.logger.info(message)
        self._insert_audit_record(
            used_by,
            f"KEY_USE:{key_name}:v{version}:{action}",
            True,
            details
        )

    def log_certificate_event(
        self,
        actor_id: str,
        target_user_id: str,
        certificate_id: str,
        event: str,
        details: str = ""
    ):
        message = (
            f"📜 CERT {event} usuario={target_user_id} "
            f"certificado={certificate_id}"
        )
        if details:
            message += f" - {details}"

        self.logger.info(message)
        self._insert_audit_record(
            actor_id,
            f"CERT:{event}:{target_user_id}",
            True,
            f"certificate_id={certificate_id}; {details}"
        )
        

    def _insert_audit_record(
        self,
        user_id: str,
        action: str,
        success: bool,
        details: str = ""
    ):
        """Inserta registro en tabla de auditoría en la BD."""
        try:
            with self._get_db_connection() as conn:
                c = conn.cursor()
                timestamp = datetime.now().isoformat()
                c.execute(
                    """
                    INSERT INTO auditoria (id_usuario, accion, resultado, detalles, fecha)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (user_id, action, "éxito" if success else "fallo", details, timestamp)
                )
                conn.commit()
        except sqlite3.Error as e:
            self.logger.error(f"Error al escribir auditoría en BD: {e}")

    def get_audit_trail(self, user_id: Optional[str] = None, limit: int = 50):
        """
        Obtiene registro de auditoría.
        
        Args:
            user_id: Filtrar por usuario (None = todos)
            limit: Número máximo de registros
            
        Returns:
            Lista de registros de auditoría
        """
        try:
            with self._get_db_connection() as conn:
                c = conn.cursor()
                if user_id:
                    c.execute(
                        "SELECT * FROM auditoria WHERE id_usuario = ? ORDER BY fecha DESC LIMIT ?",
                        (user_id, limit)
                    )
                else:
                    c.execute(
                        "SELECT * FROM auditoria ORDER BY fecha DESC LIMIT ?",
                        (limit,)
                    )
                return c.fetchall()
        except sqlite3.Error as e:
            self.logger.error(f"Error al leer auditoría: {e}")
            return []


# Instancia global del logger
audit_logger = AuditLogger()


