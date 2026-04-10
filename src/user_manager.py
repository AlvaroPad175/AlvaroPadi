"""
Módulo de gestión de usuarios y validación de contraseñas.
Implementa autenticación, registro y administración de usuarios.
"""
import sqlite3
import re
from datetime import datetime, timedelta
from typing import Optional, Tuple, List
from contextlib import contextmanager

import bcrypt

from config import (
    DATABASE_PATH,
    MIN_PASSWORD_LENGTH,
    REQUIRE_UPPERCASE,
    REQUIRE_LOWERCASE,
    REQUIRE_DIGITS,
    REQUIRE_SPECIAL_CHARS,
    SPECIAL_CHARS,
    MAX_LOGIN_ATTEMPTS,
    LOCKOUT_DURATION_MINUTES,
    ROLES,
)
from exceptions import (
    InvalidCredentialsError,
    WeakPasswordError,
    UserNotFoundError,
    UserAlreadyExistsError,
    PermissionDeniedError,
    InvalidDataError,
)
from audit_logger import audit_logger


class PasswordValidator:
    """
    Valida contraseñas contra requisitos NIST.
    """

    @staticmethod
    def validate(password: str) -> Tuple[bool, str]:
        """
        Valida una contraseña contra requisitos de seguridad.
        
        Args:
            password: Contraseña a validar
            
        Returns:
            Tupla (es_válida, mensaje_error)
        """
        issues = []

        if len(password) < MIN_PASSWORD_LENGTH:
            issues.append(f"Mínimo {MIN_PASSWORD_LENGTH} caracteres")

        if REQUIRE_UPPERCASE and not re.search(r"[A-Z]", password):
            issues.append("Al menos una mayúscula")

        if REQUIRE_LOWERCASE and not re.search(r"[a-z]", password):
            issues.append("Al menos una minúscula")

        if REQUIRE_DIGITS and not re.search(r"\d", password):
            issues.append("Al menos un número")

        if REQUIRE_SPECIAL_CHARS and not any(c in password for c in SPECIAL_CHARS):
            issues.append(f"Al menos un carácter especial ({SPECIAL_CHARS})")

        if issues:
            return False, "Contraseña débil: " + ", ".join(issues)

        return True, ""


class DataValidator:
    """
    Valida datos históricos de residentes.
    """

    @staticmethod
    def validate_age(age):
        """Valida edad (0-150)."""
        try:
            age_int = int(age)
            if 0 <= age_int <= 150:
                return True
            return False
        except (ValueError, TypeError):
            return False

    @staticmethod
    def validate_country(country: str) -> bool:
        """Valida país (formato string no vacío)."""
        return isinstance(country, str) and len(country) > 0 and len(country) <= 100

    @staticmethod
    def validate_user_id(user_id: str) -> bool:
        """Valida ID de usuario (alfanumérico, 3-50 caracteres)."""
        if not isinstance(user_id, str):
            return False
        if not (3 <= len(user_id) <= 50):
            return False
        return re.match(r"^[a-zA-Z0-9_\-]+$", user_id) is not None


class UserManager:
    """
    Gestiona usuarios: creación, autenticación, cambio de contraseña.
    Implementa validación y manejo de intentos fallidos.
    """

    def __init__(self):
        """Inicializa el gestor de usuarios y crea tablas si no existen."""
        self._init_database()

    @contextmanager
    def _get_connection(self):
        """Gestor de contexto para conexiones a BD."""
        conn = sqlite3.connect(DATABASE_PATH)
        try:
            yield conn
        finally:
            conn.close()

    def _init_database(self):
        """Crea tablas de usuarios y auditoría si no existen."""
        try:
            with self._get_connection() as conn:
                c = conn.cursor()

                # Tabla de usuarios
                c.execute(
                    """
                    CREATE TABLE IF NOT EXISTS usuarios (
                        id_usuario TEXT PRIMARY KEY,
                        password_hash BLOB NOT NULL,
                        rol TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        is_locked INTEGER DEFAULT 0,
                        locked_until TIMESTAMP
                    )
                    """
                )

                # Tabla de intentos fallidos (para rate limiting)
                c.execute(
                    """
                    CREATE TABLE IF NOT EXISTS login_attempts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        id_usuario TEXT NOT NULL,
                        attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (id_usuario) REFERENCES usuarios(id_usuario)
                    )
                    """
                )

                # Tabla de auditoría
                c.execute(
                    """
                    CREATE TABLE IF NOT EXISTS auditoria (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        id_usuario TEXT NOT NULL,
                        accion TEXT NOT NULL,
                        resultado TEXT,
                        detalles TEXT,
                        fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (id_usuario) REFERENCES usuarios(id_usuario)
                    )
                    """
                )

                conn.commit()
        except sqlite3.Error as e:
            audit_logger.log_error("SISTEMA", "init_database", "DBError", str(e))
            raise

    def create_user(
        self,
        user_id: str,
        password: str,
        rol: str,
        created_by: str = "SISTEMA",
    ) -> bool:
        """
        Crea un nuevo usuario.
        
        Args:
            user_id: ID único del usuario
            password: Contraseña en texto plano
            rol: Rol (admin, analista, publico)
            created_by: ID del admin que crea el usuario
            
        Returns:
            True si se creó exitosamente
            
        Raises:
            UserAlreadyExistsError: Si el usuario ya existe
            WeakPasswordError: Si la contraseña es débil
            InvalidDataError: Si los datos son inválidos
            PermissionDeniedError: Si no tiene permisos
        """
        # Validar permisos
        if created_by != "SISTEMA":
            creator_rol = self.get_user_role(created_by)
            if creator_rol != "admin":
                audit_logger.log_error(
                    created_by, "create_user", "PermissionDenied", f"Intento crear usuario {user_id}"
                )
                raise PermissionDeniedError("Solo administradores pueden crear usuarios")

        # Validar entrada
        if not DataValidator.validate_user_id(user_id):
            raise InvalidDataError(
                f"ID de usuario inválido. Usa 3-50 caracteres alfanuméricos, guiones o guiones bajos"
            )

        if rol not in ROLES:
            raise InvalidDataError(f"Rol inválido. Roles válidos: {list(ROLES.keys())}")

        # Validar contraseña
        is_valid, message = PasswordValidator.validate(password)
        if not is_valid:
            audit_logger.log_error(
                created_by, "create_user", "WeakPassword", f"Usuario {user_id}: {message}"
            )
            raise WeakPasswordError(message)

        # Verificar si usuario ya existe
        try:
            with self._get_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT id_usuario FROM usuarios WHERE id_usuario = ?", (user_id,))
                if c.fetchone():
                    audit_logger.log_error(
                        created_by, "create_user", "UserExists", f"Usuario {user_id} ya existe"
                    )
                    raise UserAlreadyExistsError(f"El usuario '{user_id}' ya existe")

                # Hash de contraseña
                salt = bcrypt.gensalt(rounds=12)
                hashed = bcrypt.hashpw(password.encode(), salt)

                # Insertar usuario
                c.execute(
                    """
                    INSERT INTO usuarios (id_usuario, password_hash, rol)
                    VALUES (?, ?, ?)
                    """,
                    (user_id, hashed, rol),
                )

                conn.commit()

            audit_logger.log_user_creation(created_by, user_id, rol)
            return True

        except sqlite3.Error as e:
            audit_logger.log_error(created_by, "create_user", "DBError", str(e))
            raise

    def authenticate(self, user_id: str, password: str) -> Tuple[bool, str]:
        """
        Autentica un usuario.
        
        Args:
            user_id: ID del usuario
            password: Contraseña
            
        Returns:
            Tupla (éxito, mensaje)
        """
        try:
            with self._get_connection() as conn:
                c = conn.cursor()

                # Verificar si usuario está bloqueado
                c.execute(
                    "SELECT is_locked, locked_until FROM usuarios WHERE id_usuario = ?",
                    (user_id,),
                )
                result = c.fetchone()

                if not result:
                    audit_logger.log_login(user_id, False, "Usuario no existe")
                    raise InvalidCredentialsError("Usuario o contraseña incorrectos")

                is_locked, locked_until = result
                if is_locked:
                    locked_until_dt = datetime.fromisoformat(locked_until)
                    if datetime.now() < locked_until_dt:
                        minutes = int((locked_until_dt - datetime.now()).total_seconds() / 60)
                        audit_logger.log_login(
                            user_id, False, f"Cuenta bloqueada por {minutes} minutos"
                        )
                        raise InvalidCredentialsError(
                            f"Cuenta bloqueada. Intenta en {minutes} minutos"
                        )
                    else:
                        # Desbloquear
                        c.execute(
                            "UPDATE usuarios SET is_locked = 0 WHERE id_usuario = ?",
                            (user_id,),
                        )
                        conn.commit()

                # Obtener hash
                c.execute(
                    "SELECT password_hash, rol FROM usuarios WHERE id_usuario = ?",
                    (user_id,),
                )
                db_result = c.fetchone()

                if not db_result:
                    audit_logger.log_login(user_id, False, "Usuario no existe")
                    raise InvalidCredentialsError("Usuario o contraseña incorrectos")

                password_hash, rol = db_result

                # Verificar contraseña
                if not bcrypt.checkpw(password.encode(), password_hash):
                    # Registrar intento fallido
                    c.execute(
                        "INSERT INTO login_attempts (id_usuario) VALUES (?)",
                        (user_id,),
                    )

                    # Contar intentos últimos 15 minutos
                    cutoff_time = (datetime.now() - timedelta(minutes=LOCKOUT_DURATION_MINUTES)).isoformat()
                    c.execute(
                        """
                        SELECT COUNT(*) FROM login_attempts
                        WHERE id_usuario = ? AND attempt_time > ?
                        """,
                        (user_id, cutoff_time),
                    )
                    attempts = c.fetchone()[0]

                    if attempts >= MAX_LOGIN_ATTEMPTS:
                        # Bloquear cuenta
                        locked_until = (
                            datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                        ).isoformat()
                        c.execute(
                            "UPDATE usuarios SET is_locked = 1, locked_until = ? WHERE id_usuario = ?",
                            (locked_until, user_id),
                        )
                        conn.commit()
                        audit_logger.log_login(
                            user_id,
                            False,
                            f"Demasiados intentos fallidos. Bloqueada por {LOCKOUT_DURATION_MINUTES} min",
                        )
                        raise InvalidCredentialsError(
                            f"Demasiados intentos fallidos. Cuenta bloqueada por {LOCKOUT_DURATION_MINUTES} minutos"
                        )

                    conn.commit()
                    audit_logger.log_login(
                        user_id, False, f"Contraseña incorrecta ({attempts}/{MAX_LOGIN_ATTEMPTS})"
                    )
                    raise InvalidCredentialsError("Usuario o contraseña incorrectos")

                # Autenticación exitosa
                # Actualizar last_login y limpiar intentos fallidos
                c.execute(
                    "UPDATE usuarios SET last_login = ? WHERE id_usuario = ?",
                    (datetime.now().isoformat(), user_id),
                )
                c.execute(
                    "DELETE FROM login_attempts WHERE id_usuario = ?",
                    (user_id,),
                )
                conn.commit()

                audit_logger.log_login(user_id, True)
                return True, rol

        except sqlite3.Error as e:
            audit_logger.log_error("SISTEMA", "authenticate", "DBError", str(e))
            raise InvalidCredentialsError("Error en autenticación")

    def change_password(self, user_id: str, old_password: str, new_password: str) -> bool:
        """
        Cambia la contraseña de un usuario.
        
        Args:
            user_id: ID del usuario
            old_password: Contraseña actual (para verificación)
            new_password: Nueva contraseña
            
        Returns:
            True si se cambió exitosamente
        """
        # Verificar contraseña actual
        success, rol = self.authenticate(user_id, old_password)
        if not success:
            raise InvalidCredentialsError("Contraseña actual incorrecta")

        # Validar nueva contraseña
        is_valid, message = PasswordValidator.validate(new_password)
        if not is_valid:
            raise WeakPasswordError(message)

        try:
            with self._get_connection() as conn:
                c = conn.cursor()
                salt = bcrypt.gensalt(rounds=12)
                hashed = bcrypt.hashpw(new_password.encode(), salt)

                c.execute(
                    "UPDATE usuarios SET password_hash = ? WHERE id_usuario = ?",
                    (hashed, user_id),
                )
                conn.commit()

            audit_logger.log_password_change(user_id, user_id)
            return True

        except sqlite3.Error as e:
            audit_logger.log_error(user_id, "change_password", "DBError", str(e))
            raise

    def get_user_role(self, user_id: str) -> Optional[str]:
        """Obtiene el rol de un usuario."""
        try:
            with self._get_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT rol FROM usuarios WHERE id_usuario = ?", (user_id,))
                result = c.fetchone()
                return result[0] if result else None
        except sqlite3.Error:
            return None

    def list_users(self) -> List[Tuple]:
        """Lista todos los usuarios (sin mostrar hashes)."""
        try:
            with self._get_connection() as conn:
                c = conn.cursor()
                c.execute(
                    "SELECT id_usuario, rol, created_at, last_login FROM usuarios ORDER BY created_at DESC"
                )
                return c.fetchall()
        except sqlite3.Error as e:
            audit_logger.log_error("SISTEMA", "list_users", "DBError", str(e))
            return []

    def delete_user(self, user_id: str, deleted_by: str) -> bool:
        """
        Elimina un usuario (solo admin).
        
        Args:
            user_id: ID del usuario a eliminar
            deleted_by: ID del admin que elimina
            
        Returns:
            True si se eliminó exitosamente
        """
        # Verificar permisos
        if self.get_user_role(deleted_by) != "admin":
            raise PermissionDeniedError("Solo administradores pueden eliminar usuarios")

        try:
            with self._get_connection() as conn:
                c = conn.cursor()
                c.execute("DELETE FROM usuarios WHERE id_usuario = ?", (user_id,))
                if c.rowcount == 0:
                    raise UserNotFoundError(f"Usuario '{user_id}' no existe")
                conn.commit()

            audit_logger.log_error(deleted_by, f"DELETE_USER:{user_id}", "UserDeleted", "")
            return True

        except sqlite3.Error as e:
            audit_logger.log_error(deleted_by, "delete_user", "DBError", str(e))
            raise
