"""
Interfaz CLI para el sistema de seguridad criptográfico.
Proporciona comandos para gestión de usuarios, encriptación de datos y auditoría.
"""
import click
import pandas as pd
import sys
from typing import Optional
from pathlib import Path

from config import (
    LEVEL1_COLS,
    LEVEL2_COLS,
    PUBLIC_COLS,
    ROLES,
    DATA_ENCRYPTED_PATH,
)
from user_manager import UserManager, PasswordValidator
from crypto_security import CryptoManager
from audit_logger import audit_logger
from exceptions import SecurityException


# Instancias globales
user_manager = UserManager()
crypto_manager = CryptoManager()

# Estado de sesión
current_user = None
current_role = None


@click.group()
def cli():
    """Sistema de Gestión Segura para ONG - CLI"""
    pass


# ====== COMANDOS DE USUARIO ======


@cli.command()
@click.option("--user-id", prompt="ID de Usuario", help="ID único del usuario")
@click.option("--password", prompt=True, hide_input=True, help="Contraseña")
@click.option("--password-confirm", prompt="Confirmar Contraseña", hide_input=True)
@click.option("--rol", type=click.Choice(["admin", "analista", "publico"]), default="analista", help="Rol del usuario")
@click.option("--admin-user", default="SISTEMA", help="Admin que crea el usuario")
def create_user(user_id: str, password: str, password_confirm: str, rol: str, admin_user: str):
    """Crea un nuevo usuario."""
    try:
        if password != password_confirm:
            click.secho("❌ Error: Las contraseñas no coinciden", fg="red")
            return

        user_manager.create_user(user_id, password, rol, admin_user)
        click.secho(f"✅ Usuario '{user_id}' creado exitosamente con rol '{rol}'", fg="green")

    except SecurityException as e:
        click.secho(f"❌ Error: {e}", fg="red")


@cli.command()
@click.option("--user-id", prompt="ID de Usuario", help="ID del usuario a autenticar")
@click.option("--password", prompt=True, hide_input=True, help="Contraseña")
def login(user_id: str, password: str):
    """Inicia sesión en el sistema."""
    global current_user, current_role

    try:
        success, rol = user_manager.authenticate(user_id, password)
        current_user = user_id
        current_role = rol
        click.secho(
            f"✅ Bienvenido {user_id}. Rol: {rol}",
            fg="green",
        )

    except SecurityException as e:
        click.secho(f"❌ Error: {e}", fg="red")


@cli.command()
def logout():
    """Cierra la sesión actual."""
    global current_user, current_role
    current_user = None
    current_role = None
    click.secho("✅ Sesión cerrada", fg="green")


@cli.command()
@click.option("--old-password", prompt=True, hide_input=True, help="Contraseña actual")
@click.option("--new-password", prompt=True, hide_input=True, help="Nueva contraseña")
@click.option("--new-password-confirm", prompt="Confirmar Nueva Contraseña", hide_input=True)
def change_password(old_password: str, new_password: str, new_password_confirm: str):
    """Cambia la contraseña del usuario actual."""
    if not current_user:
        click.secho("❌ Error: Debes iniciar sesión primero", fg="red")
        return

    try:
        if new_password != new_password_confirm:
            click.secho("❌ Error: Las nuevas contraseñas no coinciden", fg="red")
            return

        user_manager.change_password(current_user, old_password, new_password)
        click.secho("✅ Contraseña cambiada exitosamente", fg="green")

    except SecurityException as e:
        click.secho(f"❌ Error: {e}", fg="red")


@cli.command()
def list_users():
    """Lista todos los usuarios (requiere rol admin)."""
    if not current_user or current_role != "admin":
        click.secho("❌ Error: Solo administradores pueden listar usuarios", fg="red")
        return

    try:
        users = user_manager.list_users()
        if not users:
            click.secho("No hay usuarios registrados", fg="yellow")
            return

        click.echo("\n" + "=" * 80)
        click.echo(f"{'ID Usuario':<20} {'Rol':<15} {'Creado':<20} {'Último Login':<20}")
        click.echo("=" * 80)

        for user_id, rol, created_at, last_login in users:
            last_login_str = last_login or "Nunca"
            click.echo(f"{user_id:<20} {rol:<15} {created_at:<20} {last_login_str:<20}")

        click.echo("=" * 80)

    except SecurityException as e:
        click.secho(f"❌ Error: {e}", fg="red")


# ====== COMANDOS DE ENCRIPTACIÓN ======


@cli.command()
@click.option("--input-file", type=click.Path(exists=True), prompt="Archivo Excel a encriptar", help="Ruta del archivo Excel")
@click.option("--output-file", default=None, help="Archivo de salida (default: base_encriptada.xlsx)")
def encrypt_data(input_file: str, output_file: Optional[str]):
    """Encripta un archivo Excel."""
    if not current_user:
        click.secho("❌ Error: Debes iniciar sesión primero", fg="red")
        return

    if current_role != "admin":
        click.secho("❌ Error: Solo administradores pueden encriptar datos", fg="red")
        return

    try:
        df = pd.read_excel(input_file)
        df_enc = crypto_manager.encrypt_dataframe(df, LEVEL1_COLS, LEVEL2_COLS)

        output = output_file or DATA_ENCRYPTED_PATH
        df_enc.to_excel(output, index=False)

        audit_logger.log_data_access(current_user, current_role, "encrypt_data", f"Archivo: {input_file}")
        click.secho(f"✅ Datos encriptados y guardados en: {output}", fg="green")

    except Exception as e:
        audit_logger.log_error(current_user, "encrypt_data", "EncryptionError", str(e))
        click.secho(f"❌ Error: {e}", fg="red")


@cli.command()
@click.option("--input-file", type=click.Path(exists=True), prompt="Archivo encriptado", help="Ruta del archivo encriptado")
@click.option("--output-file", default=None, help="Archivo de salida")
def decrypt_data(input_file: str, output_file: Optional[str]):
    """Desencripta un archivo Excel según rol del usuario."""
    if not current_user:
        click.secho("❌ Error: Debes iniciar sesión primero", fg="red")
        return

    try:
        df = pd.read_excel(input_file)

        # Aplicar desencriptación según rol
        if current_role == "admin":
            df_dec = crypto_manager.decrypt_dataframe(df, LEVEL1_COLS, LEVEL2_COLS)
            cols_visible = PUBLIC_COLS + LEVEL1_COLS + LEVEL2_COLS
        elif current_role == "analista":
            df_dec = crypto_manager.decrypt_dataframe(df, LEVEL1_COLS)
            df_dec = df_dec[PUBLIC_COLS + LEVEL1_COLS]
            cols_visible = PUBLIC_COLS + LEVEL1_COLS
        else:  # publico
            df_dec = df[PUBLIC_COLS]
            cols_visible = PUBLIC_COLS

        output = output_file or f"decrypted_{input_file}"
        df_dec.to_excel(output, index=False)

        audit_logger.log_data_access(
            current_user,
            current_role,
            "decrypt_data",
            f"Columnas visibles: {cols_visible}",
        )
        click.secho(f"✅ Datos desencriptados. Columnas visibles: {cols_visible}", fg="green")
        click.secho(f"📁 Archivo guardado en: {output}", fg="green")

    except Exception as e:
        audit_logger.log_error(current_user, "decrypt_data", "DecryptionError", str(e))
        click.secho(f"❌ Error: {e}", fg="red")


# ====== COMANDOS DE AUDITORÍA ======


@cli.command()
@click.option("--user-id", default=None, help="Filtrar por usuario (default: todos)")
@click.option("--limit", type=int, default=50, help="Número de registros")
def audit_log(user_id: Optional[str], limit: int):
    """Muestra el registro de auditoría (requiere admin)."""
    if not current_user or current_role != "admin":
        click.secho("❌ Error: Solo administradores pueden ver auditoría", fg="red")
        return

    try:
        records = audit_logger.get_audit_trail(user_id, limit)

        if not records:
            click.secho("No hay registros de auditoría", fg="yellow")
            return

        click.echo("\n" + "=" * 120)
        click.echo(
            f"{'Usuario':<15} {'Acción':<25} {'Resultado':<10} {'Detalles':<30} {'Fecha':<20}"
        )
        click.echo("=" * 120)

        for record in records:
            user, action, result, details, fecha = record[1], record[2], record[3], record[4], record[5]
            details_short = (details or "")[:30]
            click.echo(
                f"{user:<15} {action:<25} {result:<10} {details_short:<30} {fecha:<20}"
            )

        click.echo("=" * 120)

    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")


# ====== COMANDOS DE ADMINISTRACIÓN ======


@cli.command()
@click.option("--user-id", prompt="ID del usuario a eliminar", help="Usuario a eliminar")
def delete_user(user_id: str):
    """Elimina un usuario (requiere admin)."""
    if not current_user or current_role != "admin":
        click.secho("❌ Error: Solo administradores pueden eliminar usuarios", fg="red")
        return

    if click.confirm(f"⚠️  ¿Estás seguro de que deseas eliminar '{user_id}'? Esta acción es irreversible"):
        try:
            user_manager.delete_user(user_id, current_user)
            click.secho(f"✅ Usuario '{user_id}' eliminado", fg="green")
        except SecurityException as e:
            click.secho(f"❌ Error: {e}", fg="red")


@cli.command()
def status():
    """Muestra el estado actual de la sesión."""
    if current_user:
        click.secho(f"✅ Conectado como: {current_user}", fg="green")
        click.secho(f"   Rol: {current_role}", fg="green")
    else:
        click.secho("❌ No hay sesión activa", fg="yellow")


@cli.command()
def help_info():
    """Muestra ayuda sobre los comandos disponibles."""
    click.echo(
        """
╔════════════════════════════════════════════════════════════════╗
║   Sistema de Gestión Segura para ONG - Ayuda                  ║
╚════════════════════════════════════════════════════════════════╝

COMANDOS DE USUARIO:
  create-user       Crear un nuevo usuario (requiere contraseña fuerte)
  login             Iniciar sesión
  logout            Cerrar sesión
  change-password   Cambiar contraseña
  list-users        Listar todos los usuarios (solo admin)
  delete-user       Eliminar un usuario (solo admin)

COMANDOS DE ENCRIPTACIÓN:
  encrypt-data      Encriptar un archivo Excel (solo admin)
  decrypt-data      Desencriptar datos según rol

COMANDOS DE AUDITORÍA:
  audit-log         Ver registro de auditoría (solo admin)

OTROS:
  status            Ver estado de la sesión actual
  help-info         Mostrar esta ayuda

EJEMPLO DE USO:
  1. crear usuario: create-user
  2. login
  3. encrypt-data --input-file datos.xlsx
  4. decrypt-data --input-file base_encriptada.xlsx

REQUISITOS DE CONTRASEÑA:
  • Mínimo 12 caracteres
  • Al menos 1 mayúscula, 1 minúscula, 1 número, 1 carácter especial
  • Ejemplo: Admin@2024!Secure

NOTA: Todos los eventos se registran en auditoría.log
    """
    )


@cli.command()
def interactive():
    """Inicia modo interactivo con menú principal."""
    click.clear()
    click.secho("╔════════════════════════════════════════════╗", fg="cyan")
    click.secho("║  Sistema de Gestión Segura para ONG       ║", fg="cyan")
    click.secho("╚════════════════════════════════════════════╝", fg="cyan")

    while True:
        click.echo("\n")
        status()

        if current_user:
            click.echo("\n📋 Menú Principal:")
            click.echo("  1. Cambiar contraseña")
            click.echo("  2. Ver lista de usuarios" if current_role == "admin" else "")
            click.echo("  3. Encriptar datos" if current_role == "admin" else "")
            click.echo("  4. Desencriptar datos")
            click.echo("  5. Ver auditoría" if current_role == "admin" else "")
            click.echo("  6. Logout")
            choice = click.prompt("Selecciona una opción", type=str)

            if choice == "1":
                ctx = click.Context(change_password)
                ctx.invoke(change_password)
            elif choice == "2" and current_role == "admin":
                ctx = click.Context(list_users)
                ctx.invoke(list_users)
            elif choice == "3" and current_role == "admin":
                ctx = click.Context(encrypt_data)
                ctx.invoke(encrypt_data)
            elif choice == "4":
                ctx = click.Context(decrypt_data)
                ctx.invoke(decrypt_data)
            elif choice == "5" and current_role == "admin":
                ctx = click.Context(audit_log)
                ctx.invoke(audit_log)
            elif choice == "6":
                ctx = click.Context(logout)
                ctx.invoke(logout)
        else:
            click.echo("\n🔐 Opciones:")
            click.echo("  1. Login")
            click.echo("  2. Crear usuario")
            click.echo("  3. Ayuda")
            click.echo("  4. Salir")
            choice = click.prompt("Selecciona una opción", type=str)

            if choice == "1":
                ctx = click.Context(login)
                ctx.invoke(login)
            elif choice == "2":
                ctx = click.Context(create_user)
                ctx.invoke(create_user)
            elif choice == "3":
                ctx = click.Context(help_info)
                ctx.invoke(help_info)
            elif choice == "4":
                click.secho("👋 ¡Hasta luego!", fg="green")
                sys.exit(0)


if __name__ == "__main__":
    cli()
