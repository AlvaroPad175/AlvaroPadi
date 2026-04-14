"""
Configuración centralizada y gestión de variables de entorno.
"""
import os
from dotenv import load_dotenv
from pathlib import Path

# Cargar variables de entorno desde .env
load_dotenv()

# Rutas base
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"

# Crear directorios si no existen
DATA_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# ====== CONFIGURACIÓN DE BD ======
DATABASE_PATH = os.getenv("DATABASE_PATH", str(DATA_DIR / "usuarios_ong.db"))
DATA_ENCRYPTED_PATH = os.getenv("DATA_ENCRYPTED_PATH", str(DATA_DIR / "base_encriptada.xlsx"))

# ====== CONFIGURACIÓN DE CRIPTOGRAFÍA ======
CRYPTO_MASTER_PASSWORD = os.getenv("CRYPTO_MASTER_PASSWORD")
if not CRYPTO_MASTER_PASSWORD:
    raise ValueError(
        "❌ Error: CRYPTO_MASTER_PASSWORD no configurada. "
        "Configura la variable de entorno o el archivo .env"
    )

# Algoritmo de derivación de claves
KEY_DERIVATION_ALGORITHM = "pbkdf2"
KEY_DERIVATION_ITERATIONS = 100000  # Recomendado por OWASP
KEY_SIZE = 32  # 256 bits para AES

# Configuración de PBKDF2
PBKDF2_HASH_ALGORITHM = "sha256"

# ====== CONFIGURACIÓN DE CONTRASEÑAS ======
MIN_PASSWORD_LENGTH = 12
REQUIRE_UPPERCASE = True
REQUIRE_LOWERCASE = True
REQUIRE_DIGITS = True
REQUIRE_SPECIAL_CHARS = True
SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"

# ====== CONFIGURACIÓN DE INTENTOS FALLIDOS ======
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

# ====== CONFIGURACIÓN DE LOGGING ======
LOG_FILE = LOGS_DIR / "audit.log"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# ====== NIVELES DE ACCESO ======
ROLES = {
    "admin": {"level": 3, "permissions": ["read_level1", "read_level2", "manage_users"]},
    "analista": {"level": 2, "permissions": ["read_level1"]},
    "publico": {"level": 1, "permissions": []},
}
PRIMARY_ADMIN_USER_ID = os.getenv("PRIMARY_ADMIN_USER_ID", "admin_master")

PRIMARY_ADMIN_ONLY_PERMISSIONS = {
    "read_raw_users",
    "assign_certificates",
    "revoke_certificates",
    "manage_keys",
    "rotate_keys",
    "view_key_usage",
}

CERTIFICATE_REQUIRED_ROLES = {"admin", "analista"}
DEFAULT_CERTIFICATE_STATUS = "pendiente"

# ====== COLUMNAS DE DATOS POR NIVEL ======
LEVEL1_COLS = ["Edad", "Tiempo Estancia Determinado"]
LEVEL2_COLS = ["Nombre", "Apellido Materno", "Apellido Paterno"]
PUBLIC_COLS = ["ID Usuario", "Fecha de Ingreso", "País Origen"]

# ====== CONFIGURACIÓN DEL CLI ======
CLI_TIMEOUT_MINUTES = 30

print("✅ Configuración cargada correctamente")



