# 🔐 Sistema de Gestión Segura para ONG - Control de Acceso Criptográfico

Sistema robusto de autenticación, encriptación y auditoría para gestión confidencial de datos de residentes en ONG. Implementa cifrado AES-256-GCM con derivación de claves PBKDF2, control de acceso basado en roles (RBAC) y auditoría completa.

## ✨ Características

### Seguridad
- ✅ **Autenticación Robusta**: Contraseñas hasheadas con bcrypt (rounds=12)
- ✅ **Cifrado de Datos**: AES-256-GCM con PBKDF2 para derivación de claves
- ✅ **Control de Acceso**: 3 roles (admin, analista, público) con vistas según permisos
- ✅ **Rate Limiting**: Bloqueo de cuenta tras 5 intentos fallidos (15 minutos)
- ✅ **Validación**: Contraseñas NIST, sanitización de entrada, tipos de datos
- ✅ **Auditoría**: Registro completo de acciones en archivo + BD

### Gestión de Datos
- 📊 Cifrado en 2 niveles según rol:
  - **Nivel 1** (Analista): Edad, Tiempo Estancia → clave básica
  - **Nivel 2** (Admin): Nombre, Apellidos → clave admin
  - **Público**: ID Usuario, Fecha Ingreso, País Origen
- 🔑 Persistencia de claves derivadas mediante PBKDF2
- 📁 Soporte para Excel (pandas) y SQLite

### Operaciones
- 👥 Gestión de usuarios (crear, listar, eliminar)
- 🔐 Cambio de contraseña seguro
- 📝 Encriptación/desencriptación de archivos
- 📊 Vistas seguras según rol
- 📋 Auditoría y logging

---

## 🚀 Instalación Rápida

### 1. Prerequisites
- Python 3.9+
- pip
- (Opcional) SQLite 3

### 2. Setup Local

```bash
# Clonar/descargar el proyecto
cd proyecto-ong

# Crear entorno virtual
python -m venv venv

# Activar entorno
# En macOS/Linux:
source venv/bin/activate
# En Windows:
venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt

# Crear archivo .env desde template
cp .env.example .env

# IMPORTANTE: Editar .env con tu contraseña maestra (CRYPTO_MASTER_PASSWORD)
```

### 3. Configuración Inicial

```bash
# Crear directorios necesarios
mkdir -p data logs

# Inicializar BD y crear primer admin
python -c "from src.user_manager import UserManager; um = UserManager(); um.create_user('admin_master', 'Admin@2024!Inicial', 'admin', 'SISTEMA')"
```

---

## 📖 Guía de Uso

### Interfaz CLI Interactiva

```bash
# Modo interactivo (recomendado para usuarios finales)
python -m src.cli interactive

# O comandos directos:
python -m src.cli create-user
python -m src.cli login
python -m src.cli encrypt-data --input-file datos.xlsx
python -m src.cli decrypt-data --input-file base_encriptada.xlsx
```

### Ejemplos de Uso

#### 1. Crear Usuario Admin

```bash
$ python -m src.cli create-user
ID de Usuario: admin_master
Contraseña: Admin@2024!Inicial  (no se ve mientras escribes)
Confirmar Contraseña: Admin@2024!Inicial
Rol: admin
Admin User [SISTEMA]: SISTEMA
✅ Usuario 'admin_master' creado exitosamente con rol 'admin'
```

**Requisitos de Contraseña:**
- Mínimo 12 caracteres
- Al menos 1 mayúscula, 1 minúscula, 1 número, 1 especial
- Ejemplo: `Admin@2024!Secure`

#### 2. Iniciar Sesión

```bash
$ python -m src.cli login
ID de Usuario: admin_master
Contraseña: ••••••••••••
✅ Bienvenido admin_master. Rol: admin
```

#### 3. Encriptar Datos

```bash
$ python -m src.cli encrypt-data
Archivo Excel a encriptar: datos_residentes.xlsx
Archivo de salida [base_encriptada.xlsx]: 
✅ Datos encriptados y guardados en: base_encriptada.xlsx
```

**Qué se encripta:**
- **Clave Básica**: Edad, Tiempo Estancia
- **Clave Admin**: Nombre, Apellido Materno, Apellido Paterno
- **No se encripta**: ID Usuario, Fecha Ingreso, País Origen (público)

#### 4. Desencriptar Datos (Según Rol)

```bash
# Admin ve TODO (nivel 1 + nivel 2)
$ python -m src.cli decrypt-data
Archivo encriptado: base_encriptada.xlsx
✅ Datos desencriptados. Columnas visibles: ID Usuario, Fecha de Ingreso, País Origen, Edad, Tiempo Estancia Determinado, Nombre, Apellido Materno, Apellido Paterno

# Analista ve SOLO nivel 1
# Usuario Público ve SOLO columnas públicas
```

#### 5. Ver Auditoría (Admin Only)

```bash
$ python -m src.cli audit-log
$ python -m src.cli audit-log --user-id admin_master --limit 100
```

#### 6. Listar Usuarios (Admin Only)

```bash
$ python -m src.cli list-users
================================================================================
ID Usuario        Rol            Creado               Último Login
================================================================================
admin_master      admin          2024-04-09 12:00:00  2024-04-09 14:23:15
usuario_analista  analista       2024-04-09 13:10:00  2024-04-09 14:20:00
================================================================================
```

---

## 🏗️ Arquitectura

```
proyecto/
├── src/
│   ├── __init__.py
│   ├── config.py              # Configuración centralizada
│   ├── exceptions.py          # Excepciones customizadas
│   ├── audit_logger.py        # Logging estructurado
│   ├── crypto_security.py     # Encriptación AES-GCM + PBKDF2
│   ├── user_manager.py        # Gestión de usuarios
│   └── cli.py                 # Interfaz CLI (click)
├── tests/
│   ├── test_validators.py     # Tests de validación
│   ├── test_crypto.py         # Tests de criptografía
│   └── test_user_manager.py   # Tests de usuarios
├── data/                       # BD y datos (git-ignored)
│   ├── usuarios_ong.db
│   └── base_encriptada.xlsx
├── logs/                       # Archivos de log
│   └── audit.log
├── .env                        # Variables de entorno (git-ignored)
├── .env.example               # Template de .env
├── .gitignore
├── requirements.txt
├── README.md
└── CryptoCifradoIntento2.ipynb # Notebook refactorizado (interfaz)
```

### Flujo de Datos

```
Usuario
  ↓
[CLI] ← login/contraseña
  ↓
[UserManager] ← verifica en BD (bcrypt)
  ↓
[Éxito] ← rol asignado
  ↓
[CryptoManager] ← obtiene claves derivadas (PBKDF2)
  ↓
[Encriptación/Desencriptación] ← AES-256-GCM
  ↓
[AuditLogger] ← registra evento
  ↓
[Datos] ← usuario ve según rol
```

---

## 🔒 Seguridad en Profundidad

### 1. Contraseñas

- **Hashing**: bcrypt con 12 rounds
- **Validación**: NIST 800-63B (12+ chars, mayúsculas, minúsculas, números, especiales)
- **Rate Limiting**: 5 intentos fallidos → 15 minutos bloqueado
- **Cambio de Contraseña**: Requiere contraseña actual verificada

#### Ejemplo de Contraseña Fuerte

```
❌ Débil:  password123, Admin2024, usuario@ong
✅ Fuerte: Admin@2024!Secure, ONG#Datos$2024, S3cur0!Contra@ña
```

### 2. Cifrado de Datos

- **Algoritmo**: AES-256 en modo GCM (Galois Counter Mode)
- **Derivación de Claves**: PBKDF2-SHA256 (100,000 iteraciones)
- **Autenticación**: GCM proporciona integridad (detecta tampering)
- **Nonce Aleatorio**: Cada operación genera nuevo nonce (16 bytes)

#### Cómo Funciona

```
Contraseña Maestra (env var)
  ↓
PBKDF2(password=, salt=, iterations=100k)
  ↓
Clave Derivada (256 bits)
  ↓
AES-256-GCM(plaintext, key, nonce)
  ↓
nonce (16) + tag (16) + ciphertext → Base64
```

### 3. Control de Acceso

| Rol | Permisos | Ve |
|-----|----------|-----|
| **admin** | Crear/eliminar usuarios, encriptar, ver auditoría | Todos los niveles |
| **analista** | Ver datos, cambiar contraseña | Nivel 1 + Público |
| **publico** | Cambiar contraseña | Solo Público |

### 4. Auditoría

Cada acción registra:
- **Quién**: ID del usuario
- **Qué**: Acción realizada
- **Cuándo**: Timestamp ISO
- **Resultado**: Éxito/Fallo
- **Detalles**: Información adicional

Registros se guardan en:
1. Archivo local: `logs/audit.log`
2. Base de datos: tabla `auditoria`

---

## 🧪 Testing

```bash
# Instalar pytest
pip install pytest

# Ejecutar todos los tests
pytest tests/ -v

# Ejecutar test específico
pytest tests/test_validators.py::TestPasswordValidator::test_valid_password -v

# Con cobertura
pip install pytest-cov
pytest tests/ --cov=src --cov-report=html
```

**Cobertura Actual:**
- ✅ Validadores (contraseña, datos)
- ✅ Criptografía (derivación, encriptación, desencriptación)
- ✅ Casos de error (claves inválidas, ciphertexts corruptos)

---

## 📦 Dependencias

```
bcrypt==4.1.1              # Hashing de contraseñas
pycryptodome==3.19.0       # AES, PBKDF2, funciones criptográficas
pandas==2.1.0              # Manejo de Excel
openpyxl==3.1.2            # Soporte Excel
click==8.1.7               # CLI framework
python-dotenv==1.0.0       # Gestión de .env
pytest==7.4.0              # Testing (opcional)
```

---

## 🌐 Deployment en Hostgator

### 1. Preparación

```bash
# 1. Crear carpeta en Hostgator (vía FTP o SSH)
mkdir -p ~/ong-seguro
cd ~/ong-seguro

# 2. Subir archivos (excluyendo .env, data/, logs/)
# Usar: src/, tests/, requirements.txt, .env.example, README.md, CryptoCifradoIntento2.ipynb

# 3. Crear .env en servidor (NO subir a Git)
cp .env.example .env
# Editar .env con editor del servidor
nano .env
```

### 2. Setup en Servidor

```bash
# SSH a Hostgator
ssh usuario@tudominio.com

# Entrar a carpeta
cd ong-seguro

# Crear venv
python3 -m venv venv
source venv/bin/activate

# Instalar
pip install -r requirements.txt

# Crear directorios
mkdir -p data logs

# Inicializar BD
python3 -c "from src.user_manager import UserManager; um = UserManager()"
```

### 3. Variable de Entorno Crítica

```bash
# En Hostgator, configurar CRYPTO_MASTER_PASSWORD como env var del sistema
# Opción 1: En archivo ~/.bashrc (no recomendado)
# Opción 2: En .env en servidor (mejor)
# Opción 3: En control panel de Hostgator (si soporta)

# Verificar que se carga:
python3 -c "import os; print(os.getenv('CRYPTO_MASTER_PASSWORD', 'NO CONFIGURADA'))"
```

### 4. Backup Automático en Hostgator

```bash
# Crear script de backup backup.sh
#!/bin/bash
BACKUP_DIR="/home/usuario/backups"
DB_FILE="/home/usuario/ong-seguro/data/usuarios_ong.db"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR
cp $DB_FILE "$BACKUP_DIR/usuarios_ong_$TIMESTAMP.db"

# Mantener solo últimos 30 días
find $BACKUP_DIR -mtime +30 -delete

# Agregar a cron (ejecutar diariamente a las 2 AM)
# crontab -e
# 0 2 * * * /home/usuario/ong-seguro/backup.sh
```

### 5. Usar CLI en Producción

```bash
# En Hostgator
cd ~/ong-seguro
source venv/bin/activate
python3 -m src.cli interactive
```

---

## 🔑 Gestión de Contraseña Maestra

### En Desarrollo Local

```bash
# .env (git-ignored)
CRYPTO_MASTER_PASSWORD=MiContraseña@Local2024!
```

### En Producción (Hostgator)

**Opción 1: Variable de Entorno del Sistema** (RECOMENDADO)
```bash
# En Hostgator (SSH)
export CRYPTO_MASTER_PASSWORD="MiContraseña@Producción2024!"

# Agregar a ~/.bashrc para persistencia
echo 'export CRYPTO_MASTER_PASSWORD="..."' >> ~/.bashrc
source ~/.bashrc
```

**Opción 2: Archivo .env en Servidor**
```bash
# Crear .env SOLO en servidor (no subir a Git)
# Usuarios sin acceso SSH no pueden ver
# Riesgo: si alguien accede al servidor, ve la contraseña
```

**Opción 3: Secret Manager (Si Hostgator lo soporta)**
```bash
# Consultar con Hostgator si tiene:
# - AWS Secrets Manager
# - HashiCorp Vault
# - Herramientas similares
```

---

## ⚠️ Checklist de Seguridad

- [ ] CRYPTO_MASTER_PASSWORD es fuerte (12+, mayúsculas, minúsculas, números, especiales)
- [ ] .env está en .gitignore (no subir a Github)
- [ ] Permisos de archivo restrictivos: `chmod 600 .env`
- [ ] BD (usuarios_ong.db) NO se sube a Git (es git-ignored)
- [ ] Logs se rotan (no crecen infinitamente)
- [ ] Backups se hacen regularmente (mínimo semanal)
- [ ] HTTPS está habilitado en Hostgator (para conectar vía web después)
- [ ] Rate limiting está activo (5 intentos, 15 minutos)
- [ ] Tests pasan: `pytest tests/ -v`
- [ ] Contraseña de primer admin es ÚNICA y segura

---

## 🐛 Troubleshooting

### Error: "CRYPTO_MASTER_PASSWORD no configurada"

```bash
# Verificar que .env existe
ls -la .env

# Verificar contenido
cat .env | grep CRYPTO_MASTER_PASSWORD

# Si no existe:
cp .env.example .env
# Luego editar con tu contraseña
```

### Error: "Usuario no existe"

```bash
# Crear primer admin
python3 -c "from src.user_manager import UserManager; um = UserManager(); um.create_user('admin_master', 'Admin@2024!', 'admin', 'SISTEMA')"
```

### Error: "Cuenta bloqueada"

La cuenta se bloquea tras 5 intentos fallidos por 15 minutos. Espera o:

```python
# En Python:
import sqlite3
conn = sqlite3.connect('data/usuarios_ong.db')
c = conn.cursor()
c.execute("UPDATE usuarios SET is_locked = 0 WHERE id_usuario = '?'", (usuario,))
conn.commit()
```

### Error: "Falló verificación de integridad"

Los datos encriptados fueron alterados o la clave es incorrecta. No se pueden recuperar.

---

## 📚 Referencias

- **NIST 800-63B**: Recomendaciones de contraseñas
- **AES-GCM**: https://en.wikipedia.org/wiki/Galois/Counter_Mode
- **PBKDF2**: https://en.wikipedia.org/wiki/PBKDF2
- **bcrypt**: https://en.wikipedia.org/wiki/Bcrypt
- **Click CLI**: https://click.palletsprojects.com/
- **PyCryptodome**: https://pycryptodome.readthedocs.io/

---

## 📋 Roadmap Futuro

- **Fase 2**: API Flask/FastAPI para acceso remoto
- **Fase 3**: Web UI (React/Vue) para no-técnicos
- **Fase 4**: 2FA (Two-Factor Authentication)
- **Fase 5**: ELK Stack para logging centralizado
- **Fase 6**: Hardware Security Module (HSM) en Hostgator

---

## 📞 Soporte

Para problemas o preguntas:
1. Revisar logs: `cat logs/audit.log`
2. Ver BD: `sqlite3 data/usuarios_ong.db ".tables"`
3. Ejecutar tests: `pytest tests/ -v`

---

**Versión**: 1.0  
**Última actualización**: 9 de Abril de 2024  
**Estado**: ✅ Producción Lista
