#!/usr/bin/env python
"""
Script principal para ejecutar el sistema de seguridad.
Proporciona interfaz CLI interactiva.
"""
import sys
import os
from pathlib import Path

# Agregar src al path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Importar y ejecutar CLI
from cli import cli

if __name__ == "__main__":
    try:
        cli()
    except KeyboardInterrupt:
        print("\n\n👋 ¡Hasta luego!")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error fatal: {e}")
        sys.exit(1)
