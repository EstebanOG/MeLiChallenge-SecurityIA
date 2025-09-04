#!/usr/bin/env python3
"""
Script para ejecutar tests del proyecto IoT Anomaly Detection.

Este script proporciona una interfaz fácil para ejecutar diferentes tipos de tests
y generar reportes de cobertura.
"""

import subprocess
import sys
import argparse
from pathlib import Path


def run_command(command, description):
    """Ejecuta un comando y maneja errores."""
    print(f"\n{'='*60}")
    print(f"Ejecutando: {description}")
    print(f"Comando: {' '.join(command)}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error ejecutando comando: {e}")
        print(f"STDOUT: {e.stdout}")
        print(f"STDERR: {e.stderr}")
        return False


def run_unit_tests():
    """Ejecuta tests unitarios."""
    command = [
        "python", "-m", "pytest", 
        "tests/domain/", 
        "tests/application/", 
        "tests/presentation/fastapi_app/controllers/",
        "tests/presentation/fastapi_app/middleware/",
        "tests/presentation/fastapi_app/factories/",
        "-m", "unit", "-v"
    ]
    return run_command(command, "Tests Unitarios")


def run_integration_tests():
    """Ejecuta tests de integración."""
    command = [
        "python", "-m", "pytest", 
        "tests/integration/", 
        "-m", "integration", "-v"
    ]
    return run_command(command, "Tests de Integración")


def run_all_tests():
    """Ejecuta todos los tests."""
    command = [
        "python", "-m", "pytest", 
        "tests/", 
        "-v", "--tb=short"
    ]
    return run_command(command, "Todos los Tests")


def run_tests_with_coverage():
    """Ejecuta tests con reporte de cobertura."""
    command = [
        "python", "-m", "pytest", 
        "tests/", 
        "--cov=src", 
        "--cov-report=html", 
        "--cov-report=term-missing", 
        "--cov-report=xml",
        "-v"
    ]
    return run_command(command, "Tests con Cobertura")


def run_specific_test(test_path):
    """Ejecuta un test específico."""
    command = [
        "python", "-m", "pytest", 
        test_path, 
        "-v", "--tb=short"
    ]
    return run_command(command, f"Test Específico: {test_path}")


def run_fast_tests():
    """Ejecuta solo tests rápidos."""
    command = [
        "python", "-m", "pytest", 
        "tests/", 
        "-m", "fast", "-v"
    ]
    return run_command(command, "Tests Rápidos")


def run_slow_tests():
    """Ejecuta solo tests lentos."""
    command = [
        "python", "-m", "pytest", 
        "tests/", 
        "-m", "slow", "-v"
    ]
    return run_command(command, "Tests Lentos")


def main():
    """Función principal del script."""
    parser = argparse.ArgumentParser(description="Ejecutar tests del proyecto IoT Anomaly Detection")
    parser.add_argument(
        "test_type", 
        choices=["unit", "integration", "all", "coverage", "fast", "slow", "specific"],
        help="Tipo de tests a ejecutar"
    )
    parser.add_argument(
        "--test-path", 
        help="Ruta del test específico (solo para 'specific')"
    )
    parser.add_argument(
        "--verbose", "-v", 
        action="store_true", 
        help="Modo verbose"
    )
    
    args = parser.parse_args()
    
    print("🧪 Ejecutando Tests del Proyecto IoT Anomaly Detection")
    print("=" * 60)
    
    success = False
    
    if args.test_type == "unit":
        success = run_unit_tests()
    elif args.test_type == "integration":
        success = run_integration_tests()
    elif args.test_type == "all":
        success = run_all_tests()
    elif args.test_type == "coverage":
        success = run_tests_with_coverage()
    elif args.test_type == "fast":
        success = run_fast_tests()
    elif args.test_type == "slow":
        success = run_slow_tests()
    elif args.test_type == "specific":
        if not args.test_path:
            print("Error: --test-path es requerido para 'specific'")
            sys.exit(1)
        success = run_specific_test(args.test_path)
    
    if success:
        print("\n✅ Tests ejecutados exitosamente!")
        sys.exit(0)
    else:
        print("\n❌ Algunos tests fallaron!")
        sys.exit(1)


if __name__ == "__main__":
    main()
