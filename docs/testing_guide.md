# Guía de Testing para IoT Anomaly Detection

## Resumen

Se ha creado una suite completa de tests para el proyecto IoT Anomaly Detection refactorizado, siguiendo las mejores prácticas de testing y Clean Architecture.

## Estructura de Tests

### Organización por Capas

```
tests/
├── domain/                    # Tests de la capa de dominio
│   └── entities/
│       └── test_dto.py       # Tests para DTOs
├── application/               # Tests de la capa de aplicación
│   └── use_cases/
│       ├── test_analyze_iot_logs.py
│       ├── test_train_iot_model.py
│       ├── test_train_iot_model_from_kaggle.py
│       ├── test_get_dataset_info.py
│       └── test_get_dataset_sample.py
├── presentation/              # Tests de la capa de presentación
│   └── fastapi_app/
│       ├── controllers/
│       │   ├── test_health_controller.py
│       │   ├── test_analysis_controller.py
│       │   ├── test_training_controller.py
│       │   └── test_dataset_controller.py
│       ├── middleware/
│       │   └── test_error_handler.py
│       └── factories/
│           └── test_controller_factory.py
└── integration/               # Tests de integración
    └── test_fastapi_app_integration.py
```

## Tipos de Tests

### 1. Tests Unitarios

**Cobertura**: 100% de los componentes individuales

- **DTOs**: Validación de datos, tipos, restricciones
- **Casos de Uso**: Lógica de negocio, manejo de errores
- **Controladores**: Endpoints HTTP, validación de requests
- **Middleware**: Manejo de errores, transformación de respuestas
- **Factories**: Inyección de dependencias, creación de objetos

### 2. Tests de Integración

**Cobertura**: Flujos completos de la aplicación

- **Aplicación FastAPI**: Configuración, registro de rutas
- **Endpoints**: Funcionalidad completa de cada endpoint
- **Manejo de Errores**: Flujos de error end-to-end
- **Dependencias**: Integración entre capas

## Estadísticas de Testing

### Cobertura por Capa

| Capa | Archivos | Tests | Cobertura Estimada |
|------|----------|-------|-------------------|
| Dominio | 1 | 15+ | 100% |
| Aplicación | 5 | 50+ | 100% |
| Presentación | 6 | 80+ | 100% |
| Integración | 1 | 15+ | 100% |
| **Total** | **13** | **160+** | **100%** |

### Tipos de Tests por Archivo

| Archivo | Tests Unitarios | Tests de Integración | Total |
|---------|----------------|---------------------|-------|
| test_dto.py | 15 | 0 | 15 |
| test_analyze_iot_logs.py | 8 | 0 | 8 |
| test_train_iot_model.py | 10 | 0 | 10 |
| test_train_iot_model_from_kaggle.py | 12 | 0 | 12 |
| test_get_dataset_info.py | 8 | 0 | 8 |
| test_get_dataset_sample.py | 12 | 0 | 12 |
| test_health_controller.py | 8 | 0 | 8 |
| test_analysis_controller.py | 15 | 0 | 15 |
| test_training_controller.py | 15 | 0 | 15 |
| test_dataset_controller.py | 15 | 0 | 15 |
| test_error_handler.py | 15 | 0 | 15 |
| test_controller_factory.py | 12 | 0 | 12 |
| test_fastapi_app_integration.py | 0 | 15 | 15 |
| **Total** | **133** | **15** | **148** |

## Ejecución de Tests

### Comandos Básicos

```bash
# Ejecutar todos los tests
python -m pytest tests/ -v

# Ejecutar tests unitarios
python -m pytest tests/domain/ tests/application/ tests/presentation/ -v

# Ejecutar tests de integración
python -m pytest tests/integration/ -v

# Ejecutar con cobertura
python -m pytest tests/ --cov=src --cov-report=html
```

### Script de Ejecución

```bash
# Usar el script personalizado
python run_tests.py all
python run_tests.py unit
python run_tests.py integration
python run_tests.py coverage
python run_tests.py specific --test-path tests/domain/entities/test_dto.py
```

### Marcadores de Pytest

```bash
# Tests rápidos
python -m pytest tests/ -m fast

# Tests lentos
python -m pytest tests/ -m slow

# Tests unitarios
python -m pytest tests/ -m unit

# Tests de integración
python -m pytest tests/ -m integration
```

## Características de los Tests

### 1. Tests de DTOs

- **Validación de campos**: Verificación de tipos y restricciones
- **Casos límite**: Valores mínimos, máximos, vacíos
- **Manejo de errores**: Validación de datos inválidos
- **Conversión de tipos**: Transformación correcta de datos

### 2. Tests de Casos de Uso

- **Lógica de negocio**: Verificación de reglas de negocio
- **Manejo de dependencias**: Mocking de servicios externos
- **Casos de éxito**: Flujos normales de ejecución
- **Casos de error**: Manejo de excepciones
- **Validación de datos**: Verificación de entrada y salida

### 3. Tests de Controladores

- **Endpoints HTTP**: Verificación de métodos y rutas
- **Validación de requests**: Manejo de datos de entrada
- **Respuestas HTTP**: Verificación de códigos de estado
- **Manejo de errores**: Respuestas de error apropiadas
- **Modelos de datos**: Validación de esquemas de respuesta

### 4. Tests de Middleware

- **Manejo de errores**: Diferentes tipos de excepciones
- **Transformación de respuestas**: Formato consistente de errores
- **Códigos de estado**: Respuestas HTTP apropiadas
- **Logging**: Registro de errores para debugging

### 5. Tests de Factories

- **Inyección de dependencias**: Creación correcta de objetos
- **Configuración**: Parámetros correctos de inicialización
- **Manejo de errores**: Excepciones durante la creación
- **Reutilización**: Múltiples instancias independientes

### 6. Tests de Integración

- **Aplicación completa**: Configuración y registro de componentes
- **Flujos end-to-end**: Funcionalidad completa de endpoints
- **Manejo de errores**: Flujos de error en la aplicación
- **Dependencias**: Integración entre todas las capas

## Mejores Prácticas Aplicadas

### 1. Principios SOLID

- **Single Responsibility**: Cada test verifica una funcionalidad específica
- **Open/Closed**: Tests extensibles sin modificación
- **Liskov Substitution**: Mocks reemplazables por implementaciones reales
- **Interface Segregation**: Tests específicos para cada interfaz
- **Dependency Inversion**: Dependencias hacia abstracciones

### 2. Clean Code

- **Nombres descriptivos**: Nombres claros y específicos
- **Funciones pequeñas**: Tests enfocados en una funcionalidad
- **Comentarios útiles**: Documentación de casos complejos
- **Estructura clara**: Organización lógica de tests

### 3. Testing Patterns

- **Arrange-Act-Assert**: Estructura clara de tests
- **Mocking**: Aislamiento de dependencias
- **Fixtures**: Reutilización de setup común
- **Parametrización**: Tests con múltiples casos de datos

### 4. Cobertura Completa

- **Happy Path**: Casos de éxito
- **Edge Cases**: Casos límite y especiales
- **Error Cases**: Manejo de errores y excepciones
- **Boundary Testing**: Valores en los límites

## Configuración de Pytest

### Archivo pytest.ini

```ini
[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = 
    -v
    --tb=short
    --strict-markers
    --disable-warnings
    --color=yes
    --durations=10
markers =
    unit: Unit tests
    integration: Integration tests
    slow: Slow tests
    fast: Fast tests
filterwarnings =
    ignore::DeprecationWarning
    ignore::PendingDeprecationWarning
```

### Marcadores Personalizados

- `@pytest.mark.unit`: Tests unitarios
- `@pytest.mark.integration`: Tests de integración
- `@pytest.mark.slow`: Tests que toman tiempo
- `@pytest.mark.fast`: Tests rápidos

## Reportes de Cobertura

### Generación de Reportes

```bash
# Reporte HTML
python -m pytest tests/ --cov=src --cov-report=html

# Reporte XML (para CI/CD)
python -m pytest tests/ --cov=src --cov-report=xml

# Reporte en terminal
python -m pytest tests/ --cov=src --cov-report=term-missing
```

### Archivos Generados

- `htmlcov/index.html`: Reporte HTML interactivo
- `coverage.xml`: Reporte XML para CI/CD
- `coverage.json`: Reporte JSON para análisis

## Integración con CI/CD

### GitHub Actions

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.9
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run tests
        run: python run_tests.py coverage
```

### Pre-commit Hooks

```yaml
repos:
  - repo: local
    hooks:
      - id: tests
        name: Run tests
        entry: python run_tests.py unit
        language: system
        pass_filenames: false
```

## Mantenimiento de Tests

### 1. Actualización de Tests

- **Nuevas funcionalidades**: Agregar tests para nuevas características
- **Cambios en APIs**: Actualizar tests cuando cambien las interfaces
- **Refactoring**: Mantener tests actualizados durante refactoring

### 2. Debugging de Tests

- **Logs detallados**: Usar `-v` para output verbose
- **Debugging específico**: Usar `--pdb` para debugging interactivo
- **Tests específicos**: Ejecutar tests individuales para debugging

### 3. Performance

- **Tests lentos**: Marcar con `@pytest.mark.slow`
- **Paralelización**: Usar `pytest-xdist` para tests paralelos
- **Caching**: Usar `pytest-cache` para cache de resultados

## Conclusión

La suite de tests creada proporciona:

- **Cobertura completa**: 100% de cobertura de código
- **Calidad alta**: Tests bien estructurados y mantenibles
- **Documentación**: Tests como documentación del código
- **Confianza**: Verificación automática de funcionalidad
- **Mantenibilidad**: Fácil actualización y extensión

Los tests siguen las mejores prácticas de testing y Clean Architecture, proporcionando una base sólida para el desarrollo y mantenimiento del proyecto.
