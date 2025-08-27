# MELIChallenge

API FastAPI con Clean Architecture para análisis básico de logs.

## Estructura (Clean Architecture)
```
src/
  domain/
    entities/
      log_entry.py            # Entidad de dominio: LogEntry
    interfaces/
      anomaly_detector.py     # Puerto: interfaz del detector
  application/
    use_cases/
      analyze_logs.py         # Caso de uso AnalyzeLogsUseCase
  infrastructure/
    detectors/
      simple_rule_detector.py # Adaptador: detector mínimo (stub)
  presentation/
    fastapi_app/
      __init__.py             # App factory FastAPI
      routes.py               # Rutas HTTP (/analyze, /health)
wsgi.py                       # Entry point
requirements.txt
```

## Ejecutar localmente
```bash
python -m venv .venv
source .venv/bin/activate   # En Windows: .venv\\Scripts\\Activate
pip install -r requirements.txt
python wsgi.py  # inicia uvicorn en reload
```

## Endpoints
- POST `/analyze`
  - Request JSON ejemplo:
    ```json
    {
      "logs": [
        {"timestamp": "2025-01-01T00:00:00Z", "ip": "1.2.3.4", "method": "GET", "path": "/login", "status": 200},
        {"timestamp": "2025-01-01T00:00:01Z", "ip": "1.2.3.4", "method": "GET", "path": "/login", "status": 200},
        {"timestamp": "2025-01-01T00:00:02Z", "ip": "1.2.3.4", "method": "GET", "path": "/login", "status": 200}
      ]
    }
    ```
  - Response JSON ejemplo:
    ```json
    {"is_threat": true, "suggested_action": "block", "score": 0.7}
    ```

- GET `/health` → `{ "status": "ok" }`

## Notas de diseño
- Capa `domain`: contratos y entidades puras (sin dependencias externas).
- Capa `application`: casos de uso orquestan puertos del dominio.
- Capa `infrastructure`: implementaciones concretas (adaptadores) de puertos.
- Capa `presentation`: framework FastAPI y capa HTTP.

## Próximos pasos (cuando avances con IA/agentes)
- Reemplazar `SimpleRuleDetector` por un detector ML (Isolation Forest, etc.).
- Validación y schemas con pydantic o marshmallow.
- Logging estructurado y trazabilidad.
- Docker/compose y CI.