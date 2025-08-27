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
      ml_isolation_forest_detector.py # Detector ML (Isolation Forest)
    services/
      kaggle_service.py       # Descarga dataset (kagglehub)
      csic_parser.py          # Parser/limpieza CSIC → LogEntry
  presentation/
    fastapi_app/
      __init__.py             # App factory FastAPI
      routes.py               # Rutas HTTP (/analyze, /train, /train/kaggle, /health)
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
- POST `/train/kaggle` (recomendado)
  - Descarga el dataset público CSIC 2010 con `kagglehub`, lo parsea y entrena el modelo Isolation Forest.
  - Requiere `kagglehub` (ya en requirements) y acceso público al dataset.
  - Ejemplo:
    ```bash
    curl -X POST http://localhost:8000/train/kaggle
    ```
  - Respuesta ejemplo:
    ```json
    {"status":"trained","samples":12345,"dataset":"ispangler/csic-2010-web-application-attacks"}
    ```

- POST `/train`
  - Entrena el modelo con un lote de logs enviado por el cliente.
  - Request JSON (igual formato que /analyze):
    ```json
    {"logs":[{"timestamp":"2025-01-01T00:00:00Z","ip":"1.2.3.4","method":"GET","path":"/","status":200}]}
    ```
  - Respuesta: `{"status":"trained","samples":N}`.

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

### Ejemplos de requests (JSON) para POST `/analyze`
```json
{
  "logs": [
    {"timestamp": "2025-01-01T00:00:00Z", "ip": "10.0.0.1", "method": "GET", "path": "/", "status": 200, "response_time_ms": 12},
    {"timestamp": "2025-01-01T00:00:01Z", "ip": "10.0.0.1", "method": "GET", "path": "/products", "status": 200, "response_time_ms": 25},
    {"timestamp": "2025-01-01T00:00:02Z", "ip": "10.0.0.1", "method": "GET", "path": "/cart", "status": 200, "response_time_ms": 18}
  ]
}
```

```json
{
  "logs": [
    {"timestamp": "2025-01-01T10:00:00Z", "ip": "203.0.113.5", "method": "POST", "path": "/login", "status": 401, "response_time_ms": 40},
    {"timestamp": "2025-01-01T10:00:02Z", "ip": "203.0.113.5", "method": "POST", "path": "/login", "status": 401, "response_time_ms": 38},
    {"timestamp": "2025-01-01T10:00:04Z", "ip": "203.0.113.5", "method": "POST", "path": "/login", "status": 401, "response_time_ms": 42}
  ]
}
```

```json
{
  "logs": [
    {"timestamp": "2025-01-02T09:00:00Z", "ip": "198.51.100.9", "method": "GET", "path": "/admin", "status": 404, "response_time_ms": 15},
    {"timestamp": "2025-01-02T09:00:01Z", "ip": "198.51.100.9", "method": "GET", "path": "/.env", "status": 404, "response_time_ms": 14},
    {"timestamp": "2025-01-02T09:00:02Z", "ip": "198.51.100.9", "method": "GET", "path": "/search?q=%27%20OR%201%3D1--", "status": 400, "response_time_ms": 20}
  ]
}
```

```json
{
  "logs": [
    {"timestamp": "2025-01-03T12:00:00Z", "ip": "192.0.2.7", "method": "GET", "path": "/checkout", "status": 502, "response_time_ms": 120},
    {"timestamp": "2025-01-03T12:00:02Z", "ip": "192.0.2.7", "method": "GET", "path": "/checkout", "status": 503, "response_time_ms": 200}
  ]
}
```

```json
{
  "logs": [
    {"timestamp": "2025-01-04T08:00:00Z", "ip": "203.0.113.55", "method": "GET", "path": "/api/v1/item?id=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "status": 200, "response_time_ms": 30}
  ]
}
```

## Detector ML (Isolation Forest)
- El sistema usa `ml_isolation_forest_detector.py`.
- Si existe `models/isoforest.joblib`, lo carga; si no, se entrena automáticamente (en `/train/kaggle` o `/train`).
- Feature engineering mínima: IP descompuesta, método, longitud de path, flag de query, log(status), longitud de user agent, log(response_time_ms).
- El endpoint `/analyze` devuelve `score` en [0,1] (máximo del lote) y `is_threat` según umbral (0.7 por defecto).

## Notas de diseño
- Capa `domain`: contratos y entidades puras (sin dependencias externas).
- Capa `application`: casos de uso orquestan puertos del dominio.
- Capa `infrastructure`: implementaciones concretas (adaptadores) de puertos.
- Capa `presentation`: framework FastAPI y capa HTTP.

## Próximos pasos
- Validación robusta con Pydantic (límites de tamaño, timeouts, tipos estrictos).
- Calibración de umbral/contamination con un 10% etiquetado (F1/PR-curve).
- Persistencia de eventos y métricas (DB/OLAP) y dashboard.
- Streaming (Kafka/Kinesis) y ventanas por IP/usuario.
- Explainability (SHAP/feature importances) y alerting.
- Seguridad: auth (API key/JWT), CORS restrictivo, rate limiting.
- Observabilidad: Prometheus, OpenTelemetry.
- Docker/compose y CI.
- Logging estructurado y trazabilidad.
