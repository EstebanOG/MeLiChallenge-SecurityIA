from __future__ import annotations

from typing import List, Optional, Tuple, Dict, Any
import math
import os
import json
import time

# Importaciones condicionales para evitar errores
try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False
    print("⚠️ joblib no disponible, el detector funcionará en modo básico")

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    print("⚠️ pandas no disponible, algunas funciones estarán limitadas")

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("⚠️ numpy no disponible, el detector funcionará en modo básico")

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler, RobustScaler, MinMaxScaler
    from sklearn.model_selection import GridSearchCV, cross_val_score
    from sklearn.metrics import roc_auc_score, precision_score, recall_score, f1_score, confusion_matrix
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("⚠️ scikit-learn no disponible, el detector funcionará en modo básico")

from ...domain.entities.dto import ThreatLogItemDTO, ThreatLogItemWithLabelDTO
from ...application.interfaces.anomaly_detector import AnomalyDetector, AnomalyResult


class IsolationForestDetector(AnomalyDetector):
    """
    ML-based anomaly detector using Isolation Forest.

    - Loads a pre-trained model from disk if available.
    - If no model is found, trains unsupervised on the incoming batch
      (assumes majority are normal) and then scores.
    - Can use labeled data for calibration and threshold optimization.
    - Returns an aggregate batch score in [0, 1] and a threat flag when the
      maximum anomaly score in the batch exceeds the configured threshold.
    """

    def __init__(
        self,
        model_path: str = "models/isoforest.joblib",
        random_state: int = 42,
        contamination: float = 0.2,
        threshold: float = 0.5,
        n_estimators: int = 200,
        max_samples: str | int = "auto",
        use_labeled_calibration: bool = True,
        scaler_type: str = "robust",  # 'standard', 'robust', 'minmax', 'none'
        max_features: float = 1.0,
        bootstrap: bool = False,
        warm_start: bool = False,
    ) -> None:
        self.model_path = model_path
        self.random_state = random_state
        self.contamination = contamination
        self.threshold = threshold
        # Adjust threshold based on contamination for better calibration
        self._adjusted_threshold = threshold
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.max_features = max_features
        self.bootstrap = bootstrap
        self.warm_start = warm_start
        self.use_labeled_calibration = use_labeled_calibration
        self.scaler_type = scaler_type
        self._model: Optional[IsolationForest] = None
        self._scaler: Optional[object] = None
        self._score_stats: Optional[dict] = None
        self._calibration_stats: Optional[dict] = None
        self._feature_names: List[str] = [
            'network_packet_size', 'login_attempts', 'session_duration',
            'ip_reputation_score', 'failed_logins', 'unusual_time_access',
            'protocol_type', 'encryption_used', 'browser_type'
        ]
        
        # Solo cargar modelo si las dependencias están disponibles
        if all([JOBLIB_AVAILABLE, NUMPY_AVAILABLE, SKLEARN_AVAILABLE]):
            self._ensure_model_loaded()

    def _ensure_model_loaded(self) -> None:
        """Carga el modelo pre-entrenado si existe."""
        if self._model is not None or not JOBLIB_AVAILABLE:
            return
            
        if os.path.exists(self.model_path):
            try:
                model_data = joblib.load(self.model_path)
                
                # Manejar formato nuevo (con scaler) y formato antiguo (solo modelo)
                if isinstance(model_data, dict) and 'model' in model_data:
                    self._model = model_data['model']
                    self._scaler = model_data.get('scaler')
                    self.scaler_type = model_data.get('scaler_type', 'none')
                    self._feature_names = model_data.get('feature_names', self._feature_names)
                    # Cargar threshold ajustado si existe
                    if 'threshold' in model_data:
                        self._adjusted_threshold = model_data['threshold']
                    else:
                        self._adjusted_threshold = self.threshold
                    print(f"✅ Modelo y scaler cargados desde: {self.model_path}")
                else:
                    # Formato antiguo - solo modelo
                    self._model = model_data
                    self._scaler = None
                    self._adjusted_threshold = self.threshold
                    print(f"✅ Modelo cargado desde: {self.model_path} (formato antiguo)")
                
                # Cargar estadísticas si existen
                stats_path = self.model_path.replace('.joblib', '_stats.json')
                if os.path.exists(stats_path):
                    with open(stats_path, 'r') as f:
                        self._score_stats = json.load(f)
                
                calib_path = self.model_path.replace('.joblib', '_calibration.json')
                if os.path.exists(calib_path):
                    with open(calib_path, 'r') as f:
                        self._calibration_stats = json.load(f)
                        
            except Exception as e:
                print(f"⚠️ Error cargando modelo: {e}")
                self._model = None
                self._scaler = None

    def _build_model(self) -> Optional[IsolationForest]:
        """Construye un nuevo modelo Isolation Forest."""
        if not SKLEARN_AVAILABLE:
            print("❌ scikit-learn no disponible para construir modelo")
            return None
            
        return IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            max_samples=self.max_samples,
            max_features=self.max_features,
            bootstrap=self.bootstrap,
            warm_start=self.warm_start,
            n_jobs=-1,
        )
    
    def _calibrate_threshold_from_contamination(self, X_scaled: np.ndarray) -> None:
        """Calibra el threshold basado en el parámetro de contamination."""
        if self._model is None:
            return
            
        try:
            # Obtener scores de anomalía
            anomaly_scores = self._model.score_samples(X_scaled)
            anomaly_probs = (anomaly_scores + 1) / 2  # Convert [-1, 1] to [0, 1]
            
            # Calcular threshold basado en contamination
            # Si contamination = 0.1, queremos que el 10% de los datos sean considerados anómalos
            threshold_percentile = (1 - self.contamination) * 100
            self._adjusted_threshold = float(np.percentile(anomaly_probs, threshold_percentile))
            
            print(f"🎯 Threshold calibrado: {self._adjusted_threshold:.4f} (contamination: {self.contamination})")
            
        except Exception as e:
            print(f"⚠️ Error calibrando threshold: {e}")
            self._adjusted_threshold = self.threshold
    
    def _build_scaler(self) -> Optional[object]:
        """Construye el scaler apropiado."""
        if not SKLEARN_AVAILABLE:
            return None
            
        if self.scaler_type == "standard":
            return StandardScaler()
        elif self.scaler_type == "robust":
            return RobustScaler()
        elif self.scaler_type == "minmax":
            return MinMaxScaler()
        else:
            return None

    def _encode_logs(self, logs: List[ThreatLogItemDTO]) -> Optional[np.ndarray]:
        """Transforma ThreatLogItemDTO list en matriz de features numéricas."""
        if not NUMPY_AVAILABLE:
            print("❌ numpy no disponible para encoding")
            return None
            
        # Mapeo de protocolos a números (más completo)
        protocol_types = {"TCP": 0, "UDP": 1, "ICMP": 2, "HTTP": 3, "HTTPS": 4, "FTP": 5, "SSH": 6}
        
        # Mapeo de tipos de encriptación a números (más completo)
        encryption_types = {"None": 0, "DES": 1, "AES": 2, "TLS": 3, "SSL": 4, "MD5": 5, "SHA1": 6, "SHA256": 7}
        
        # Mapeo de tipos de navegador a números (más completo)
        browser_types = {"Chrome": 0, "Firefox": 1, "Edge": 2, "Safari": 3, "Opera": 4, "Unknown": 5, "Bot": 6}

        X: List[List[float]] = []
        for entry in logs:
            try:
                # Features numéricas del dataset de threat intelligence
                network_packet_size = float(entry.network_packet_size)
                login_attempts = float(entry.login_attempts)
                session_duration = float(entry.session_duration)
                ip_reputation_score = float(entry.ip_reputation_score)
                failed_logins = float(entry.failed_logins)
                unusual_time_access = float(entry.unusual_time_access)
                
                # Features categóricas codificadas
                protocol_type = protocol_types.get(entry.protocol_type, 0)
                encryption_used = encryption_types.get(entry.encryption_used, 0)
                browser_type = browser_types.get(entry.browser_type, 0)
                
                # Features sin normalización manual (el scaler se encargará)
                features = [
                    network_packet_size,
                    login_attempts,
                    session_duration,
                    ip_reputation_score,
                    failed_logins,
                    unusual_time_access,
                    protocol_type,
                    encryption_used,
                    browser_type
                ]
                X.append(features)
            except (ValueError, TypeError) as e:
                print(f"⚠️ Error procesando log entry: {e}")
                # Usar valores por defecto para entradas problemáticas
                features = [0.0] * 9
                X.append(features)
        
        return np.array(X)

    def fit(self, logs: List[ThreatLogItemDTO]) -> None:
        """Entrena el modelo con los logs proporcionados."""
        if not all([NUMPY_AVAILABLE, SKLEARN_AVAILABLE]):
            print("❌ Dependencias no disponibles para entrenamiento")
            return
            
        if not logs:
            print("⚠️ No hay logs para entrenar")
            return
            
        print(f"🚀 Entrenando modelo con {len(logs)} logs...")
        
        # Preparar features
        X = self._encode_logs(logs)
        if X is None:
            print("❌ Error preparando features")
            return
        
        # Construir y entrenar scaler
        self._scaler = self._build_scaler()
        if self._scaler is not None:
            X_scaled = self._scaler.fit_transform(X)
            print(f"⚖️ Features escaladas usando {self.scaler_type} scaler")
        else:
            X_scaled = X
            print("⚖️ Sin escalado de features")
            
        # Construir y entrenar modelo
        self._model = self._build_model()
        if self._model is None:
            print("❌ Error construyendo modelo")
            return
            
        self._model.fit(X_scaled)
        print(f"✅ Modelo entrenado con {X_scaled.shape[1]} features")
        
        # Calibrar threshold basado en contamination
        self._calibrate_threshold_from_contamination(X_scaled)
        
        # Guardar modelo y scaler si es posible
        if JOBLIB_AVAILABLE:
            try:
                os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
                
                # Guardar modelo y scaler juntos
                model_data = {
                    'model': self._model,
                    'scaler': self._scaler,
                    'scaler_type': self.scaler_type,
                    'feature_names': self._feature_names,
                    'threshold': self._adjusted_threshold
                }
                joblib.dump(model_data, self.model_path)
                print(f"💾 Modelo y scaler guardados en: {self.model_path}")
            except Exception as e:
                print(f"⚠️ Error guardando modelo: {e}")

    def detect_anomalies(self, logs: List[ThreatLogItemDTO]) -> AnomalyResult:
        """Detecta anomalías en un lote de logs."""
        if not logs:
            return AnomalyResult(
                batch_score=0.0,
                threat_detected=False,
                anomaly_scores=[],
                confidence=0.0
            )
            
        if not all([NUMPY_AVAILABLE, SKLEARN_AVAILABLE]):
            print("❌ Dependencias no disponibles para detección")
            return AnomalyResult(
                batch_score=0.0,
                threat_detected=False,
                anomaly_scores=[0.0] * len(logs),
                confidence=0.0
            )
        
        # Preparar features
        X = self._encode_logs(logs)
        if X is None:
            print("❌ Error preparando features")
            return AnomalyResult(
                batch_score=0.0,
                threat_detected=False,
                anomaly_scores=[0.0] * len(logs),
                confidence=0.0
            )
        
        # Aplicar scaler si está disponible
        if self._scaler is not None:
            X_scaled = self._scaler.transform(X)
        else:
            X_scaled = X
        
        # Si no hay modelo, entrenar uno básico
        if self._model is None:
            print("⚠️ No hay modelo, entrenando uno básico...")
            self.fit(logs)
            if self._model is None:
                print("❌ Error entrenando modelo")
                return AnomalyResult(
                    batch_score=0.0,
                    threat_detected=False,
                    anomaly_scores=[0.0] * len(logs),
                    confidence=0.0
                )
            # Re-aplicar scaler después del entrenamiento
            if self._scaler is not None:
                X_scaled = self._scaler.transform(X)
        
        # Predecir anomalías
        try:
            anomaly_scores = self._model.score_samples(X_scaled)
            # Convertir scores a probabilidades (0 = normal, 1 = anómalo)
            # Isolation Forest scores are already in [-1, 1] range, normalize to [0, 1]
            anomaly_probs = (anomaly_scores + 1) / 2  # Convert [-1, 1] to [0, 1]
            
            # Calcular score del batch con diferentes métricas
            batch_score_mean = float(np.mean(anomaly_probs))
            batch_score_median = float(np.median(anomaly_probs))
            batch_score_max = float(np.max(anomaly_probs))
            
            # Detectar amenaza si algún score supera el umbral ajustado
            threat_detected = bool(np.any(anomaly_probs > self._adjusted_threshold))
            
            # Calcular confianza mejorada
            confidence = self._calculate_confidence(anomaly_probs, X_scaled)
            
            # Calcular métricas adicionales
            anomaly_count = int(np.sum(anomaly_probs > self._adjusted_threshold))
            anomaly_ratio = float(anomaly_count / len(anomaly_probs))
            
            # Calcular severidad de la amenaza
            threat_severity = self._calculate_threat_severity(anomaly_probs)
            
            return AnomalyResult(
                batch_score=batch_score_mean,
                threat_detected=threat_detected,
                anomaly_scores=anomaly_probs.tolist(),
                confidence=confidence
            )
            
        except Exception as e:
            print(f"❌ Error durante detección: {e}")
            return AnomalyResult(
                batch_score=0.0,
                threat_detected=False,
                anomaly_scores=[0.0] * len(logs),
                confidence=0.0
            )
    
    def fit_from_dataset(self, dataset_path: str) -> Dict[str, Any]:
        """Entrena el modelo desde un archivo de dataset."""
        import time
        import pandas as pd
        
        if not all([NUMPY_AVAILABLE, SKLEARN_AVAILABLE]):
            raise Exception("Dependencias no disponibles para entrenamiento")
        
        if not os.path.exists(dataset_path):
            raise FileNotFoundError(f"Dataset no encontrado: {dataset_path}")
        
        print(f"🚀 Cargando dataset desde: {dataset_path}")
        
        # Cargar dataset
        df = pd.read_csv(dataset_path)
        print(f"📊 Dataset cargado: {len(df)} filas, {len(df.columns)} columnas")
        
        # Convertir a LogEntry objects
        log_entries = []
        for _, row in df.iterrows():
            try:
                log_entry = ThreatLogItemWithLabelDTO(
                    session_id=str(row['session_id']),
                    network_packet_size=int(row['network_packet_size']),
                    protocol_type=str(row['protocol_type']),
                    login_attempts=int(row['login_attempts']),
                    session_duration=float(row['session_duration']),
                    encryption_used=str(row['encryption_used']) if pd.notna(row['encryption_used']) else 'None',
                    ip_reputation_score=float(row['ip_reputation_score']),
                    failed_logins=int(row['failed_logins']),
                    browser_type=str(row['browser_type']),
                    unusual_time_access=bool(row['unusual_time_access']),
                    attack_detected=bool(row['attack_detected'])
                )
                log_entries.append(log_entry)
            except Exception as e:
                print(f"⚠️ Error procesando fila {row.get('session_id', 'unknown')}: {e}")
                continue
        
        print(f"✅ {len(log_entries)} logs procesados correctamente")
        
        # Entrenar modelo
        start_time = time.time()
        self.fit(log_entries)
        training_time = time.time() - start_time
        
        # Preparar features para evaluación
        X = self._encode_logs(log_entries)
        
        # Calcular métricas de evaluación si hay etiquetas disponibles
        evaluation_metrics = self._calculate_evaluation_metrics(log_entries, X) if X is not None else {}
        
        # Guardar estadísticas
        stats = {
            'contamination': self.contamination,
            'n_estimators': self.n_estimators,
            'threshold': self.threshold,
            'train_samples': len(log_entries),
            'model_ready': self._model is not None,
            'training_time': training_time,
            **evaluation_metrics  # Incluir métricas de evaluación
        }
        
        # Guardar estadísticas en archivo
        if JOBLIB_AVAILABLE:
            try:
                stats_path = self.model_path.replace('.joblib', '_stats.json')
                with open(stats_path, 'w') as f:
                    json.dump(stats, f, indent=2)
                print(f"💾 Estadísticas guardadas en: {stats_path}")
            except Exception as e:
                print(f"⚠️ Error guardando estadísticas: {e}")
        
        return stats
    
    def is_ready(self) -> bool:
        """Verifica si el modelo está listo para inferencia."""
        return self._model is not None
    
    def _calculate_evaluation_metrics(self, log_entries: List[ThreatLogItemDTO], X: np.ndarray) -> Dict[str, Any]:
        """Calcula métricas de evaluación robustas usando las etiquetas del dataset."""
        if not all([NUMPY_AVAILABLE, SKLEARN_AVAILABLE]) or self._model is None:
            return {}
        
        try:
            from sklearn.metrics import (
                roc_auc_score, precision_score, recall_score, f1_score, 
                confusion_matrix, classification_report, roc_curve, precision_recall_curve
            )
            
            # Obtener etiquetas reales
            y_true = np.array([int(entry.attack_detected) for entry in log_entries])
            
            # Verificar que hay al menos dos clases
            unique_classes = np.unique(y_true)
            if len(unique_classes) < 2:
                return {
                    'error': 'Dataset contains only one class, cannot calculate classification metrics',
                    'class_distribution': {str(cls): int(np.sum(y_true == cls)) for cls in unique_classes}
                }
            
            # Obtener predicciones del modelo
            anomaly_scores = self._model.score_samples(X)
            anomaly_probs = 1.0 - anomaly_scores  # Convertir a probabilidades
            
            # Usar threshold para obtener predicciones binarias
            y_pred = (anomaly_probs > self.threshold).astype(int)
            
            # Métricas básicas
            try:
                auc_score = roc_auc_score(y_true, anomaly_probs)
            except ValueError:
                auc_score = 0.0
            
            precision = precision_score(y_true, y_pred, zero_division=0)
            recall = recall_score(y_true, y_pred, zero_division=0)
            f1 = f1_score(y_true, y_pred, zero_division=0)
            
            # Calcular matriz de confusión
            cm = confusion_matrix(y_true, y_pred)
            if cm.size == 4:  # 2x2 matrix
                tn, fp, fn, tp = cm.ravel()
            else:
                # Manejar casos con una sola clase
                tn, fp, fn, tp = 0, 0, 0, 0
                if len(unique_classes) == 1:
                    if unique_classes[0] == 0:
                        tn = len(y_true)
                    else:
                        tp = len(y_true)
            
            # Métricas adicionales
            accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0
            specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
            sensitivity = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            
            # Métricas balanceadas
            precision_macro = precision_score(y_true, y_pred, average='macro', zero_division=0)
            recall_macro = recall_score(y_true, y_pred, average='macro', zero_division=0)
            f1_macro = f1_score(y_true, y_pred, average='macro', zero_division=0)
            
            # Calcular ROC curve y PR curve
            try:
                fpr, tpr, _ = roc_curve(y_true, anomaly_probs)
                precision_curve, recall_curve, _ = precision_recall_curve(y_true, anomaly_probs)
                
                # Calcular área bajo la curva PR
                pr_auc = np.trapz(precision_curve, recall_curve)
            except:
                fpr, tpr = [], []
                precision_curve, recall_curve = [], []
                pr_auc = 0.0
            
            # Análisis de threshold
            threshold_analysis = self._analyze_threshold_performance(y_true, anomaly_probs)
            
            # Distribución de clases
            class_distribution = {
                'normal': int(np.sum(y_true == 0)),
                'attack': int(np.sum(y_true == 1)),
                'total': len(y_true)
            }
            
            # Métricas de calibración
            calibration_metrics = self._calculate_calibration_metrics(y_true, anomaly_probs)
            
            return {
                'basic_metrics': {
                    'auc_score': float(auc_score),
                    'pr_auc': float(pr_auc),
                    'precision': float(precision),
                    'recall': float(recall),
                    'f1_score': float(f1),
                    'accuracy': float(accuracy),
                    'specificity': float(specificity),
                    'sensitivity': float(sensitivity)
                },
                'macro_metrics': {
                    'precision_macro': float(precision_macro),
                    'recall_macro': float(recall_macro),
                    'f1_macro': float(f1_macro)
                },
                'confusion_matrix': {
                    'true_positives': int(tp),
                    'true_negatives': int(tn),
                    'false_positives': int(fp),
                    'false_negatives': int(fn)
                },
                'threshold_analysis': threshold_analysis,
                'class_distribution': class_distribution,
                'calibration_metrics': calibration_metrics,
                'roc_curve': {
                    'fpr': fpr.tolist() if hasattr(fpr, 'tolist') else list(fpr),
                    'tpr': tpr.tolist() if hasattr(tpr, 'tolist') else list(tpr)
                },
                'pr_curve': {
                    'precision': precision_curve.tolist() if hasattr(precision_curve, 'tolist') else list(precision_curve),
                    'recall': recall_curve.tolist() if hasattr(recall_curve, 'tolist') else list(recall_curve)
                }
            }
            
        except Exception as e:
            print(f"⚠️ Error calculando métricas de evaluación: {e}")
            return {'error': str(e)}
    
    def _analyze_threshold_performance(self, y_true: np.ndarray, y_probs: np.ndarray) -> Dict[str, Any]:
        """
        Analiza el rendimiento del modelo en diferentes thresholds.
        
        Args:
            y_true: Etiquetas reales
            y_probs: Probabilidades de anomalía
            
        Returns:
            Diccionario con análisis de threshold
        """
        thresholds = np.arange(0.1, 0.9, 0.05)
        best_f1 = 0
        best_threshold = self.threshold
        threshold_metrics = []
        
        for threshold in thresholds:
            y_pred = (y_probs > threshold).astype(int)
            
            if len(np.unique(y_pred)) > 1:  # Solo si hay predicciones de ambas clases
                precision = precision_score(y_true, y_pred, zero_division=0)
                recall = recall_score(y_true, y_pred, zero_division=0)
                f1 = f1_score(y_true, y_pred, zero_division=0)
                
                threshold_metrics.append({
                    'threshold': float(threshold),
                    'precision': float(precision),
                    'recall': float(recall),
                    'f1_score': float(f1)
                })
                
                if f1 > best_f1:
                    best_f1 = f1
                    best_threshold = threshold
        
        return {
            'current_threshold': float(self.threshold),
            'best_threshold': float(best_threshold),
            'best_f1_score': float(best_f1),
            'threshold_metrics': threshold_metrics
        }
    
    def _calculate_calibration_metrics(self, y_true: np.ndarray, y_probs: np.ndarray) -> Dict[str, Any]:
        """
        Calcula métricas de calibración del modelo.
        
        Args:
            y_true: Etiquetas reales
            y_probs: Probabilidades de anomalía
            
        Returns:
            Diccionario con métricas de calibración
        """
        try:
            from sklearn.calibration import calibration_curve
            
            # Asegurar que las probabilidades estén en el rango [0, 1]
            y_probs = np.clip(y_probs, 0.0, 1.0)
            
            # Calcular curva de calibración
            fraction_of_positives, mean_predicted_value = calibration_curve(
                y_true, y_probs, n_bins=10
            )
            
            # Calcular Brier Score
            brier_score = np.mean((y_probs - y_true) ** 2)
            
            # Calcular Expected Calibration Error (ECE)
            n_bins = 10
            bin_boundaries = np.linspace(0, 1, n_bins + 1)
            bin_lowers = bin_boundaries[:-1]
            bin_uppers = bin_boundaries[1:]
            
            ece = 0
            for bin_lower, bin_upper in zip(bin_lowers, bin_uppers):
                in_bin = (y_probs > bin_lower) & (y_probs <= bin_upper)
                prop_in_bin = in_bin.mean()
                
                if prop_in_bin > 0:
                    accuracy_in_bin = y_true[in_bin].mean()
                    avg_confidence_in_bin = y_probs[in_bin].mean()
                    ece += np.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin
            
            return {
                'brier_score': float(brier_score),
                'expected_calibration_error': float(ece),
                'calibration_curve': {
                    'fraction_of_positives': fraction_of_positives.tolist(),
                    'mean_predicted_value': mean_predicted_value.tolist()
                }
            }
            
        except ImportError:
            return {'error': 'sklearn.calibration not available'}
        except Exception as e:
            return {'error': f'Calibration calculation failed: {str(e)}'}
    
    def optimize_hyperparameters(self, logs: List[ThreatLogItemDTO], cv_folds: int = 5) -> Dict[str, Any]:
        """
        Optimiza los hiperparámetros del modelo usando validación cruzada.
        
        Args:
            logs: Lista de logs para optimización
            cv_folds: Número de folds para validación cruzada
            
        Returns:
            Diccionario con mejores parámetros y métricas
        """
        if not all([NUMPY_AVAILABLE, SKLEARN_AVAILABLE]):
            print("❌ Dependencias no disponibles para optimización")
            return {}
            
        if not logs:
            print("⚠️ No hay logs para optimización")
            return {}
        
        print(f"🔍 Optimizando hiperparámetros con {len(logs)} logs...")
        
        # Preparar features
        X = self._encode_logs(logs)
        if X is None:
            print("❌ Error preparando features")
            return {}
        
        # Aplicar scaler
        if self._scaler is not None:
            X_scaled = self._scaler.transform(X)
        else:
            X_scaled = X
        
        # Definir grid de parámetros
        param_grid = {
            'n_estimators': [50, 100, 200, 300],
            'contamination': [0.05, 0.1, 0.15, 0.2],
            'max_samples': ['auto', 0.5, 0.7, 0.9],
            'max_features': [0.5, 0.7, 0.9, 1.0],
            'bootstrap': [True, False]
        }
        
        # Crear modelo base
        base_model = IsolationForest(
            random_state=self.random_state,
            n_jobs=-1
        )
        
        # GridSearch con validación cruzada
        print("🔄 Ejecutando GridSearch...")
        grid_search = GridSearchCV(
            base_model,
            param_grid,
            cv=cv_folds,
            scoring='neg_mean_squared_error',  # Para modelos no supervisados
            n_jobs=-1,
            verbose=1
        )
        
        grid_search.fit(X_scaled)
        
        # Actualizar parámetros del modelo
        best_params = grid_search.best_params_
        self.n_estimators = best_params['n_estimators']
        self.contamination = best_params['contamination']
        self.max_samples = best_params['max_samples']
        self.max_features = best_params['max_features']
        self.bootstrap = best_params['bootstrap']
        
        print(f"✅ Mejores parámetros encontrados: {best_params}")
        print(f"✅ Mejor score: {grid_search.best_score_:.4f}")
        
        # Entrenar modelo final con mejores parámetros
        self._model = grid_search.best_estimator_
        
        # Calcular métricas adicionales
        cv_scores = cross_val_score(
            self._model, X_scaled, 
            cv=cv_folds, scoring='neg_mean_squared_error'
        )
        
        results = {
            'best_params': best_params,
            'best_score': float(grid_search.best_score_),
            'cv_scores': cv_scores.tolist(),
            'cv_mean': float(cv_scores.mean()),
            'cv_std': float(cv_scores.std()),
            'n_samples': len(logs),
            'n_features': X_scaled.shape[1]
        }
        
        return results
    
    def calibrate_threshold(self, logs: List[ThreatLogItemDTO], target_fpr: float = 0.05) -> float:
        """
        Calibra el threshold basado en la tasa de falsos positivos objetivo.
        
        Args:
            logs: Lista de logs para calibración
            target_fpr: Tasa de falsos positivos objetivo (0.05 = 5%)
            
        Returns:
            Threshold calibrado
        """
        if not all([NUMPY_AVAILABLE, SKLEARN_AVAILABLE]) or self._model is None:
            print("❌ Modelo no disponible para calibración")
            return self.threshold
            
        if not logs:
            print("⚠️ No hay logs para calibración")
            return self.threshold
        
        print(f"🎯 Calibrando threshold con {len(logs)} logs (FPR objetivo: {target_fpr})")
        
        # Preparar features
        X = self._encode_logs(logs)
        if X is None:
            return self.threshold
        
        # Aplicar scaler
        if self._scaler is not None:
            X_scaled = self._scaler.transform(X)
        else:
            X_scaled = X
        
        # Obtener scores de anomalía
        anomaly_scores = self._model.score_samples(X_scaled)
        anomaly_probs = 1.0 - anomaly_scores
        
        # Calcular threshold basado en percentil
        threshold = float(np.percentile(anomaly_probs, (1 - target_fpr) * 100))
        
        print(f"✅ Threshold calibrado: {threshold:.4f}")
        self.threshold = threshold
        
        # Guardar estadísticas de calibración
        self._calibration_stats = {
            'threshold': threshold,
            'target_fpr': target_fpr,
            'score_percentiles': {
                'p50': float(np.percentile(anomaly_probs, 50)),
                'p75': float(np.percentile(anomaly_probs, 75)),
                'p90': float(np.percentile(anomaly_probs, 90)),
                'p95': float(np.percentile(anomaly_probs, 95)),
                'p99': float(np.percentile(anomaly_probs, 99))
            },
            'score_stats': {
                'mean': float(np.mean(anomaly_probs)),
                'std': float(np.std(anomaly_probs)),
                'min': float(np.min(anomaly_probs)),
                'max': float(np.max(anomaly_probs))
            }
        }
        
        return threshold
    
    def detect_outliers(self, logs: List[ThreatLogItemDTO], method: str = "iqr") -> List[bool]:
        """
        Detecta outliers usando diferentes métodos.
        
        Args:
            logs: Lista de logs para análisis
            method: Método de detección ('iqr', 'zscore', 'isolation')
            
        Returns:
            Lista de booleanos indicando si cada log es outlier
        """
        if not all([NUMPY_AVAILABLE, SKLEARN_AVAILABLE]):
            print("❌ Dependencias no disponibles para detección de outliers")
            return [False] * len(logs)
            
        if not logs:
            return []
        
        # Preparar features
        X = self._encode_logs(logs)
        if X is None:
            return [False] * len(logs)
        
        # Aplicar scaler
        if self._scaler is not None:
            X_scaled = self._scaler.transform(X)
        else:
            X_scaled = X
        
        outliers = []
        
        if method == "iqr":
            # Método IQR (Interquartile Range)
            for i in range(X_scaled.shape[1]):
                Q1 = np.percentile(X_scaled[:, i], 25)
                Q3 = np.percentile(X_scaled[:, i], 75)
                IQR = Q3 - Q1
                lower_bound = Q1 - 1.5 * IQR
                upper_bound = Q3 + 1.5 * IQR
                
                feature_outliers = (X_scaled[:, i] < lower_bound) | (X_scaled[:, i] > upper_bound)
                outliers.append(feature_outliers)
            
            # Un log es outlier si es outlier en cualquier característica
            outliers = np.any(outliers, axis=0)
            
        elif method == "zscore":
            # Método Z-Score
            z_scores = np.abs((X_scaled - np.mean(X_scaled, axis=0)) / np.std(X_scaled, axis=0))
            outliers = np.any(z_scores > 3, axis=1)
            
        elif method == "isolation":
            # Usar Isolation Forest para detectar outliers
            if self._model is not None:
                anomaly_scores = self._model.score_samples(X_scaled)
                anomaly_probs = 1.0 - anomaly_scores
                outliers = anomaly_probs > self.threshold
            else:
                outliers = [False] * len(logs)
        
        else:
            print(f"⚠️ Método de detección de outliers no reconocido: {method}")
            outliers = [False] * len(logs)
        
        print(f"🔍 Detectados {np.sum(outliers)} outliers usando método {method}")
        return outliers.tolist()
    
    def get_anomaly_explanation(self, logs: List[ThreatLogItemDTO], log_index: int) -> Dict[str, Any]:
        """
        Proporciona explicación detallada de por qué un log es anómalo.
        
        Args:
            logs: Lista de logs
            log_index: Índice del log a explicar
            
        Returns:
            Diccionario con explicación de la anomalía
        """
        if not all([NUMPY_AVAILABLE, SKLEARN_AVAILABLE]) or self._model is None:
            return {"error": "Modelo no disponible"}
        
        if log_index >= len(logs) or log_index < 0:
            return {"error": "Índice de log inválido"}
        
        # Preparar features
        X = self._encode_logs([logs[log_index]])
        if X is None:
            return {"error": "Error procesando features"}
        
        # Aplicar scaler
        if self._scaler is not None:
            X_scaled = self._scaler.transform(X)
        else:
            X_scaled = X
        
        # Obtener score de anomalía
        anomaly_score = self._model.score_samples(X_scaled)[0]
        anomaly_prob = 1.0 - anomaly_score
        
        # Analizar contribución de cada característica
        feature_contributions = []
        log_entry = logs[log_index]
        
        # Valores de las características
        feature_values = {
            'network_packet_size': log_entry.network_packet_size,
            'login_attempts': log_entry.login_attempts,
            'session_duration': log_entry.session_duration,
            'ip_reputation_score': log_entry.ip_reputation_score,
            'failed_logins': log_entry.failed_logins,
            'unusual_time_access': log_entry.unusual_time_access,
            'protocol_type': log_entry.protocol_type,
            'encryption_used': log_entry.encryption_used,
            'browser_type': log_entry.browser_type
        }
        
        # Analizar cada característica
        for i, (name, value) in enumerate(feature_values.items()):
            if i < X_scaled.shape[1]:
                scaled_value = X_scaled[0, i]
                contribution = abs(scaled_value)  # Contribución aproximada
                feature_contributions.append({
                    'feature': name,
                    'value': value,
                    'scaled_value': float(scaled_value),
                    'contribution': float(contribution)
                })
        
        # Ordenar por contribución
        feature_contributions.sort(key=lambda x: x['contribution'], reverse=True)
        
        # Determinar nivel de anomalía
        if anomaly_prob > 0.8:
            severity = "MUY ALTA"
        elif anomaly_prob > 0.6:
            severity = "ALTA"
        elif anomaly_prob > 0.4:
            severity = "MEDIA"
        else:
            severity = "BAJA"
        
        explanation = {
            'log_index': log_index,
            'session_id': log_entry.session_id,
            'anomaly_score': float(anomaly_score),
            'anomaly_probability': float(anomaly_prob),
            'severity': severity,
            'is_anomaly': anomaly_prob > self.threshold,
            'threshold': self.threshold,
            'feature_contributions': feature_contributions[:5],  # Top 5 características
            'explanation': f"Log con probabilidad de anomalía {anomaly_prob:.3f} (threshold: {self.threshold:.3f})"
        }
        
        return explanation
    
    def _calculate_confidence(self, anomaly_probs: np.ndarray, X_scaled: np.ndarray) -> float:
        """
        Calcula la confianza del modelo basada en múltiples factores.
        
        Args:
            anomaly_probs: Probabilidades de anomalía
            X_scaled: Features escaladas
            
        Returns:
            Valor de confianza entre 0 y 1
        """
        if len(anomaly_probs) == 0:
            return 0.0
        
        # Factor 1: Consistencia de los scores (menor varianza = mayor confianza)
        score_consistency = 1.0 - min(np.std(anomaly_probs), 1.0)
        
        # Factor 2: Separación clara entre normales y anómalos
        normal_scores = anomaly_probs[anomaly_probs <= self.threshold]
        anomaly_scores = anomaly_probs[anomaly_probs > self.threshold]
        
        if len(normal_scores) > 0 and len(anomaly_scores) > 0:
            separation = abs(np.mean(normal_scores) - np.mean(anomaly_scores))
        else:
            separation = 0.5
        
        # Factor 3: Estabilidad del modelo (basado en la distribución de features)
        feature_stability = 1.0 - min(np.std(X_scaled), 1.0)
        
        # Factor 4: Tamaño de la muestra (más logs = mayor confianza, hasta cierto punto)
        sample_size_factor = min(len(anomaly_probs) / 10.0, 1.0)
        
        # Combinar factores con pesos
        confidence = (
            0.3 * score_consistency +
            0.3 * separation +
            0.2 * feature_stability +
            0.2 * sample_size_factor
        )
        
        return float(max(0.0, min(1.0, confidence)))
    
    def _calculate_threat_severity(self, anomaly_probs: np.ndarray) -> str:
        """
        Calcula la severidad de la amenaza basada en los scores de anomalía.
        
        Args:
            anomaly_probs: Probabilidades de anomalía
            
        Returns:
            Nivel de severidad como string
        """
        if len(anomaly_probs) == 0:
            return "NONE"
        
        max_prob = np.max(anomaly_probs)
        mean_prob = np.mean(anomaly_probs)
        anomaly_ratio = np.sum(anomaly_probs > self.threshold) / len(anomaly_probs)
        
        # Calcular severidad basada en múltiples factores
        if max_prob > 0.9 or (mean_prob > 0.7 and anomaly_ratio > 0.5):
            return "CRITICAL"
        elif max_prob > 0.8 or (mean_prob > 0.6 and anomaly_ratio > 0.3):
            return "HIGH"
        elif max_prob > 0.6 or (mean_prob > 0.4 and anomaly_ratio > 0.1):
            return "MEDIUM"
        elif max_prob > self.threshold:
            return "LOW"
        else:
            return "NONE"
    
    def get_detailed_anomaly_analysis(self, logs: List[ThreatLogItemDTO]) -> Dict[str, Any]:
        """
        Proporciona un análisis detallado de anomalías en un batch de logs.
        
        Args:
            logs: Lista de logs para análisis
            
        Returns:
            Diccionario con análisis detallado
        """
        if not all([NUMPY_AVAILABLE, SKLEARN_AVAILABLE]) or self._model is None:
            return {"error": "Modelo no disponible"}
        
        if not logs:
            return {"error": "No hay logs para analizar"}
        
        # Preparar features
        X = self._encode_logs(logs)
        if X is None:
            return {"error": "Error procesando features"}
        
        # Aplicar scaler
        if self._scaler is not None:
            X_scaled = self._scaler.transform(X)
        else:
            X_scaled = X
        
        # Obtener scores de anomalía
        anomaly_scores = self._model.score_samples(X_scaled)
        anomaly_probs = 1.0 - anomaly_scores
        
        # Análisis estadístico
        stats = {
            'total_logs': len(logs),
            'anomaly_count': int(np.sum(anomaly_probs > self.threshold)),
            'anomaly_ratio': float(np.sum(anomaly_probs > self.threshold) / len(anomaly_probs)),
            'mean_anomaly_prob': float(np.mean(anomaly_probs)),
            'median_anomaly_prob': float(np.median(anomaly_probs)),
            'max_anomaly_prob': float(np.max(anomaly_probs)),
            'min_anomaly_prob': float(np.min(anomaly_probs)),
            'std_anomaly_prob': float(np.std(anomaly_probs))
        }
        
        # Distribución de severidad
        severity_distribution = {
            'critical': int(np.sum(anomaly_probs > 0.9)),
            'high': int(np.sum((anomaly_probs > 0.8) & (anomaly_probs <= 0.9))),
            'medium': int(np.sum((anomaly_probs > 0.6) & (anomaly_probs <= 0.8))),
            'low': int(np.sum((anomaly_probs > self.threshold) & (anomaly_probs <= 0.6))),
            'normal': int(np.sum(anomaly_probs <= self.threshold))
        }
        
        # Análisis por características
        feature_analysis = []
        for i, feature_name in enumerate(self._feature_names):
            if i < X_scaled.shape[1]:
                feature_values = X_scaled[:, i]
                feature_stats = {
                    'feature': feature_name,
                    'mean': float(np.mean(feature_values)),
                    'std': float(np.std(feature_values)),
                    'min': float(np.min(feature_values)),
                    'max': float(np.max(feature_values)),
                    'correlation_with_anomaly': float(np.corrcoef(feature_values, anomaly_probs)[0, 1])
                }
                feature_analysis.append(feature_stats)
        
        # Ordenar por correlación con anomalía
        feature_analysis.sort(key=lambda x: abs(x['correlation_with_anomaly']), reverse=True)
        
        # Identificar logs más anómalos
        most_anomalous_indices = np.argsort(anomaly_probs)[-5:][::-1]  # Top 5
        most_anomalous = []
        for idx in most_anomalous_indices:
            if anomaly_probs[idx] > self.threshold:
                most_anomalous.append({
                    'log_index': int(idx),
                    'session_id': logs[idx].session_id,
                    'anomaly_probability': float(anomaly_probs[idx]),
                    'severity': self._calculate_threat_severity([anomaly_probs[idx]])
                })
        
        analysis = {
            'summary': stats,
            'severity_distribution': severity_distribution,
            'feature_analysis': feature_analysis,
            'most_anomalous_logs': most_anomalous,
            'threshold': self.threshold,
            'model_confidence': self._calculate_confidence(anomaly_probs, X_scaled)
        }
        
        return analysis
    
    def generate_anomaly_report(self, logs: List[ThreatLogItemDTO]) -> Dict[str, Any]:
        """
        Genera un reporte completo de anomalías con explicaciones detalladas.
        
        Args:
            logs: Lista de logs para análisis
            
        Returns:
            Diccionario con reporte completo de anomalías
        """
        if not all([NUMPY_AVAILABLE, SKLEARN_AVAILABLE]) or self._model is None:
            return {"error": "Modelo no disponible"}
        
        if not logs:
            return {"error": "No hay logs para analizar"}
        
        # Obtener análisis detallado
        analysis = self.get_detailed_anomaly_analysis(logs)
        if "error" in analysis:
            return analysis
        
        # Preparar features para explicaciones individuales
        X = self._encode_logs(logs)
        if X is None:
            return {"error": "Error procesando features"}
        
        if self._scaler is not None:
            X_scaled = self._scaler.transform(X)
        else:
            X_scaled = X
        
        # Obtener scores de anomalía
        anomaly_scores = self._model.score_samples(X_scaled)
        anomaly_probs = 1.0 - anomaly_scores
        
        # Generar explicaciones para logs anómalos
        anomalous_explanations = []
        for i, prob in enumerate(anomaly_probs):
            if prob > self.threshold:
                explanation = self.get_anomaly_explanation(logs, i)
                anomalous_explanations.append(explanation)
        
        # Generar insights y recomendaciones
        insights = self._generate_insights(analysis, anomalous_explanations)
        
        # Generar resumen ejecutivo
        executive_summary = self._generate_executive_summary(analysis, anomalous_explanations)
        
        report = {
            'executive_summary': executive_summary,
            'detailed_analysis': analysis,
            'anomalous_logs': anomalous_explanations,
            'insights': insights,
            'recommendations': self._generate_recommendations(analysis, anomalous_explanations),
            'metadata': {
                'report_timestamp': str(pd.Timestamp.now()) if PANDAS_AVAILABLE else str(time.time()),
                'model_version': 'isolation_forest_v2',
                'threshold': self.threshold,
                'total_logs_analyzed': len(logs)
            }
        }
        
        return report
    
    def _generate_insights(self, analysis: Dict[str, Any], explanations: List[Dict[str, Any]]) -> List[str]:
        """
        Genera insights basados en el análisis de anomalías.
        
        Args:
            analysis: Análisis detallado de anomalías
            explanations: Explicaciones de logs anómalos
            
        Returns:
            Lista de insights
        """
        insights = []
        
        # Insight sobre distribución de anomalías
        severity_dist = analysis['severity_distribution']
        total_anomalies = sum(severity_dist.values()) - severity_dist['normal']
        
        if total_anomalies > 0:
            if severity_dist['critical'] > 0:
                insights.append(f"🚨 CRÍTICO: Se detectaron {severity_dist['critical']} anomalías críticas que requieren atención inmediata")
            
            if severity_dist['high'] > 0:
                insights.append(f"⚠️ ALTO: {severity_dist['high']} anomalías de alta severidad detectadas")
            
            anomaly_ratio = analysis['summary']['anomaly_ratio']
            if anomaly_ratio > 0.3:
                insights.append(f"📊 ALTO VOLUMEN: {anomaly_ratio:.1%} de los logs son anómalos, indicando posible ataque coordinado")
            elif anomaly_ratio > 0.1:
                insights.append(f"📈 ELEVADO: {anomaly_ratio:.1%} de los logs son anómalos, monitoreo intensificado recomendado")
        
        # Insight sobre características más relevantes
        feature_analysis = analysis['feature_analysis']
        if feature_analysis:
            top_feature = feature_analysis[0]
            if abs(top_feature['correlation_with_anomaly']) > 0.5:
                insights.append(f"🔍 CARACTERÍSTICA CLAVE: '{top_feature['feature']}' muestra alta correlación con anomalías ({top_feature['correlation_with_anomaly']:.2f})")
        
        # Insight sobre patrones en logs anómalos
        if explanations:
            # Analizar patrones comunes en características
            common_patterns = self._analyze_common_patterns(explanations)
            if common_patterns:
                insights.append(f"🔄 PATRÓN DETECTADO: {common_patterns}")
        
        # Insight sobre confianza del modelo
        confidence = analysis['model_confidence']
        if confidence > 0.8:
            insights.append("✅ ALTA CONFIANZA: El modelo muestra alta confianza en sus predicciones")
        elif confidence < 0.5:
            insights.append("⚠️ BAJA CONFIANZA: El modelo muestra baja confianza, considerar recalibración")
        
        return insights
    
    def _generate_executive_summary(self, analysis: Dict[str, Any], explanations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Genera un resumen ejecutivo del análisis de anomalías.
        
        Args:
            analysis: Análisis detallado de anomalías
            explanations: Explicaciones de logs anómalos
            
        Returns:
            Resumen ejecutivo
        """
        summary = analysis['summary']
        severity_dist = analysis['severity_distribution']
        
        # Determinar nivel de amenaza general
        total_anomalies = sum(severity_dist.values()) - severity_dist['normal']
        if severity_dist['critical'] > 0:
            threat_level = "CRÍTICO"
        elif severity_dist['high'] > 0:
            threat_level = "ALTO"
        elif severity_dist['medium'] > 0:
            threat_level = "MEDIO"
        elif total_anomalies > 0:
            threat_level = "BAJO"
        else:
            threat_level = "NINGUNO"
        
        # Generar mensaje principal
        if total_anomalies == 0:
            main_message = "✅ No se detectaron anomalías en el batch de logs analizado"
        else:
            main_message = f"🚨 Se detectaron {total_anomalies} anomalías de diferentes niveles de severidad"
        
        return {
            'threat_level': threat_level,
            'main_message': main_message,
            'key_metrics': {
                'total_logs': summary['total_logs'],
                'anomalies_detected': total_anomalies,
                'anomaly_ratio': f"{summary['anomaly_ratio']:.1%}",
                'max_anomaly_probability': f"{summary['max_anomaly_prob']:.3f}",
                'model_confidence': f"{analysis['model_confidence']:.3f}"
            },
            'severity_breakdown': {
                'critical': severity_dist['critical'],
                'high': severity_dist['high'],
                'medium': severity_dist['medium'],
                'low': severity_dist['low'],
                'normal': severity_dist['normal']
            }
        }
    
    def _analyze_common_patterns(self, explanations: List[Dict[str, Any]]) -> str:
        """
        Analiza patrones comunes en las explicaciones de anomalías.
        
        Args:
            explanations: Lista de explicaciones de anomalías
            
        Returns:
            String describiendo patrones comunes
        """
        if not explanations:
            return ""
        
        # Analizar características más frecuentemente anómalas
        feature_counts = {}
        for explanation in explanations:
            for contrib in explanation.get('feature_contributions', []):
                feature = contrib['feature']
                if contrib['contribution'] > 0.5:  # Alta contribución
                    feature_counts[feature] = feature_counts.get(feature, 0) + 1
        
        if feature_counts:
            most_common = max(feature_counts.items(), key=lambda x: x[1])
            return f"Característica '{most_common[0]}' aparece como anómala en {most_common[1]} de {len(explanations)} casos"
        
        return ""
    
    def _generate_recommendations(self, analysis: Dict[str, Any], explanations: List[Dict[str, Any]]) -> List[str]:
        """
        Genera recomendaciones basadas en el análisis de anomalías.
        
        Args:
            analysis: Análisis detallado de anomalías
            explanations: Explicaciones de logs anómalos
            
        Returns:
            Lista de recomendaciones
        """
        recommendations = []
        
        severity_dist = analysis['severity_distribution']
        total_anomalies = sum(severity_dist.values()) - severity_dist['normal']
        
        if severity_dist['critical'] > 0:
            recommendations.append("🚨 ACCIÓN INMEDIATA: Investigar y contener las anomalías críticas detectadas")
            recommendations.append("🔒 AISLAR: Considerar aislar temporalmente los sistemas afectados")
        
        if severity_dist['high'] > 0:
            recommendations.append("⚠️ INVESTIGAR: Revisar en detalle las anomalías de alta severidad")
            recommendations.append("📊 MONITOREAR: Aumentar la frecuencia de monitoreo de seguridad")
        
        if total_anomalies > 0:
            recommendations.append("🔍 ANALIZAR: Revisar los logs anómalos para identificar patrones de ataque")
            recommendations.append("📈 ESCALAR: Notificar al equipo de seguridad sobre las anomalías detectadas")
        
        # Recomendaciones basadas en características
        feature_analysis = analysis['feature_analysis']
        if feature_analysis:
            top_features = [f for f in feature_analysis[:3] if abs(f['correlation_with_anomaly']) > 0.3]
            if top_features:
                feature_names = [f['feature'] for f in top_features]
                recommendations.append(f"🎯 ENFOCAR: Monitorear especialmente las características: {', '.join(feature_names)}")
        
        # Recomendaciones basadas en confianza del modelo
        confidence = analysis['model_confidence']
        if confidence < 0.6:
            recommendations.append("🔄 RECALIBRAR: Considerar recalibrar el modelo debido a baja confianza")
            recommendations.append("📚 ENTRENAR: Revisar y actualizar el conjunto de entrenamiento")
        
        if not recommendations:
            recommendations.append("✅ CONTINUAR: Mantener el monitoreo actual, no se requieren acciones especiales")
        
        return recommendations
    
    def detect_concept_drift(self, new_logs: List[ThreatLogItemDTO], drift_threshold: float = 0.1) -> Dict[str, Any]:
        """
        Detecta concept drift comparando la distribución de nuevas muestras con el modelo actual.
        
        Args:
            new_logs: Lista de nuevos logs para comparar
            drift_threshold: Umbral para detectar drift (0.1 = 10% de diferencia)
            
        Returns:
            Diccionario con información sobre concept drift
        """
        if not all([NUMPY_AVAILABLE, SKLEARN_AVAILABLE]) or self._model is None:
            return {"error": "Modelo no disponible para detección de drift"}
        
        if not new_logs:
            return {"error": "No hay logs nuevos para analizar"}
        
        print(f"🔄 Detectando concept drift con {len(new_logs)} logs nuevos...")
        
        # Preparar features de los nuevos logs
        X_new = self._encode_logs(new_logs)
        if X_new is None:
            return {"error": "Error procesando features de nuevos logs"}
        
        # Aplicar scaler
        if self._scaler is not None:
            X_new_scaled = self._scaler.transform(X_new)
        else:
            X_new_scaled = X_new
        
        # Obtener scores de anomalía para los nuevos logs
        new_anomaly_scores = self._model.score_samples(X_new_scaled)
        new_anomaly_probs = 1.0 - new_anomaly_scores
        
        # Calcular estadísticas de los nuevos datos
        new_stats = {
            'mean_score': float(np.mean(new_anomaly_scores)),
            'std_score': float(np.std(new_anomaly_scores)),
            'mean_prob': float(np.mean(new_anomaly_probs)),
            'std_prob': float(np.std(new_anomaly_probs)),
            'anomaly_ratio': float(np.sum(new_anomaly_probs > self.threshold) / len(new_anomaly_probs))
        }
        
        # Comparar con estadísticas históricas si están disponibles
        drift_detected = False
        drift_metrics = {}
        
        if self._score_stats:
            # Comparar con estadísticas históricas
            historical_mean = self._score_stats.get('mean_score', 0)
            historical_std = self._score_stats.get('std_score', 0)
            
            # Calcular diferencia en distribución
            mean_drift = abs(new_stats['mean_score'] - historical_mean)
            std_drift = abs(new_stats['std_score'] - historical_std)
            
            # Detectar drift si la diferencia supera el umbral
            if mean_drift > drift_threshold or std_drift > drift_threshold:
                drift_detected = True
                drift_metrics = {
                    'mean_drift': float(mean_drift),
                    'std_drift': float(std_drift),
                    'drift_severity': 'HIGH' if (mean_drift > 0.2 or std_drift > 0.2) else 'MEDIUM'
                }
        else:
            # Sin estadísticas históricas, usar heurísticas
            if new_stats['anomaly_ratio'] > 0.5:  # Más del 50% de anomalías
                drift_detected = True
                drift_metrics = {
                    'reason': 'High anomaly ratio without historical data',
                    'anomaly_ratio': new_stats['anomaly_ratio']
                }
        
        # Análisis de distribución por características
        feature_drift = self._analyze_feature_drift(X_new_scaled)
        
        result = {
            'drift_detected': drift_detected,
            'drift_metrics': drift_metrics,
            'new_data_stats': new_stats,
            'feature_drift': feature_drift,
            'recommendation': self._get_drift_recommendation(drift_detected, drift_metrics, new_stats)
        }
        
        if drift_detected:
            print(f"⚠️ Concept drift detectado: {drift_metrics}")
        else:
            print("✅ No se detectó concept drift significativo")
        
        return result
    
    def _analyze_feature_drift(self, X_new_scaled: np.ndarray) -> Dict[str, Any]:
        """
        Analiza drift en características individuales.
        
        Args:
            X_new_scaled: Features escaladas de nuevos datos
            
        Returns:
            Diccionario con análisis de drift por característica
        """
        feature_drift = {}
        
        for i, feature_name in enumerate(self._feature_names):
            if i < X_new_scaled.shape[1]:
                feature_values = X_new_scaled[:, i]
                feature_stats = {
                    'mean': float(np.mean(feature_values)),
                    'std': float(np.std(feature_values)),
                    'min': float(np.min(feature_values)),
                    'max': float(np.max(feature_values))
                }
                
                # Detectar outliers en la característica
                Q1 = np.percentile(feature_values, 25)
                Q3 = np.percentile(feature_values, 75)
                IQR = Q3 - Q1
                outlier_ratio = np.sum((feature_values < Q1 - 1.5 * IQR) | 
                                     (feature_values > Q3 + 1.5 * IQR)) / len(feature_values)
                
                feature_drift[feature_name] = {
                    **feature_stats,
                    'outlier_ratio': float(outlier_ratio),
                    'has_drift': outlier_ratio > 0.1  # Más del 10% de outliers
                }
        
        return feature_drift
    
    def _get_drift_recommendation(self, drift_detected: bool, drift_metrics: Dict, new_stats: Dict) -> str:
        """
        Genera recomendaciones basadas en la detección de drift.
        
        Args:
            drift_detected: Si se detectó drift
            drift_metrics: Métricas de drift
            new_stats: Estadísticas de nuevos datos
            
        Returns:
            Recomendación como string
        """
        if not drift_detected:
            return "✅ No se requiere acción - el modelo sigue siendo válido"
        
        if drift_metrics.get('drift_severity') == 'HIGH':
            return "🚨 RECALIBRAR INMEDIATAMENTE: Drift severo detectado, el modelo necesita actualización urgente"
        elif drift_metrics.get('drift_severity') == 'MEDIUM':
            return "⚠️ MONITOREAR: Drift moderado detectado, considerar recalibración en las próximas horas"
        elif new_stats['anomaly_ratio'] > 0.5:
            return "📊 INVESTIGAR: Alta proporción de anomalías, verificar si es drift o ataque real"
        else:
            return "🔄 EVALUAR: Drift detectado, evaluar necesidad de retraining"
    
    def retrain_model(self, new_logs: List[ThreatLogItemDTO], retrain_threshold: float = 0.15) -> Dict[str, Any]:
        """
        Reentrena el modelo si se detecta concept drift significativo.
        
        Args:
            new_logs: Lista de nuevos logs para retraining
            retrain_threshold: Umbral para activar retraining
            
        Returns:
            Diccionario con resultados del retraining
        """
        if not all([NUMPY_AVAILABLE, SKLEARN_AVAILABLE]):
            return {"error": "Dependencias no disponibles para retraining"}
        
        if not new_logs:
            return {"error": "No hay logs para retraining"}
        
        print(f"🔄 Iniciando retraining con {len(new_logs)} logs...")
        
        # Detectar concept drift primero
        drift_result = self.detect_concept_drift(new_logs, retrain_threshold)
        
        if not drift_result.get('drift_detected', False):
            return {
                "retraining_triggered": False,
                "reason": "No significant concept drift detected",
                "drift_analysis": drift_result
            }
        
        # Guardar modelo anterior para comparación
        old_model = self._model
        old_scaler = self._scaler
        old_threshold = self.threshold
        
        try:
            # Reentrenar modelo
            start_time = time.time()
            self.fit(new_logs)
            training_time = time.time() - start_time
            
            # Evaluar nuevo modelo
            X_new = self._encode_logs(new_logs)
            if X_new is None:
                return {"error": "Error procesando features para evaluación"}
            
            if self._scaler is not None:
                X_new_scaled = self._scaler.transform(X_new)
            else:
                X_new_scaled = X_new
            
            # Calcular métricas del nuevo modelo
            new_anomaly_scores = self._model.score_samples(X_new_scaled)
            new_anomaly_probs = 1.0 - new_anomaly_scores
            
            new_metrics = {
                'mean_anomaly_prob': float(np.mean(new_anomaly_probs)),
                'std_anomaly_prob': float(np.std(new_anomaly_probs)),
                'anomaly_ratio': float(np.sum(new_anomaly_probs > self.threshold) / len(new_anomaly_probs))
            }
            
            # Comparar con métricas anteriores si están disponibles
            improvement = None
            if self._score_stats:
                old_mean = self._score_stats.get('mean_score', 0)
                new_mean = np.mean(new_anomaly_scores)
                improvement = float(new_mean - old_mean)
            
            result = {
                "retraining_triggered": True,
                "training_time": training_time,
                "new_model_metrics": new_metrics,
                "improvement": improvement,
                "drift_analysis": drift_result,
                "old_threshold": old_threshold,
                "new_threshold": self.threshold
            }
            
            print(f"✅ Retraining completado en {training_time:.2f} segundos")
            return result
            
        except Exception as e:
            # Restaurar modelo anterior en caso de error
            self._model = old_model
            self._scaler = old_scaler
            self.threshold = old_threshold
            print(f"❌ Error durante retraining, modelo restaurado: {e}")
            return {"error": f"Retraining failed: {str(e)}"}
    
    def update_model_periodically(self, new_logs: List[ThreatLogItemDTO], 
                                update_frequency_hours: int = 24,
                                drift_threshold: float = 0.1) -> Dict[str, Any]:
        """
        Actualiza el modelo periódicamente basado en concept drift.
        
        Args:
            new_logs: Lista de nuevos logs
            update_frequency_hours: Frecuencia de actualización en horas
            drift_threshold: Umbral para detección de drift
            
        Returns:
            Diccionario con resultados de la actualización
        """
        current_time = time.time()
        
        # Verificar si es tiempo de actualización
        last_update = getattr(self, '_last_update_time', 0)
        time_since_update = current_time - last_update
        hours_since_update = time_since_update / 3600
        
        if hours_since_update < update_frequency_hours:
            return {
                "update_skipped": True,
                "reason": f"Last update was {hours_since_update:.1f} hours ago, next update in {update_frequency_hours - hours_since_update:.1f} hours"
            }
        
        # Detectar drift
        drift_result = self.detect_concept_drift(new_logs, drift_threshold)
        
        if drift_result.get('drift_detected', False):
            # Retraining necesario
            retrain_result = self.retrain_model(new_logs, drift_threshold)
            self._last_update_time = current_time
            return {
                "update_performed": True,
                "type": "retraining",
                "drift_detected": True,
                "retrain_result": retrain_result
            }
        else:
            # Solo actualizar estadísticas
            self._last_update_time = current_time
            return {
                "update_performed": True,
                "type": "statistics_update",
                "drift_detected": False,
                "drift_analysis": drift_result
            }


