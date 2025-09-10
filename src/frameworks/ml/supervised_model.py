"""
Modelo de Machine Learning Supervisado para detección de ataques.

Este módulo implementa un modelo Gradient Boosting entrenado con el dataset
de threat intelligence para detectar ataques conocidos.
"""

import pandas as pd
import numpy as np
import joblib
import os
from typing import List, Dict, Any, Tuple, Optional
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV, StratifiedKFold
from sklearn.metrics import classification_report, roc_auc_score, precision_score, recall_score, f1_score, confusion_matrix
import warnings
warnings.filterwarnings('ignore')


class SupervisedThreatDetector:
    """
    Detector de amenazas supervisado usando Gradient Boosting.
    
    Este modelo está entrenado para detectar ataques conocidos basándose
    en patrones del dataset de threat intelligence.
    """
    
    def __init__(self, model_path: str = "models/supervised_model.joblib", threshold: float = 0.5):
        self.model_path = model_path
        self.threshold = threshold
        self.model = None
        self.scaler = None
        self.label_encoders = {}
        self.feature_columns = [
            'network_packet_size', 'protocol_type', 'login_attempts', 
            'session_duration', 'encryption_used', 'ip_reputation_score',
            'failed_logins', 'browser_type', 'unusual_time_access'
        ]
        self.is_trained = False
        
        # Valores por defecto más inteligentes basados en estadísticas del dataset
        self.default_values = {
            'network_packet_size': 512,  # Tamaño promedio de paquetes TCP
            'protocol_type': 'TCP',      # Protocolo más común
            'login_attempts': 3,         # Valor promedio
            'session_duration': 600,     # 10 minutos promedio
            'encryption_used': 'AES',    # Encriptación más segura
            'ip_reputation_score': 0.5,  # Neutral
            'failed_logins': 0,          # Normalmente no hay fallos
            'browser_type': 'Chrome',    # Más común
            'unusual_time_access': False # Normalmente acceso en horario normal
        }
    
    def train(self, dataset_path: str) -> Dict[str, Any]:
        """
        Entrena el modelo con el dataset completo.
        
        Args:
            dataset_path: Ruta al archivo CSV del dataset
            
        Returns:
            Diccionario con métricas de entrenamiento
        """
        print("🔧 Cargando dataset para entrenamiento...")
        df = pd.read_csv(dataset_path)
        
        print("📊 Preparando datos...")
        X, y = self._prepare_data(df)
        
        print("🔄 Dividiendo datos en entrenamiento, validación y prueba...")
        # Primero dividir en train+val y test
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        # Luego dividir train+val en train y val
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=0.25, random_state=42, stratify=y_temp
        )
        
        print("⚖️ Escalando características...")
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        X_test_scaled = self.scaler.transform(X_test)
        
        print("🤖 Optimizando hiperparámetros con GridSearch...")
        # Definir parámetros simplificados para búsqueda de grid
        param_grid = {
            'n_estimators': [100, 200],
            'learning_rate': [0.1, 0.2],
            'max_depth': [3, 6],
            'subsample': [0.9, 1.0],
            'max_features': ['sqrt', 'log2']
        }
        
        # Usar validación cruzada estratificada (reducida para velocidad)
        cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
        
        # GridSearch con validación cruzada
        grid_search = GridSearchCV(
            GradientBoostingClassifier(random_state=42),
            param_grid,
            cv=cv,
            scoring='f1_weighted',
            n_jobs=-1,
            verbose=1
        )
        
        grid_search.fit(X_train_scaled, y_train)
        self.model = grid_search.best_estimator_
        
        print(f"✅ Mejores parámetros encontrados: {grid_search.best_params_}")
        print(f"✅ Mejor score de validación cruzada: {grid_search.best_score_:.4f}")
        
        # Validación cruzada adicional para métricas robustas
        print("📊 Realizando validación cruzada adicional...")
        cv_scores = cross_val_score(
            self.model, X_train_scaled, y_train, 
            cv=cv, scoring='f1_weighted'
        )
        print(f"📊 Scores de validación cruzada: {cv_scores}")
        print(f"📊 Score promedio: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        
        # Optimizar threshold usando conjunto de validación
        print("🎯 Optimizando threshold...")
        self.optimize_threshold(X_val_scaled, y_val)
        
        print("📈 Evaluando modelo...")
        
        # Generar reporte detallado de evaluación
        evaluation_report = self.generate_evaluation_report(X_test, y_test)
        
        # Extraer métricas principales para mostrar
        perf = evaluation_report['model_performance']
        auc_score = perf['auc_score']
        precision = perf['precision_weighted']
        recall = perf['recall_weighted']
        f1 = perf['f1_score_weighted']
        
        # Crear métricas simplificadas
        metrics = {
            'auc_score': auc_score,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'accuracy': perf['accuracy'],
            'confusion_matrix': evaluation_report['confusion_matrix'],
            'test_samples': len(X_test),
            'train_samples': len(X_train),
            'cv_scores_mean': cv_scores.mean(),
            'cv_scores_std': cv_scores.std(),
            'best_params': grid_search.best_params_
        }
        
        print(f"✅ Modelo entrenado - AUC: {auc_score:.4f}, Precisión: {precision:.4f}, Recall: {recall:.4f}, F1: {f1:.4f}")
        print(f"📊 Especificidad: {perf['specificity']:.4f}, Sensibilidad: {perf['sensitivity']:.4f}")
        print(f"🎯 Threshold optimizado: {self.threshold:.3f}")
        
        # Guardar modelo
        self._save_model()
        self.is_trained = True
        
        # Guardar métricas
        self._save_metrics(metrics)
        
        return metrics
    
    def _prepare_data(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Prepara los datos para entrenamiento.
        
        Args:
            df: DataFrame con los datos
            
        Returns:
            Tupla con características (X) y objetivo (y)
        """
        # Seleccionar características
        X = df[self.feature_columns].copy()
        y = df['attack_detected'].values
        
        # Manejar valores faltantes en encryption_used
        X['encryption_used'] = X['encryption_used'].fillna('Unknown')
        
        # Codificar variables categóricas
        categorical_columns = ['protocol_type', 'encryption_used', 'browser_type']
        
        for col in categorical_columns:
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col].astype(str))
            self.label_encoders[col] = le
        
        return X.values, y
    
    def _validate_input_data(self, log_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Valida los datos de entrada para predicción.
        
        Args:
            log_data: Lista de diccionarios con datos de logs
            
        Returns:
            Diccionario con resultado de validación
        """
        try:
            if not isinstance(log_data, list):
                return {'is_valid': False, 'error': 'Los datos deben ser una lista'}
            
            if len(log_data) == 0:
                return {'is_valid': False, 'error': 'La lista de logs está vacía'}
            
            # Validar que cada elemento sea un diccionario
            for i, log in enumerate(log_data):
                if not isinstance(log, dict):
                    return {'is_valid': False, 'error': f'El elemento {i} no es un diccionario'}
                
                # Validar campos requeridos
                required_fields = ['session_id']
                for field in required_fields:
                    if field not in log:
                        return {'is_valid': False, 'error': f'Campo requerido "{field}" faltante en elemento {i}'}
                
                # Validar tipos de datos básicos
                if 'session_id' in log and not isinstance(log['session_id'], str):
                    return {'is_valid': False, 'error': f'session_id debe ser string en elemento {i}'}
                
                # Validar rangos de valores numéricos
                numeric_fields = {
                    'network_packet_size': (1, 65535),
                    'login_attempts': (0, 100),
                    'session_duration': (0, 86400),  # Máximo 24 horas
                    'ip_reputation_score': (0, 1),
                    'failed_logins': (0, 100)
                }
                
                for field, (min_val, max_val) in numeric_fields.items():
                    if field in log and log[field] is not None:
                        try:
                            value = float(log[field])
                            if not (min_val <= value <= max_val):
                                return {'is_valid': False, 'error': f'{field} debe estar entre {min_val} y {max_val} en elemento {i}'}
                        except (ValueError, TypeError):
                            return {'is_valid': False, 'error': f'{field} debe ser numérico en elemento {i}'}
                
                # Validar valores booleanos
                boolean_fields = ['unusual_time_access']
                for field in boolean_fields:
                    if field in log and log[field] is not None:
                        if not isinstance(log[field], bool) and log[field] not in [0, 1, '0', '1', 'true', 'false', 'True', 'False']:
                            return {'is_valid': False, 'error': f'{field} debe ser booleano en elemento {i}'}
            
            return {'is_valid': True, 'error': None}
            
        except Exception as e:
            return {'is_valid': False, 'error': f'Error de validación: {str(e)}'}
    
    def predict(self, log_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Predice si hay un ataque en los logs dados.
        
        Args:
            log_data: Lista de diccionarios con datos de logs
            
        Returns:
            Diccionario con predicción y confianza
        """
        if not self.is_trained:
            self._load_model()
        
        # Validar datos de entrada
        validation_result = self._validate_input_data(log_data)
        if not validation_result['is_valid']:
            return {
                'is_attack': False,
                'confidence': 0.0,
                'probability': 0.0,
                'reasoning': f"Datos de entrada inválidos: {validation_result['error']}"
            }
        
        if not log_data:
            return {
                'is_attack': False,
                'confidence': 0.0,
                'probability': 0.0,
                'reasoning': 'No hay datos para analizar'
            }
        
        # Convertir logs a DataFrame
        df = pd.DataFrame(log_data)
        
        # Preparar características
        X = self._prepare_features(df)
        
        if X is None:
            return {
                'is_attack': False,
                'confidence': 0.0,
                'probability': 0.0,
                'reasoning': 'Datos insuficientes para predicción'
            }
        
        # Escalar características
        X_scaled = self.scaler.transform(X)
        
        # Predecir probabilidades
        probabilities = self.model.predict_proba(X_scaled)[0]
        probability = probabilities[1]  # Probabilidad de ataque
        
        # Debug: Mostrar probabilidades y features
        print(f"🔍 [SUPERVISED] Probabilidades: Normal={probabilities[0]:.3f}, Ataque={probability:.3f}")
        print(f"🔍 [SUPERVISED] Threshold actual: {self.threshold}")
        print(f"🔍 [SUPERVISED] Features procesadas: {X_scaled[0]}")
        print(f"🔍 [SUPERVISED] Log original: {log_data[0]}")
        
        # Usar threshold para clasificación
        prediction = 1 if probability >= self.threshold else 0
        
        print(f"🔍 [SUPERVISED] Predicción: {'ATAQUE' if prediction else 'NORMAL'}")
        
        # Calcular confianza basada en la probabilidad
        confidence = abs(probability - 0.5) * 2  # Convertir a escala 0-1
        
        # Generar reasoning
        reasoning = self._generate_reasoning(df, prediction, probability)
        
        return {
            'is_attack': bool(prediction),
            'confidence': float(confidence),
            'probability': float(probability),
            'reasoning': reasoning
        }
    
    def _prepare_features(self, df: pd.DataFrame) -> Optional[np.ndarray]:
        """
        Prepara las características de un DataFrame de logs.
        
        Args:
            df: DataFrame con datos de logs
            
        Returns:
            Array numpy con características preparadas o None si hay error
        """
        try:
            # Crear DataFrame con todas las características necesarias
            features_df = pd.DataFrame()
            
            for col in self.feature_columns:
                if col in df.columns:
                    features_df[col] = df[col]
                else:
                    # Usar valores por defecto inteligentes
                    features_df[col] = self.default_values[col]
            
            # Manejar valores faltantes de manera más robusta
            for col in self.feature_columns:
                if features_df[col].isna().any():
                    if col in ['protocol_type', 'encryption_used', 'browser_type']:
                        # Para variables categóricas, usar el valor más común o por defecto
                        most_common = features_df[col].mode()
                        if not most_common.empty:
                            features_df[col] = features_df[col].fillna(most_common.iloc[0])
                        else:
                            features_df[col] = features_df[col].fillna(self.default_values[col])
                    else:
                        # Para variables numéricas, usar la mediana o valor por defecto
                        if features_df[col].notna().any():
                            median_val = features_df[col].median()
                            features_df[col] = features_df[col].fillna(median_val)
                        else:
                            features_df[col] = features_df[col].fillna(self.default_values[col])
            
            # Validar tipos de datos
            features_df['network_packet_size'] = pd.to_numeric(features_df['network_packet_size'], errors='coerce')
            features_df['login_attempts'] = pd.to_numeric(features_df['login_attempts'], errors='coerce')
            features_df['session_duration'] = pd.to_numeric(features_df['session_duration'], errors='coerce')
            features_df['ip_reputation_score'] = pd.to_numeric(features_df['ip_reputation_score'], errors='coerce')
            features_df['failed_logins'] = pd.to_numeric(features_df['failed_logins'], errors='coerce')
            features_df['unusual_time_access'] = features_df['unusual_time_access'].astype(bool)
            
            # Codificar variables categóricas
            categorical_columns = ['protocol_type', 'encryption_used', 'browser_type']
            
            for col in categorical_columns:
                if col in self.label_encoders:
                    le = self.label_encoders[col]
                    # Manejar valores no vistos durante el entrenamiento
                    features_df[col] = features_df[col].astype(str)
                    unique_values = features_df[col].unique()
                    for val in unique_values:
                        if val not in le.classes_:
                            # Asignar el valor más común si no está en el encoder
                            features_df[col] = features_df[col].replace(val, le.classes_[0])
                    features_df[col] = le.transform(features_df[col])
            
            return features_df.values
            
        except Exception as e:
            print(f"❌ Error preparando características: {e}")
            return None
    
    def _generate_reasoning(self, df: pd.DataFrame, prediction: int, probability: float) -> str:
        """
        Genera explicación simplificada de la predicción.
        
        Args:
            df: DataFrame con datos de logs
            prediction: Predicción del modelo (0 o 1)
            probability: Probabilidad de ataque
            
        Returns:
            String con explicación simplificada de la predicción
        """
        if prediction == 0:
            return f"Comportamiento normal detectado (probabilidad: {probability:.3f})"
        
        # Análisis simplificado para ataques detectados
        attack_indicators = []
        
        # Solo verificar indicadores más importantes
        if 'failed_logins' in df.columns and df['failed_logins'].iloc[0] > 3:
            attack_indicators.append(f"múltiples fallos de login ({df['failed_logins'].iloc[0]})")
        
        if 'ip_reputation_score' in df.columns and df['ip_reputation_score'].iloc[0] < 0.3:
            attack_indicators.append(f"IP con baja reputación ({df['ip_reputation_score'].iloc[0]:.2f})")
        
        if 'unusual_time_access' in df.columns and df['unusual_time_access'].iloc[0] == 1:
            attack_indicators.append("acceso en horario inusual")
        
        # Construir reasoning simplificado
        reasoning = f"🚨 ATAQUE DETECTADO (probabilidad: {probability:.3f})"
        
        if attack_indicators:
            reasoning += f" - Indicadores: {', '.join(attack_indicators)}"
        
        # Añadir nivel de confianza simple
        if probability > 0.8:
            confidence_level = "MUY ALTA"
        elif probability > 0.6:
            confidence_level = "ALTA"
        else:
            confidence_level = "MEDIA"
        
        reasoning += f" - Confianza: {confidence_level}"
        
        return reasoning
    
    def _save_model(self):
        """Guarda el modelo entrenado y preprocesadores."""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'label_encoders': self.label_encoders,
            'feature_columns': self.feature_columns,
            'threshold': self.threshold
        }
        
        joblib.dump(model_data, self.model_path)
        print(f"💾 Modelo guardado en: {self.model_path}")
    
    def _save_metrics(self, metrics: Dict[str, Any]):
        """Guarda las métricas del modelo en un archivo JSON."""
        import json
        
        metrics_path = "models/supervised_model_metrics.json"
        os.makedirs(os.path.dirname(metrics_path), exist_ok=True)
        
        # Preparar métricas simplificadas para guardar
        metrics_to_save = {
            "auc_score": metrics['auc_score'],
            "precision": metrics['precision'],
            "recall": metrics['recall'],
            "f1_score": metrics['f1_score'],
            "accuracy": metrics.get('accuracy', 0),
            "train_samples": metrics['train_samples'],
            "test_samples": metrics['test_samples']
        }
        
        with open(metrics_path, 'w') as f:
            json.dump(metrics_to_save, f, indent=2)
        
        print(f"💾 Métricas guardadas en: {metrics_path}")
    
    def _load_model(self):
        """Carga el modelo entrenado y preprocesadores."""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Modelo no encontrado en: {self.model_path}")
        
        model_data = joblib.load(self.model_path)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.label_encoders = model_data['label_encoders']
        self.feature_columns = model_data['feature_columns']
        # Cargar threshold si existe, sino usar el por defecto
        self.threshold = model_data.get('threshold', self.threshold)
        self.is_trained = True
        
        print(f"📂 Modelo cargado desde: {self.model_path}")
    
    def get_feature_importance(self) -> Dict[str, float]:
        """
        Retorna la importancia de las características.
        
        Returns:
            Diccionario con importancia de cada característica
        """
        if not self.is_trained:
            self._load_model()
        
        importance = self.model.feature_importances_
        feature_importance = dict(zip(self.feature_columns, importance))
        
        return dict(sorted(feature_importance.items(), key=lambda x: x[1], reverse=True))
    
    def optimize_threshold(self, X_val: np.ndarray, y_val: np.ndarray) -> float:
        """
        Optimiza el threshold de manera simplificada.
        
        Args:
            X_val: Características de validación
            y_val: Etiquetas de validación
            
        Returns:
            Threshold optimizado
        """
        if not self.is_trained:
            self._load_model()
        
        # Obtener probabilidades de predicción
        y_proba = self.model.predict_proba(X_val)[:, 1]
        
        # Probar solo algunos thresholds clave (más rápido)
        # Priorizar 0.5 para mantener consistencia y reducir falsos positivos
        thresholds = [0.5, 0.4, 0.6, 0.3, 0.7]
        best_threshold = 0.5  # Usar 0.5 como default
        best_f1 = 0
        
        for threshold in thresholds:
            y_pred = (y_proba >= threshold).astype(int)
            f1 = f1_score(y_val, y_pred, average='weighted')
            
            if f1 > best_f1:
                best_f1 = f1
                best_threshold = threshold
        
        print(f"🎯 Threshold optimizado: {best_threshold:.3f} (F1: {best_f1:.4f})")
        self.threshold = best_threshold
        
        return best_threshold
    
    def generate_evaluation_report(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        """
        Genera un reporte simplificado de evaluación del modelo.
        
        Args:
            X_test: Características de prueba
            y_test: Etiquetas de prueba
            
        Returns:
            Diccionario con reporte simplificado
        """
        if not self.is_trained:
            self._load_model()
        
        # Escalar características si es necesario
        X_test_scaled = self.scaler.transform(X_test)
        
        # Predicciones
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)[:, 1]
        
        # Métricas básicas (solo las esenciales)
        auc_score = roc_auc_score(y_test, y_pred_proba)
        precision = precision_score(y_test, y_pred, average='weighted')
        recall = recall_score(y_test, y_pred, average='weighted')
        f1 = f1_score(y_test, y_pred, average='weighted')
        
        # Matriz de confusión
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        accuracy = (tp + tn) / (tp + tn + fp + fn)
        
        report = {
            'model_performance': {
                'auc_score': float(auc_score),
                'accuracy': float(accuracy),
                'precision_weighted': float(precision),
                'recall_weighted': float(recall),
                'f1_score_weighted': float(f1),
                'specificity': float(tn / (tn + fp)) if (tn + fp) > 0 else 0,
                'sensitivity': float(tp / (tp + fn)) if (tp + fn) > 0 else 0
            },
            'confusion_matrix': {
                'true_negatives': int(tn),
                'false_positives': int(fp),
                'false_negatives': int(fn),
                'true_positives': int(tp)
            },
            'model_configuration': {
                'threshold': float(self.threshold),
                'n_features': len(self.feature_columns)
            }
        }
        
        return report
