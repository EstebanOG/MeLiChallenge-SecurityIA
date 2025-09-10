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
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score, precision_score, recall_score, f1_score
import warnings
warnings.filterwarnings('ignore')


class SupervisedThreatDetector:
    """
    Detector de amenazas supervisado usando Gradient Boosting.
    
    Este modelo está entrenado para detectar ataques conocidos basándose
    en patrones del dataset de threat intelligence.
    """
    
    def __init__(self, model_path: str = "models/supervised_model.joblib"):
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.label_encoders = {}
        self.feature_columns = [
            'network_packet_size', 'protocol_type', 'login_attempts', 
            'session_duration', 'encryption_used', 'ip_reputation_score',
            'failed_logins', 'browser_type', 'unusual_time_access'
        ]
        self.is_trained = False
    
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
        
        print("🔄 Dividiendo datos en entrenamiento y prueba...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print("⚖️ Escalando características...")
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        print("🤖 Entrenando modelo Gradient Boosting...")
        self.model = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=6,
            random_state=42
        )
        
        self.model.fit(X_train_scaled, y_train)
        
        print("📈 Evaluando modelo...")
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)[:, 1]
        
        # Calcular métricas
        auc_score = roc_auc_score(y_test, y_pred_proba)
        precision = precision_score(y_test, y_pred, average='weighted')
        recall = recall_score(y_test, y_pred, average='weighted')
        f1 = f1_score(y_test, y_pred, average='weighted')
        
        metrics = {
            'auc_score': auc_score,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'classification_report': classification_report(y_test, y_pred, output_dict=True),
            'test_samples': len(X_test),
            'train_samples': len(X_train)
        }
        
        print(f"✅ Modelo entrenado - AUC: {auc_score:.4f}, Precisión: {precision:.4f}, Recall: {recall:.4f}, F1: {f1:.4f}")
        
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
        
        # Predecir
        prediction = self.model.predict(X_scaled)[0]
        probability = self.model.predict_proba(X_scaled)[0][1]
        
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
                    # Valores por defecto si la columna no existe
                    if col == 'network_packet_size':
                        features_df[col] = 500  # Valor promedio
                    elif col == 'protocol_type':
                        features_df[col] = 'TCP'  # Más común
                    elif col == 'login_attempts':
                        features_df[col] = 4  # Valor promedio
                    elif col == 'session_duration':
                        features_df[col] = 800  # Valor promedio
                    elif col == 'encryption_used':
                        features_df[col] = 'AES'  # Más seguro
                    elif col == 'ip_reputation_score':
                        features_df[col] = 0.5  # Neutral
                    elif col == 'failed_logins':
                        features_df[col] = 1  # Valor promedio
                    elif col == 'browser_type':
                        features_df[col] = 'Chrome'  # Más común
                    elif col == 'unusual_time_access':
                        features_df[col] = 0  # Normal
            
            # Manejar valores faltantes
            features_df['encryption_used'] = features_df['encryption_used'].fillna('Unknown')
            
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
        Genera explicación de la predicción.
        
        Args:
            df: DataFrame con datos de logs
            prediction: Predicción del modelo (0 o 1)
            probability: Probabilidad de ataque
            
        Returns:
            String con explicación de la predicción
        """
        if prediction == 0:
            return f"Comportamiento normal detectado (probabilidad: {probability:.2f})"
        
        # Analizar características que contribuyen al ataque
        indicators = []
        
        if 'failed_logins' in df.columns and df['failed_logins'].iloc[0] > 2:
            indicators.append(f"múltiples fallos de login ({df['failed_logins'].iloc[0]})")
        
        if 'ip_reputation_score' in df.columns and df['ip_reputation_score'].iloc[0] < 0.3:
            indicators.append(f"IP con baja reputación ({df['ip_reputation_score'].iloc[0]:.2f})")
        
        if 'unusual_time_access' in df.columns and df['unusual_time_access'].iloc[0] == 1:
            indicators.append("acceso en horario inusual")
        
        if 'encryption_used' in df.columns and df['encryption_used'].iloc[0] == 'DES':
            indicators.append("uso de encriptación débil (DES)")
        
        if indicators:
            reasoning = f"Ataque detectado (probabilidad: {probability:.2f}) - Indicadores: {', '.join(indicators)}"
        else:
            reasoning = f"Ataque detectado (probabilidad: {probability:.2f}) - Patrón complejo identificado"
        
        return reasoning
    
    def _save_model(self):
        """Guarda el modelo entrenado y preprocesadores."""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'label_encoders': self.label_encoders,
            'feature_columns': self.feature_columns
        }
        
        joblib.dump(model_data, self.model_path)
        print(f"💾 Modelo guardado en: {self.model_path}")
    
    def _save_metrics(self, metrics: Dict[str, Any]):
        """Guarda las métricas del modelo en un archivo JSON."""
        import json
        
        metrics_path = "models/supervised_model_metrics.json"
        os.makedirs(os.path.dirname(metrics_path), exist_ok=True)
        
        # Preparar métricas para guardar
        metrics_to_save = {
            "auc_score": metrics['auc_score'],
            "precision": metrics['precision'],
            "recall": metrics['recall'],
            "f1_score": metrics['f1_score'],
            "train_samples": metrics['train_samples'],
            "test_samples": metrics['test_samples'],
            "feature_importance": self.get_feature_importance()
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
