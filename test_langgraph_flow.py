#!/usr/bin/env python3
"""
Script de prueba para demostrar el flujo de LangGraph.

Este script muestra cómo funciona el pipeline de agentes con LangGraph.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.frameworks.orchestration.langgraph_orchestrator import LangGraphPipelineOrchestrator

def test_langgraph_flow():
    """Prueba el flujo completo de LangGraph."""
    print("🧪 [TEST] Iniciando prueba del flujo LangGraph...")
    
    # Crear orquestador
    orchestrator = LangGraphPipelineOrchestrator()
    
    # Cargar datos reales del dataset de threat intelligence
    import pandas as pd
    import random
    
    try:
        # Cargar dataset real
        df = pd.read_csv("notebooks/data/processed/dataset_complete.csv")
        print(f"📊 [DATASET] Cargado dataset real con {len(df)} registros")
        
        # Seleccionar muestras aleatorias (una con ataque, una normal)
        attack_samples = df[df['attack_detected'] == 1].sample(1)
        normal_samples = df[df['attack_detected'] == 0].sample(1)
        
        # Convertir a formato de logs para el pipeline
        test_logs = []
        
        # Log con ataque detectado
        for _, row in attack_samples.iterrows():
            test_logs.append({
                "session_id": row['session_id'],
                "network_packet_size": row['network_packet_size'],
                "protocol_type": row['protocol_type'],
                "login_attempts": row['login_attempts'],
                "session_duration": row['session_duration'],
                "encryption_used": row['encryption_used'],
                "ip_reputation_score": row['ip_reputation_score'],
                "failed_logins": row['failed_logins'],
                "browser_type": row['browser_type'],
                "unusual_time_access": row['unusual_time_access'],
                "attack_detected": row['attack_detected'],
                # Mapear a campos que esperan los agentes
                "failed_auth_attempts": row['failed_logins'],
                "cpu_usage": min(95, 20 + (row['network_packet_size'] / 10)),  # Simular CPU basado en tráfico
                "memory_usage": min(90, 30 + (row['session_duration'] / 20)),  # Simular memoria basada en duración
                "network_in_kb": row['network_packet_size'],
                "avg_response_time_ms": row['session_duration'] * 2,  # Simular tiempo de respuesta
                "is_encrypted": 1 if row['encryption_used'] == 'AES' else 0
            })
        
        # Log normal
        for _, row in normal_samples.iterrows():
            test_logs.append({
                "session_id": row['session_id'],
                "network_packet_size": row['network_packet_size'],
                "protocol_type": row['protocol_type'],
                "login_attempts": row['login_attempts'],
                "session_duration": row['session_duration'],
                "encryption_used": row['encryption_used'],
                "ip_reputation_score": row['ip_reputation_score'],
                "failed_logins": row['failed_logins'],
                "browser_type": row['browser_type'],
                "unusual_time_access": row['unusual_time_access'],
                "attack_detected": row['attack_detected'],
                # Mapear a campos que esperan los agentes
                "failed_auth_attempts": row['failed_logins'],
                "cpu_usage": min(60, 20 + (row['network_packet_size'] / 15)),  # CPU normal
                "memory_usage": min(70, 30 + (row['session_duration'] / 30)),  # Memoria normal
                "network_in_kb": row['network_packet_size'],
                "avg_response_time_ms": row['session_duration'] * 1.5,  # Tiempo normal
                "is_encrypted": 1 if row['encryption_used'] == 'AES' else 0
            })
            
        print(f"🎯 [DATASET] Seleccionadas {len(test_logs)} muestras del dataset real")
        print(f"   - Ataque detectado: {test_logs[0]['attack_detected']}")
        print(f"   - Comportamiento normal: {test_logs[1]['attack_detected']}")
        
    except FileNotFoundError:
        print("⚠️ [WARNING] Dataset no encontrado, usando datos simulados...")
        # Fallback a datos simulados si no se encuentra el dataset
        test_logs = [
            {
                "session_id": "SID_SIMULATED_001",
                "network_packet_size": 800,
                "protocol_type": "TCP",
                "login_attempts": 5,
                "session_duration": 1200.0,
                "encryption_used": "DES",
                "ip_reputation_score": 0.2,
                "failed_logins": 4,
                "browser_type": "Chrome",
                "unusual_time_access": 1,
                "attack_detected": 1,
                "failed_auth_attempts": 4,
                "cpu_usage": 95.0,
                "memory_usage": 85.0,
                "network_in_kb": 800,
                "avg_response_time_ms": 600.0,
                "is_encrypted": 0
            },
            {
                "session_id": "SID_SIMULATED_002",
                "network_packet_size": 400,
                "protocol_type": "TCP",
                "login_attempts": 2,
                "session_duration": 300.0,
                "encryption_used": "AES",
                "ip_reputation_score": 0.8,
                "failed_logins": 0,
                "browser_type": "Firefox",
                "unusual_time_access": 0,
                "attack_detected": 0,
                "failed_auth_attempts": 0,
                "cpu_usage": 35.0,
                "memory_usage": 45.0,
                "network_in_kb": 400,
                "avg_response_time_ms": 200.0,
                "is_encrypted": 1
            }
        ]
    
    print(f"📊 [TEST] Procesando {len(test_logs)} logs de prueba...")
    
    # Ejecutar pipeline
    result = orchestrator.execute_pipeline(test_logs)
    
    print("\n" + "="*60)
    print("📋 [RESULTADO] Resultado del pipeline:")
    print("="*60)
    print(f"ID de Ejecución: {result.execution_id}")
    print(f"Estado: {result.status.value}")
    print(f"Tiempo Total: {result.total_execution_time_ms}ms")
    print(f"Agentes Ejecutados: {len(result.agent_results)}")
    
    # Mostrar resultados de cada agente
    print(f"\n🤖 [AGENTES] Resultados por agente:")
    for i, agent_result in enumerate(result.agent_results, 1):
        print(f"  {i}. {agent_result.agent_type.value}: {agent_result.status}")
        if agent_result.output:
            print(f"     Output: {agent_result.output}")
    
    # Mostrar decisión final si existe
    if result.agent_results:
        last_agent = result.agent_results[-1]
        if last_agent.output and 'final_decision' in last_agent.output:
            decision = last_agent.output['final_decision']
            print(f"\n🎯 [DECISIÓN FINAL]")
            print(f"Es Amenaza: {decision.get('is_threat', False)}")
            print(f"Confianza: {decision.get('confidence', 0)}")
            print(f"Tipo de Amenaza: {decision.get('threat_type', 'unknown')}")
            print(f"Explicación: {decision.get('explanation', 'N/A')}")
    
    print("\n" + "="*60)
    print("✅ [TEST] Prueba completada exitosamente!")
    print("="*60)

if __name__ == "__main__":
    test_langgraph_flow()
