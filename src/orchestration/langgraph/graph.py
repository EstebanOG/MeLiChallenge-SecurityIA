from __future__ import annotations

from typing import Any, Dict, List, TypedDict, Optional
import uuid

from langgraph.graph import StateGraph, START, END

from .agents import ingestion_agent, decision_agent, IngestionOutput, DecisionOutput
from ...domain.entities.log_entry import LogEntry
from ...infrastructure.detectors.ml_isolation_forest_detector import IsolationForestDetector


class PipelineState(TypedDict):
    """Explicit state schema for the graph."""
    logs: List[Dict[str, Any]]
    trace_id: str
    ingestion: Optional[IngestionOutput]
    batch_score: Optional[float]
    batch_is_threat: Optional[bool]
    decision: Optional[DecisionOutput]


def _node_ingestion(state: PipelineState) -> PipelineState:
    logs = state["logs"]
    trace_id = state["trace_id"]
    ingestion = ingestion_agent(logs=logs, trace_id=trace_id)
    state["ingestion"] = ingestion
    return state


def _node_ml_scoring(state: PipelineState) -> PipelineState:
    # Bridge to existing IsolationForestDetector for batch score
    ingestion: IngestionOutput = state["ingestion"]
    detector = IsolationForestDetector()
    log_entries: List[LogEntry] = [
        LogEntry(
            timestamp=item["timestamp"],
            ip=item["ip"],
            method=item["method"],
            path=item["path"],
            status=item["status"],
            user_agent=item.get("user_agent"),
            response_time_ms=item.get("response_time_ms"),
        )
        for item in ingestion["logs"]
    ]
    result = detector.analyze(log_entries)
    state["batch_score"] = float(result.get("score", 0.0))
    state["batch_is_threat"] = bool(result.get("is_threat", False))
    return state


def _node_decision(state: PipelineState) -> PipelineState:
    ingestion: IngestionOutput = state["ingestion"]
    score: float = state.get("batch_score", 0.0)
    decision: DecisionOutput = decision_agent(ingestion, score)
    state["decision"] = decision
    return state


def build_graph():
    graph = StateGraph(PipelineState)
    graph.add_node("ingestion", _node_ingestion)
    graph.add_node("ml_scoring", _node_ml_scoring)
    graph.add_node("decision", _node_decision)

    graph.add_edge(START, "ingestion")
    graph.add_edge("ingestion", "ml_scoring")
    graph.add_edge("ml_scoring", "decision")
    graph.add_edge("decision", END)

    return graph.compile()


def run_agents_pipeline(logs: List[Dict[str, Any]], trace_id: str | None = None) -> Dict[str, Any]:
    """Public API to run the small agent pipeline.

    Returns a dict with keys: trace_id, score, decision
    """
    compiled = build_graph()
    tid = trace_id or str(uuid.uuid4())
    
    # Initialize state with all required keys
    initial_state: PipelineState = {
        "logs": logs,
        "trace_id": tid,
        "ingestion": None,
        "batch_score": None,
        "batch_is_threat": None,
        "decision": None
    }
    
    out: PipelineState = compiled.invoke(initial_state)
    decision = out.get("decision", {})
    return {
        "trace_id": tid,
        "score": out.get("batch_score", 0.0),
        "decision": decision,
    }


