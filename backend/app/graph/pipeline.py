from langgraph.graph import END, StateGraph

from app.graph import nodes
from app.graph.state import GraphState


def build_pipeline():
    graph = StateGraph(GraphState)

    graph.add_node("ingest", nodes.ingest_node)
    graph.add_node("configuration", nodes.configuration_node)
    graph.add_node("static_scan", nodes.static_scan_node)
    graph.add_node("dependency_scan", nodes.dependency_scan_node)
    graph.add_node("compliance_scan", nodes.compliance_scan_node)
    graph.add_node("risk_correlation", nodes.risk_correlation_node)
    graph.add_node("security_reasoning", nodes.security_reasoning_node)
    graph.add_node("merge", nodes.merge_node)
    graph.add_node("compliance_scoring", nodes.compliance_scoring_node)
    graph.add_node("report_generation", nodes.report_node)

    graph.set_entry_point("ingest")
    graph.add_edge("ingest", "configuration")
    graph.add_edge("ingest", "static_scan")
    graph.add_edge("ingest", "dependency_scan")
    graph.add_edge("ingest", "compliance_scan")
    graph.add_edge(
        ["configuration", "static_scan", "dependency_scan", "compliance_scan"],
        "risk_correlation",
    )
    graph.add_conditional_edges(
        "risk_correlation",
        nodes.route_after_risk_correlation,
        {"security_reasoning": "security_reasoning", "merge": "merge"},
    )
    graph.add_edge("security_reasoning", "merge")
    graph.add_edge("merge", "compliance_scoring")
    graph.add_edge("compliance_scoring", "report_generation")
    graph.add_edge("report_generation", END)

    return graph.compile()


pipeline = build_pipeline()
