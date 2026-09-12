import json
from typing import Any, Dict, List, Type

from crewai.tools import BaseTool
from pydantic import BaseModel, ConfigDict, Field

from red_team_agents.rag.local_chromadb_rag import query_local_chromadb_rag


class RAGRetrievalToolInput(BaseModel):
    """Input schema for local RAG retrieval."""

    model_config = ConfigDict(extra="forbid")

    query: str = Field(
        ...,
        description=(
            "Question to retrieve contextual evidence from the local ChromaDB RAG "
            "knowledge base."
        ),
    )
    top_k: int = Field(
        5,
        ge=1,
        le=10,
        description="Maximum number of chunks to retrieve.",
    )


class RAGRetrievalTool(BaseTool):
    name: str = "rag_retrieval"
    description: str = (
        "Retrieves audit-ready contextual evidence from the local ChromaDB RAG "
        "knowledge base. Use this for OWASP API Security Top 10, MITRE ATT&CK, "
        "NIS2 Article 21, RAG methodology, evaluation metrics, runtime evidence, "
        "Shadow API, BOLA/BFLA, and compliance/threat-mapping context. The tool "
        "returns source paths, chunk indexes, distances, excerpts, and routing "
        "metadata; it does not modify findings, ground truth, or metrics."
    )
    args_schema: Type[BaseModel] = RAGRetrievalToolInput

    def _run(self, query: str, top_k: int = 5) -> str:
        report = query_local_chromadb_rag(
            queries=[query],
            top_k=top_k,
        )

        query_report = report["queries"][0]

        response: Dict[str, Any] = {
            "tool": self.name,
            "status": "completed",
            "query": query_report["query"],
            "top_k": query_report["top_k"],
            "routing_applied": query_report.get("routing_applied", False),
            "preferred_source": query_report.get("preferred_source"),
            "results": [
                {
                    "rank": index + 1,
                    "source_path": result.get("source_path"),
                    "source_kind": result.get("source_kind"),
                    "chunk_index": result.get("chunk_index"),
                    "chunk_count": result.get("chunk_count"),
                    "distance": result.get("distance"),
                    "document_excerpt": result.get("document_excerpt"),
                }
                for index, result in enumerate(query_report.get("results", []))
            ],
            "methodological_boundary": {
                "rag_modifies_ground_truth": False,
                "rag_modifies_runtime_evidence": False,
                "rag_modifies_metrics": False,
                "rag_role": "contextual evidence retrieval for agent reasoning and reporting",
            },
        }

        return json.dumps(response, indent=2, ensure_ascii=False)
