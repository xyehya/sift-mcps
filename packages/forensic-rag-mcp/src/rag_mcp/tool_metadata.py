"""Per-tool caveats and interpretation constraints for structured responses.

BATCH-OSX-RAG: the kb_ knowledge tools are restored, now backed by the
Supabase pgvector store (see ``server.py``). The FastMCP server returns
provenance-linked, path-free results directly; these metadata entries are kept
as reference caveats for any caller that wants per-tool interpretation guidance.
"""

TOOL_METADATA: dict[str, dict[str, list[str] | str]] = {
    "kb_search_knowledge": {
        "caveats": [
            "Results are shared reference knowledge, not case evidence.",
            "Relevance is by embedding distance; correlate with case artifacts.",
        ],
        "interpretation_constraint": "Use retrieved knowledge as grounding context only; never as attribution or as a case finding.",
    },
    "kb_list_knowledge_sources": {
        "caveats": ["Source labels describe the corpus, not case data."],
        "interpretation_constraint": "Use to pick source/source_ids filters; not evidence.",
    },
    "kb_get_knowledge_stats": {
        "caveats": ["Statistics describe the shared knowledge corpus only."],
        "interpretation_constraint": "Health/size signal only; not case evidence.",
    },
}

DEFAULT_METADATA: dict[str, list[str] | str] = {
    "caveats": ["No specific caveats"],
    "interpretation_constraint": "Interpret results in context of the specific investigation",
}
