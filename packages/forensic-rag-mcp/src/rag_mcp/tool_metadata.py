"""Per-tool caveats and interpretation constraints for structured responses.

BATCH-PMI2: The kb_search_knowledge / kb_list_knowledge_sources /
kb_get_knowledge_stats tool metadata entries have been removed together with
the tools themselves.  The Chroma-backed tool surface is gone; RAG is served
exclusively by the gateway core tool ``rag_search_case``.

DEFAULT_METADATA is kept for any future tool registrations.
"""

TOOL_METADATA: dict[str, dict[str, list[str] | str]] = {}

DEFAULT_METADATA: dict[str, list[str] | str] = {
    "caveats": ["No specific caveats"],
    "interpretation_constraint": "Interpret results in context of the specific investigation",
}
