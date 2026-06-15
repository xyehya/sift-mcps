"""Shared MCP ``outputSchema`` builder — the SIFT add-on authoring standard.

Every SIFT backend (core or add-on) advertises, per tool, a structured
``outputSchema``: the tool's success model **OR** a structured ``ToolError`` on
the error path. The MCP spec requires this schema to be an object-typed JSON
Schema, and strict clients (e.g. the Claude Code MCP loader) reject a bare
``anyOf`` whose root ``type`` is absent with ``Invalid input: expected
"object"`` — which can drop the ENTIRE aggregated ``tools/list`` and take the
whole gateway MCP surface down (B-MVP-038).

Building that schema by hand is subtle (root ``type``, ``$defs`` hoisting, ref
resolution), and the logic was being copy-pasted verbatim into every backend's
``registry.py`` — drift risk, and the next add-on would copy it a third time.

This module is the single home for that logic so that **any backend, including
future add-ons, emits a spec-compliant ``outputSchema`` with zero core/gateway
changes**:

    from sift_common.mcp_schema import output_schema

    FunctionTool(
        ...,
        output_schema=output_schema(MyToolOut, ToolError),
    )

A conforming backend that uses this helper is robust by construction; the
gateway additionally repairs any non-conforming proxied schema at aggregation
(B-MVP-038 ``_sanitize_output_schema``) as belt-and-suspenders.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

__all__ = ["output_schema", "SchemaCollisionError"]

# Branch-body keys injected at the document root. Underscore-prefixed so they
# cannot collide with pydantic's PascalCase model names hoisted from $defs.
_SUCCESS_KEY = "__SuccessResult"
_ERROR_KEY = "__ToolErrorResult"


class SchemaCollisionError(ValueError):
    """Raised when the success and error models define clashing ``$defs`` names.

    A silent ``dict.update`` would let one branch's definition overwrite the
    other's under the same name, producing a schema that mis-describes one of
    the branches. We fail loudly instead so the conflict is fixed at authoring
    time (rename one of the models).
    """


def output_schema(
    success_model: type[BaseModel],
    error_model: type[BaseModel],
) -> dict[str, Any]:
    """Build the advertised ``outputSchema`` for one tool.

    The result admits either the tool's success shape or a structured error,
    so a schema-validating client (and the D27b gateway response-guard) accepts
    error results instead of rejecting them as schema-violating.

    :param success_model: the tool's success/output pydantic model.
    :param error_model: the structured error model (each backend's ``ToolError``).
    :returns: an object-typed JSON Schema with an ``anyOf`` over both shapes.
    :raises SchemaCollisionError: if the two models hoist ``$defs`` entries that
        share a name (which would silently overwrite one definition).

    The root carries ``"type": "object"`` because the MCP spec requires an
    ``outputSchema`` to be an object-typed JSON Schema. Both ``anyOf`` branches
    are pydantic models (objects), so the added root type is always satisfied.

    Each branch's own ``$defs`` are hoisted to the combined document root and
    the branch bodies are referenced via ``#/$defs/...``. A bare ``anyOf`` of
    two ``model_json_schema()`` outputs leaves each branch's ``$defs`` nested,
    so a nested ``$ref`` (e.g. ``#/$defs/Finding``) — which resolves against
    the document root — dangles, and the structured-output validator raises
    ``PointerToNowhere`` the moment such a tool actually returns. Hoisting keeps
    every pointer resolvable at the root.
    """
    success = success_model.model_json_schema()
    error = error_model.model_json_schema()

    success_defs = success.pop("$defs", None) or {}
    error_defs = error.pop("$defs", None) or {}

    # Guard the previously-silent overwrite: if both branches define a $def
    # under the same name, one would clobber the other. Fail loudly.
    collisions = sorted(set(success_defs) & set(error_defs))
    if collisions:
        raise SchemaCollisionError(
            f"{success_model.__name__} and {error_model.__name__} both define "
            f"$defs entries named {collisions!r}; rename one set of models so "
            "the hoisted output-schema $defs namespace stays unambiguous."
        )

    defs: dict[str, Any] = {}
    defs.update(success_defs)
    defs.update(error_defs)
    # Branch bodies live in $defs too so the anyOf is a pair of resolvable refs
    # and every nested model ref shares the same root $defs namespace.
    defs[_SUCCESS_KEY] = success
    defs[_ERROR_KEY] = error
    return {
        "type": "object",
        "$defs": defs,
        "anyOf": [
            {"$ref": f"#/$defs/{_SUCCESS_KEY}"},
            {"$ref": f"#/$defs/{_ERROR_KEY}"},
        ],
    }
