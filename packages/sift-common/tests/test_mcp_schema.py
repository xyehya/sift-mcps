"""Tests for the shared MCP ``outputSchema`` builder (B-MVP-039)."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, Field

from sift_common.mcp_schema import SchemaCollisionError, output_schema


class _Nested(BaseModel):
    label: str


class _Success(BaseModel):
    ok: bool = True
    detail: _Nested | None = None


class _Error(BaseModel):
    error: str
    remediation: str = Field(default="")


def test_output_schema_root_is_object_with_anyof():
    schema = output_schema(_Success, _Error)
    assert schema["type"] == "object"
    assert schema["anyOf"] == [
        {"$ref": "#/$defs/__SuccessResult"},
        {"$ref": "#/$defs/__ToolErrorResult"},
    ]
    # Branch bodies and any nested model defs are hoisted to the root $defs.
    defs = schema["$defs"]
    assert "__SuccessResult" in defs
    assert "__ToolErrorResult" in defs
    assert "_Nested" in defs  # nested $ref must resolve at the document root


def test_output_schema_no_nested_defs_left_in_branches():
    schema = output_schema(_Success, _Error)
    assert "$defs" not in schema["$defs"]["__SuccessResult"]
    assert "$defs" not in schema["$defs"]["__ToolErrorResult"]


def _make_model_with_nested(field_type: type) -> type[BaseModel]:
    """Build an outer model nesting a model named ``Shared`` in a private scope.

    Two such models produce a ``$defs`` key ``"Shared"`` from *distinct* classes
    — exactly the silent-overwrite hazard the guard protects against.
    """

    class Shared(BaseModel):
        v: field_type  # type: ignore[valid-type]

    class Outer(BaseModel):
        s: Shared

    return Outer


def test_output_schema_collision_guard_raises():
    """Two models hoisting a $def under the same name must fail loudly,
    not silently overwrite one definition."""
    success = _make_model_with_nested(int)
    error = _make_model_with_nested(str)
    # Sanity: both branches really do hoist a "Shared" def from different classes.
    assert "Shared" in success.model_json_schema()["$defs"]
    assert "Shared" in error.model_json_schema()["$defs"]

    with pytest.raises(SchemaCollisionError) as exc:
        output_schema(success, error)
    assert "Shared" in str(exc.value)
