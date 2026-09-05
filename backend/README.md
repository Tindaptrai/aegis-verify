# Backend

The backend currently contains the canonical event model and a pure evidence hash
helper. Install from the repository root with `python -m pip install -e ".[test]"`
and run `python -m pytest backend/tests -q` in the same virtual environment.

The import package is `aegis_verify`; its source directory is `backend/app`.
See [the field contract and examples](../docs/CANONICAL_EVENT.md).

Scenario validation, CLI, run comparison, and the API are later issues. This initial
contract and its tests require no live lab.
