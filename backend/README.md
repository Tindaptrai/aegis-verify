# Backend

The backend contains the canonical event model, a pure evidence hash helper, and
read-only scenario manifest validation. Install from the repository root with `python -m pip install -e ".[test]"`
and run `python -m pytest backend/tests -q` in the same virtual environment.

The import package is `aegis_verify`; its source directory is `backend/app`.
See [the field contract and examples](../docs/CANONICAL_EVENT.md).

Use `aegis_verify.models.ScenarioManifest` for already-decoded scenario data, and
`aegis_verify.scenario_loader.load_scenario` / `parse_scenario_yaml` for YAML.
See [the scenario contract and public error interface](../docs/SCENARIO_SCHEMA.md).

Evidence evaluation, CLI, run comparison, and the API are later issues. These
contracts and their tests require no live lab.
