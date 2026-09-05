"""Private, bounded YAML policy. No public diagnostics or filesystem access."""

import re

import yaml
from yaml.events import (
    AliasEvent, CollectionEndEvent, CollectionStartEvent, DocumentStartEvent,
    ScalarEvent,
)
from yaml.nodes import MappingNode, ScalarNode, SequenceNode


MAX_BYTES = 256 * 1024
MAX_DEPTH = 20
MAX_NODES = 10_000
_PREFIX = "tag:yaml.org,2002:"
_TAGS = frozenset(_PREFIX + name for name in ("str", "bool", "int", "float", "null", "seq", "map"))


class YamlPolicyError(Exception):
    """Fixed code and coordinates only; never retain the parser's source mark."""

    def __init__(self, code: str, mark=None):
        super().__init__(code)
        self.code = code
        self.line = mark.line + 1 if mark is not None else None
        self.column = mark.column + 1 if mark is not None else None


class _ManifestSafeLoader(yaml.SafeLoader):
    # Copy per subclass: never change the shared SafeLoader resolver table.
    yaml_implicit_resolvers = {
        key: [(tag, pattern) for tag, pattern in entries if tag != _PREFIX + "bool"]
        for key, entries in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def construct_object(self, node, deep=False):
        if node.tag not in _TAGS:
            raise YamlPolicyError("yaml_tag", node.start_mark)
        expected_shape = {
            _PREFIX + "map": MappingNode, _PREFIX + "seq": SequenceNode,
        }.get(node.tag, ScalarNode)
        if not isinstance(node, expected_shape):
            raise YamlPolicyError("yaml_tag_shape", node.start_mark)
        if node.tag == _PREFIX + "bool":
            if not isinstance(node, ScalarNode) or node.value not in ("true", "false"):
                raise YamlPolicyError("yaml_scalar", node.start_mark)
        if node.tag == _PREFIX + "null":
            if not isinstance(node, ScalarNode) or node.value not in ("", "~", "null", "Null", "NULL"):
                raise YamlPolicyError("yaml_scalar", node.start_mark)
        try:
            return super().construct_object(node, deep=deep)
        except (ValueError, IndexError, OverflowError):
            raise YamlPolicyError("yaml_scalar", node.start_mark) from None

    def construct_mapping(self, node, deep=False):
        if not isinstance(node, MappingNode):
            raise YamlPolicyError("yaml_mapping", node.start_mark)
        mapping = {}
        for key_node, value_node in node.value:
            if key_node.tag == _PREFIX + "merge" or key_node.value == "<<":
                raise YamlPolicyError("yaml_merge", key_node.start_mark)
            if not isinstance(key_node, ScalarNode) or key_node.tag != _PREFIX + "str":
                raise YamlPolicyError("yaml_key", key_node.start_mark)
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                raise YamlPolicyError("yaml_duplicate_key", key_node.start_mark)
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


_ManifestSafeLoader.add_implicit_resolver(
    _PREFIX + "bool", re.compile(r"^(?:true|false)$"), list("tf"),
)


def _check_events(text: str) -> None:
    """Enforce budgets iteratively before PyYAML composes recursive nodes."""
    depth = nodes = documents = 0
    events = yaml.parse(text, Loader=_ManifestSafeLoader)
    try:
        for event in events:
            if isinstance(event, DocumentStartEvent):
                documents += 1
                if documents > 1:
                    raise YamlPolicyError("yaml_documents", event.start_mark)
            if isinstance(event, AliasEvent) or getattr(event, "anchor", None) is not None:
                raise YamlPolicyError("yaml_alias", event.start_mark)
            tag = getattr(event, "tag", None)
            if tag is not None and tag not in _TAGS:
                raise YamlPolicyError("yaml_tag", event.start_mark)
            if isinstance(event, (ScalarEvent, CollectionStartEvent)):
                nodes += 1
                if nodes > MAX_NODES:
                    raise YamlPolicyError("yaml_nodes", event.start_mark)
            if isinstance(event, CollectionStartEvent):
                depth += 1
                if depth > MAX_DEPTH:
                    raise YamlPolicyError("yaml_depth", event.start_mark)
            elif isinstance(event, CollectionEndEvent):
                depth -= 1
    finally:
        events.close()


def read_yaml_data(text: str) -> dict:
    """Called only after the public boundary checks size and UTF-8 encodability."""
    _check_events(text)
    data = yaml.load(text, Loader=_ManifestSafeLoader)
    if not isinstance(data, dict):
        raise YamlPolicyError("yaml_root")
    return data
