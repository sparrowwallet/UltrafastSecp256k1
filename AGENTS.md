# AGENTS.md -- UltrafastSecp256k1

Use the SQLite project graph before broad file search.

## Canonical Graph

- DB: `.project_graph.db`
- Rebuild:

```bash
python3 scripts/build_project_graph.py --rebuild
```

## Preferred Workflow

1. Query graph first.
2. Read only the files or line ranges the graph points to.
3. After structural changes, rebuild the graph.
4. Before finishing, rerun `preflight.py` if the change is substantial.

## Most Useful Commands

```bash
python3 scripts/query_graph.py context cpu/src/ct_sign.cpp
python3 scripts/query_graph.py impact cpu/src/ecdh.cpp
python3 scripts/query_graph.py routing ecdsa_sign
python3 scripts/query_graph.py tags
python3 scripts/query_graph.py tag constant_time
python3 scripts/query_graph.py symbol ecdsa_sign
python3 scripts/query_graph.py optimize 15
python3 scripts/query_graph.py risk 15
python3 scripts/query_graph.py gpuwork 15
python3 scripts/query_graph.py fragile 15
python3 scripts/query_graph.py hotspots 20
python3 scripts/query_graph.py coverage ecdsa_sign
```

## Reasoning Layers

The graph includes more than structure. It also includes:

- semantic classification
- secret/CT metadata
- parser-boundary sensitivity
- performance/gpu-candidate scoring
- audit coverage
- change history
- risk/gain/optimization priority

Important tables/views:

- `semantic_tags`
- `entity_tags`
- `symbol_semantics`
- `symbol_security`
- `symbol_performance`
- `symbol_audit_coverage`
- `symbol_history`
- `symbol_scores`
- `v_symbol_reasoning`

## Rules

- Do not claim CT guarantees without checking the graph and the relevant tests.
- Do not claim audit coverage without checking `function_test_map` or `symbol_audit_coverage`.
- Do not change ABI-visible or secret-bearing code blindly; query `routing`, `bindings`, and `fragile` first.
- If you add new graph-worthy entities, update the graph builder.
