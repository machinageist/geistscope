-- GeistScope security graph production schema sketch.
-- This is intentionally not applied by the current local-first JSONL adapter.
-- It documents the Postgres target shape for a future PostgresGraphStore.

CREATE TABLE IF NOT EXISTS security_nodes (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    label TEXT NOT NULL,
    properties JSONB NOT NULL DEFAULT '{}'::jsonb,
    evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS security_edges (
    id TEXT PRIMARY KEY,
    from_node TEXT NOT NULL REFERENCES security_nodes(id) ON DELETE CASCADE,
    to_node TEXT NOT NULL REFERENCES security_nodes(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    label TEXT,
    properties JSONB NOT NULL DEFAULT '{}'::jsonb,
    evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS security_nodes_kind_idx ON security_nodes(kind);
CREATE INDEX IF NOT EXISTS security_edges_from_idx ON security_edges(from_node);
CREATE INDEX IF NOT EXISTS security_edges_to_idx ON security_edges(to_node);
CREATE INDEX IF NOT EXISTS security_edges_kind_idx ON security_edges(kind);
