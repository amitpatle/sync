-- Repository registry: identity is the immutable GitHub numeric repo ID, never the name.
CREATE TABLE repositories (
    github_repo_id             bigint PRIMARY KEY,
    github_node_id             text        NOT NULL,
    owner                      text        NOT NULL,
    owner_type                 text        NOT NULL,
    name                       text        NOT NULL,
    full_name                  text        NOT NULL,
    installation_id            bigint      NOT NULL,
    github_visibility          text        NOT NULL
        CHECK (github_visibility IN ('public', 'private', 'internal')),
    target_visibility          text        NOT NULL
        CHECK (target_visibility IN ('private', 'internal', 'public')),
    visibility_review_required boolean     NOT NULL DEFAULT false,
    archived                   boolean     NOT NULL DEFAULT false,
    is_fork                    boolean     NOT NULL DEFAULT false,
    disabled                   boolean     NOT NULL DEFAULT false,
    default_branch             text,
    description                text,
    topics                     text[]      NOT NULL DEFAULT '{}',
    has_wiki                   boolean     NOT NULL DEFAULT false,
    has_issues                 boolean     NOT NULL DEFAULT false,
    lifecycle                  text        NOT NULL DEFAULT 'active'
        CHECK (lifecycle IN ('active', 'missing', 'source_deleted', 'excluded')),
    exclusion_reason           text,
    sync_state                 text        NOT NULL DEFAULT 'pending'
        CHECK (sync_state IN ('pending', 'migrating', 'synced', 'blocked', 'quarantined')),
    missing_scans              integer     NOT NULL DEFAULT 0 CHECK (missing_scans >= 0),
    gitlab_project_id          bigint UNIQUE,
    gitlab_path                text,
    first_seen_at              timestamptz NOT NULL DEFAULT now(),
    last_seen_at               timestamptz NOT NULL,
    last_synced_at             timestamptz,
    updated_at                 timestamptz NOT NULL DEFAULT now()
);
-- Deliberately NOT unique: a deleted repo's name can be reused by a different repo ID.
CREATE INDEX repositories_full_name_idx ON repositories (lower(full_name));
CREATE INDEX repositories_state_idx ON repositories (lifecycle, sync_state);

CREATE TABLE repository_name_history (
    id             bigserial PRIMARY KEY,
    github_repo_id bigint      NOT NULL REFERENCES repositories (github_repo_id),
    old_full_name  text        NOT NULL,
    new_full_name  text        NOT NULL,
    change_kind    text        NOT NULL CHECK (change_kind IN ('renamed', 'transferred')),
    changed_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE discovery_runs (
    id                     uuid PRIMARY KEY,
    started_at             timestamptz NOT NULL,
    finished_at            timestamptz,
    dry_run                boolean     NOT NULL,
    complete               boolean,
    installations_scanned  integer,
    repos_seen             integer,
    change_summary         jsonb       NOT NULL DEFAULT '{}'::jsonb,
    failed_installations   jsonb       NOT NULL DEFAULT '{}'::jsonb
);

-- Append-only, hash-chained audit log. Chain links (prev_hash) are authoritative; `seq`
-- may have gaps (rolled-back dry runs consume sequence values).
CREATE TABLE audit_events (
    seq            bigserial   PRIMARY KEY,
    ts             timestamptz NOT NULL,
    actor          text        NOT NULL,
    action         text        NOT NULL,
    github_repo_id bigint,
    correlation_id text,
    details        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    prev_hash      text        NOT NULL,
    hash           text        NOT NULL UNIQUE
);
CREATE INDEX audit_events_repo_idx ON audit_events (github_repo_id);
CREATE INDEX audit_events_action_idx ON audit_events (action, ts);

CREATE FUNCTION audit_events_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only (% blocked)', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_events_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();
CREATE TRIGGER audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_immutable();
