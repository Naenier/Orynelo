CREATE TABLE metadata (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);
CREATE TABLE diagnoses (
    id TEXT PRIMARY KEY NOT NULL,
    target_original TEXT NOT NULL,
    target_normalized TEXT NOT NULL,
    target_host TEXT NOT NULL,
    target_port INTEGER NOT NULL,
    target_scheme TEXT NOT NULL,
    status TEXT NOT NULL,
    summary_title TEXT NOT NULL,
    summary_description TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    duration_ns INTEGER NOT NULL,
    version TEXT NOT NULL,
    commit_hash TEXT NOT NULL,
    snapshot_schema_version TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE check_results (
    diagnosis_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    check_id TEXT NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    duration_ns INTEGER NOT NULL,
    summary TEXT NOT NULL,
    error_code TEXT NOT NULL,
    PRIMARY KEY (diagnosis_id, position),
    FOREIGN KEY (diagnosis_id) REFERENCES diagnoses(id) ON DELETE CASCADE
);
CREATE TABLE evidence (
    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
    diagnosis_id TEXT NOT NULL,
    check_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    evidence_id TEXT NOT NULL,
    check_id TEXT NOT NULL,
    code TEXT NOT NULL,
    message TEXT NOT NULL,
    details_json TEXT NOT NULL,
    FOREIGN KEY (diagnosis_id, check_position)
        REFERENCES check_results(diagnosis_id, position) ON DELETE CASCADE
);
CREATE TABLE recommendations (
    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
    diagnosis_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    check_position INTEGER,
    position INTEGER NOT NULL,
    recommendation_id TEXT NOT NULL,
    check_id TEXT NOT NULL,
    priority TEXT NOT NULL,
    message TEXT NOT NULL,
    FOREIGN KEY (diagnosis_id) REFERENCES diagnoses(id) ON DELETE CASCADE,
    FOREIGN KEY (diagnosis_id, check_position)
        REFERENCES check_results(diagnosis_id, position) ON DELETE CASCADE
);
CREATE INDEX diagnoses_started_at_idx ON diagnoses(started_at DESC, id DESC);
CREATE INDEX diagnoses_status_started_at_idx ON diagnoses(status, started_at DESC);
CREATE INDEX diagnoses_target_idx ON diagnoses(target_normalized COLLATE NOCASE);
CREATE INDEX evidence_diagnosis_idx ON evidence(diagnosis_id, check_position, position);
CREATE INDEX recommendations_diagnosis_idx
    ON recommendations(diagnosis_id, scope, check_position, position);
INSERT INTO metadata(key, value) VALUES('schema_version', '1');
PRAGMA user_version = 1;
