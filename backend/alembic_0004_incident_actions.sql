BEGIN;

-- Running upgrade 0003_bug_resolution_notes -> 0004_incident_actions

CREATE TYPE incident_action_status AS ENUM ('todo', 'doing', 'done');

CREATE TYPE incident_action_source AS ENUM ('generated', 'manual');

CREATE TABLE incident_actions (
    id UUID NOT NULL, 
    incident_id UUID NOT NULL, 
    title VARCHAR NOT NULL, 
    description VARCHAR, 
    owner_team VARCHAR, 
    status incident_action_status DEFAULT 'todo' NOT NULL, 
    source incident_action_source DEFAULT 'generated' NOT NULL, 
    sort_order INTEGER, 
    completed_at TIMESTAMP WITHOUT TIME ZONE, 
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT now(), 
    PRIMARY KEY (id), 
    FOREIGN KEY(incident_id) REFERENCES data_incidents (id)
);

CREATE INDEX ix_incident_actions_incident_id ON incident_actions (incident_id);

UPDATE alembic_version SET version_num='0004_incident_actions' WHERE alembic_version.version_num = '0003_bug_resolution_notes';

COMMIT;

