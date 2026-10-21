-- Capability roles are provisioned by the database operator, never by replicas.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'bloc_runtime' AND NOT rolcanlogin AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolbypassrls)
       OR NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'bloc_operator' AND NOT rolcanlogin AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolbypassrls)
       OR NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'bloc_maintenance' AND NOT rolcanlogin AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolbypassrls) THEN
        RAISE EXCEPTION 'required capability roles are missing or privileged';
    END IF;
END $$;

CREATE SCHEMA bloc;
REVOKE ALL ON SCHEMA bloc FROM PUBLIC;

CREATE TABLE bloc.installation (
    id smallint PRIMARY KEY CHECK (id = 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO bloc.installation (id) VALUES (1);

CREATE TABLE bloc.installation_administrator (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    installation_id smallint NOT NULL UNIQUE REFERENCES bloc.installation(id),
    email text NOT NULL CHECK (octet_length(email) BETWEEN 3 AND 254),
    password_hash text NOT NULL CHECK (octet_length(password_hash) BETWEEN 1 AND 1024),
    credential_version bigint NOT NULL DEFAULT 1 CHECK (credential_version > 0),
    created_at timestamptz NOT NULL,
    password_changed_at timestamptz NOT NULL
);

CREATE TABLE bloc.operator_code (
    installation_id smallint NOT NULL REFERENCES bloc.installation(id),
    purpose text NOT NULL CHECK (purpose IN ('setup', 'recovery')),
    code_digest bytea NOT NULL UNIQUE CHECK (octet_length(code_digest) = 32),
    administrator_id uuid REFERENCES bloc.installation_administrator(id),
    credential_version bigint,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    PRIMARY KEY (installation_id, purpose),
    CHECK (expires_at = issued_at + interval '15 minutes'),
    CHECK ((purpose = 'setup' AND administrator_id IS NULL AND credential_version IS NULL)
        OR (purpose = 'recovery' AND administrator_id IS NOT NULL AND credential_version IS NOT NULL AND credential_version > 0))
);

CREATE TABLE bloc.security_audit_event (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    installation_id smallint NOT NULL REFERENCES bloc.installation(id),
    administrator_id uuid REFERENCES bloc.installation_administrator(id),
    action text NOT NULL CHECK (action IN ('code_issue', 'setup', 'sign_in', 'sign_out', 'password_change', 'recovery', 'restore')),
    outcome text NOT NULL CHECK (outcome = 'success'),
    request_id uuid NOT NULL DEFAULT gen_random_uuid()
);
CREATE INDEX ON bloc.security_audit_event (occurred_at);

CREATE FUNCTION bloc.issue_setup_code(digest bytea) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, bloc, pg_temp AS $$
DECLARE issued timestamptz;
BEGIN
    PERFORM id FROM bloc.installation WHERE id = 1 FOR UPDATE;
    IF EXISTS (SELECT FROM bloc.installation_administrator WHERE installation_id = 1) THEN
        RETURN NULL;
    END IF;
    issued := clock_timestamp();
    INSERT INTO bloc.operator_code (installation_id, purpose, code_digest, issued_at, expires_at)
        VALUES (1, 'setup', digest, issued, issued + interval '15 minutes')
        ON CONFLICT (installation_id, purpose) DO UPDATE SET code_digest = EXCLUDED.code_digest,
            issued_at = EXCLUDED.issued_at, expires_at = EXCLUDED.expires_at, consumed_at = NULL;
    INSERT INTO bloc.security_audit_event (installation_id, action, outcome) VALUES (1, 'code_issue', 'success');
    RETURN to_char((issued + interval '15 minutes') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
END $$;

CREATE FUNCTION bloc.claim_owner(digest bytea, identifier text, phc text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, bloc, pg_temp AS $$
DECLARE checked_at timestamptz; owner_id uuid;
BEGIN
    PERFORM id FROM bloc.installation WHERE id = 1 FOR UPDATE;
    IF EXISTS (SELECT FROM bloc.installation_administrator WHERE installation_id = 1) THEN
        RETURN 'closed';
    END IF;
    checked_at := clock_timestamp();
    IF NOT EXISTS (SELECT FROM bloc.operator_code WHERE installation_id = 1 AND purpose = 'setup'
        AND code_digest = digest AND consumed_at IS NULL AND expires_at > checked_at) THEN
        RETURN 'unusable';
    END IF;
    INSERT INTO bloc.installation_administrator (installation_id, email, password_hash, created_at, password_changed_at)
        VALUES (1, identifier, phc, checked_at, checked_at) RETURNING id INTO owner_id;
    UPDATE bloc.operator_code SET consumed_at = checked_at WHERE installation_id = 1 AND purpose = 'setup';
    INSERT INTO bloc.security_audit_event (installation_id, administrator_id, action, outcome)
        VALUES (1, owner_id, 'setup', 'success');
    RETURN 'created';
END $$;

REVOKE ALL ON ALL TABLES IN SCHEMA bloc FROM PUBLIC, bloc_runtime, bloc_operator, bloc_maintenance;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA bloc FROM PUBLIC, bloc_runtime, bloc_operator, bloc_maintenance;
GRANT USAGE ON SCHEMA bloc TO bloc_runtime, bloc_operator;
GRANT EXECUTE ON FUNCTION bloc.issue_setup_code(bytea) TO bloc_operator;
GRANT EXECUTE ON FUNCTION bloc.claim_owner(bytea, text, text) TO bloc_runtime;
GRANT SELECT ON public._sqlx_migrations TO bloc_runtime, bloc_operator;
