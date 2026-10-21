CREATE TABLE bloc.tenant (
 installation_id smallint NOT NULL DEFAULT 1 REFERENCES bloc.installation CHECK(installation_id=1),
 id uuid PRIMARY KEY, name text NOT NULL CHECK(char_length(name) BETWEEN 1 AND 128 AND octet_length(name)<=512),
 status text NOT NULL DEFAULT 'active' CHECK(status IN('active','suspended')),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0),
 created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL
);
CREATE INDEX ON bloc.tenant(created_at,id);
CREATE TABLE bloc.tenant_user (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES bloc.tenant,
 email text COLLATE "C" NOT NULL CHECK(octet_length(email) BETWEEN 3 AND 254), display_name text CHECK(char_length(display_name) BETWEEN 1 AND 128 AND octet_length(display_name)<=512),
 status text NOT NULL DEFAULT 'active' CHECK(status IN('active','suspended')),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0), created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
 UNIQUE(tenant_id,email), UNIQUE(tenant_id,id)
);
CREATE INDEX ON bloc.tenant_user(tenant_id,created_at,id);
ALTER TABLE bloc.security_audit_event ADD COLUMN tenant_id uuid REFERENCES bloc.tenant,
 ADD COLUMN tenant_user_id uuid,
 ADD CONSTRAINT directory_user_target FOREIGN KEY(tenant_id,tenant_user_id) REFERENCES bloc.tenant_user(tenant_id,id);
ALTER TABLE bloc.security_audit_event DROP CONSTRAINT security_audit_event_action_check;
ALTER TABLE bloc.security_audit_event ADD CONSTRAINT security_audit_event_action_check CHECK(action IN('code_issue','setup','sign_in','sign_out','password_change','recovery','restore','tenant_create','tenant_update','tenant_suspend','tenant_reactivate','tenant_user_create','tenant_user_update','tenant_user_suspend','tenant_user_reactivate'));
ALTER TABLE bloc.security_audit_event ADD CONSTRAINT directory_target CHECK(
 (action IN('tenant_create','tenant_update','tenant_suspend','tenant_reactivate') AND tenant_id IS NOT NULL AND tenant_user_id IS NULL)
 OR (action IN('tenant_user_create','tenant_user_update','tenant_user_suspend','tenant_user_reactivate') AND tenant_id IS NOT NULL AND tenant_user_id IS NOT NULL)
 OR (action NOT LIKE 'tenant%' AND tenant_id IS NULL AND tenant_user_id IS NULL));
ALTER TABLE bloc.administrator_denial_aggregate DROP CONSTRAINT administrator_denial_aggregate_action_check;
ALTER TABLE bloc.administrator_denial_aggregate ADD CONSTRAINT administrator_denial_aggregate_action_check CHECK(action IN('form_issue','setup','sign_in','sign_out','password_change','recovery','code_issue','restore','tenant_management','tenant_user_management'));
-- Private: every directory operation orders itself against credential/session/fence changes.
CREATE FUNCTION bloc.directory_authority(digest bytea) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE aid uuid;
BEGIN
 PERFORM id FROM bloc.installation WHERE id=1 FOR UPDATE;
 IF NOT EXISTS(SELECT FROM bloc.authorize_session(digest)) THEN RAISE EXCEPTION 'directory authority' USING ERRCODE='28000'; END IF;
 SELECT administrator_id INTO aid FROM bloc.administrator_session WHERE session_digest=digest;
 RETURN aid;
END $$;
CREATE FUNCTION bloc.directory_tenants(digest bytea,record_id uuid,cursor_time bigint,cursor_id uuid)
RETURNS TABLE(id text,name text,status text,version bigint,created text,updated text,cursor_value bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
BEGIN
 PERFORM bloc.directory_authority(digest);
 RETURN QUERY SELECT t.id::text,t.name,t.status,t.version,to_char(t.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),to_char(t.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),(extract(epoch FROM t.created_at)*1000000)::bigint FROM bloc.tenant t
 WHERE (record_id IS NULL OR t.id=record_id) AND (cursor_time IS NULL OR ((extract(epoch FROM t.created_at)*1000000)::bigint,t.id)>(cursor_time,cursor_id)) ORDER BY t.created_at,t.id LIMIT 51;
END $$;
CREATE FUNCTION bloc.directory_users(digest bytea,parent_id uuid,record_id uuid,cursor_time bigint,cursor_id uuid)
RETURNS TABLE(id text,email text,display_name text,status text,version bigint,created text,updated text,cursor_value bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
BEGIN
 PERFORM bloc.directory_authority(digest);
 RETURN QUERY SELECT u.id::text,u.email,u.display_name,u.status,u.version,to_char(u.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),to_char(u.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),(extract(epoch FROM u.created_at)*1000000)::bigint FROM bloc.tenant_user u
 WHERE u.tenant_id=parent_id AND (record_id IS NULL OR u.id=record_id) AND (cursor_time IS NULL OR ((extract(epoch FROM u.created_at)*1000000)::bigint,u.id)>(cursor_time,cursor_id)) ORDER BY u.created_at,u.id LIMIT 51;
END $$;
CREATE FUNCTION bloc.directory_mutate(digest bytea,operation text,parent_id uuid,record_id uuid,expected_version bigint,profile text,display_value text,status_value text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE aid uuid; checked timestamptz; t bloc.tenant; u bloc.tenant_user; event_action text;
BEGIN
 aid:=bloc.directory_authority(digest); checked:=clock_timestamp();
 IF operation IS NULL OR operation NOT IN('tenant_create','tenant_update','tenant_status','user_create','user_update','user_status') THEN RAISE EXCEPTION 'invalid operation'; END IF;
 IF operation LIKE 'user_%' THEN
  IF NOT EXISTS(SELECT FROM bloc.tenant WHERE id=parent_id) THEN RETURN 'missing'; END IF;
  SELECT * INTO u FROM bloc.tenant_user WHERE id=record_id AND tenant_id=parent_id;
  IF operation='user_create' THEN
   IF EXISTS(SELECT FROM bloc.tenant_user WHERE id=record_id) THEN RETURN CASE WHEN u.id IS NULL THEN 'foreign_creation' ELSE 'reused' END; END IF;
   BEGIN
    INSERT INTO bloc.tenant_user(id,tenant_id,email,display_name,created_at,updated_at) VALUES(record_id,parent_id,profile,display_value,checked,checked);
   EXCEPTION WHEN unique_violation THEN RETURN 'email_conflict'; END;
   event_action:='tenant_user_create';
  ELSE
   IF u.id IS NULL THEN RETURN 'missing'; END IF;
   IF expected_version IS NULL OR expected_version<=0 OR u.version<>expected_version THEN RETURN 'stale'; END IF;
   IF operation='user_update' THEN
    IF u.email=profile AND u.display_name IS NOT DISTINCT FROM display_value THEN RETURN 'ok'; END IF;
    BEGIN
     UPDATE bloc.tenant_user SET email=profile,display_name=display_value,version=version+1,updated_at=checked WHERE id=record_id AND tenant_id=parent_id;
    EXCEPTION WHEN unique_violation THEN RETURN 'email_conflict'; END;
    event_action:='tenant_user_update';
   ELSE
    IF status_value NOT IN('active','suspended') OR status_value IS NULL THEN RAISE EXCEPTION 'invalid status'; END IF;
    IF u.status=status_value THEN RETURN 'ok'; END IF;
    UPDATE bloc.tenant_user SET status=status_value,version=version+1,updated_at=checked WHERE id=record_id AND tenant_id=parent_id;
    event_action:=CASE status_value WHEN 'active' THEN 'tenant_user_reactivate' ELSE 'tenant_user_suspend' END;
   END IF;
  END IF;
 ELSE
  SELECT * INTO t FROM bloc.tenant WHERE id=parent_id;
  IF operation='tenant_create' THEN
   IF t.id IS NOT NULL THEN RETURN 'reused'; END IF;
   INSERT INTO bloc.tenant(id,name,created_at,updated_at) VALUES(parent_id,profile,checked,checked);
   event_action:='tenant_create';
  ELSE
   IF t.id IS NULL THEN RETURN 'missing'; END IF;
   IF expected_version IS NULL OR expected_version<=0 OR t.version<>expected_version THEN RETURN 'stale'; END IF;
   IF operation='tenant_update' THEN
    IF t.name=profile THEN RETURN 'ok'; END IF;
    UPDATE bloc.tenant SET name=profile,version=version+1,updated_at=checked WHERE id=parent_id;
    event_action:='tenant_update';
   ELSE
    IF status_value NOT IN('active','suspended') OR status_value IS NULL THEN RAISE EXCEPTION 'invalid status'; END IF;
    IF t.status=status_value THEN RETURN 'ok'; END IF;
    UPDATE bloc.tenant SET status=status_value,version=version+1,updated_at=checked WHERE id=parent_id;
    event_action:=CASE status_value WHEN 'active' THEN 'tenant_reactivate' ELSE 'tenant_suspend' END;
   END IF;
  END IF;
 END IF;
 INSERT INTO bloc.security_audit_event(installation_id,administrator_id,action,outcome,tenant_id,tenant_user_id) VALUES(1,aid,event_action,'success',parent_id,CASE WHEN operation LIKE 'user_%' THEN record_id ELSE NULL END);
 RETURN 'ok';
END $$;
REVOKE ALL ON TABLE bloc.tenant,bloc.tenant_user FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
REVOKE ALL ON FUNCTION bloc.directory_authority(bytea),bloc.directory_tenants(bytea,uuid,bigint,uuid),bloc.directory_users(bytea,uuid,uuid,bigint,uuid),bloc.directory_mutate(bytea,text,uuid,uuid,bigint,text,text,text) FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
GRANT EXECUTE ON FUNCTION bloc.directory_tenants(bytea,uuid,bigint,uuid),bloc.directory_users(bytea,uuid,uuid,bigint,uuid),bloc.directory_mutate(bytea,text,uuid,uuid,bigint,text,text,text) TO bloc_runtime;
