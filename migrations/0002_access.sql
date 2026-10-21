ALTER TABLE bloc.installation ADD COLUMN recovery_required boolean NOT NULL DEFAULT false;
CREATE TABLE bloc.administrator_session (
 session_digest bytea PRIMARY KEY CHECK(octet_length(session_digest)=32),
 administrator_id uuid NOT NULL REFERENCES bloc.installation_administrator,
 credential_version bigint NOT NULL,
 created_at timestamptz NOT NULL, last_activity_at timestamptz NOT NULL,
 absolute_expires_at timestamptz NOT NULL, revoked_at timestamptz,
 CHECK(absolute_expires_at=created_at+interval '12 hours')
);
CREATE TABLE bloc.administrator_form_state (
 browser_digest bytea PRIMARY KEY CHECK(octet_length(browser_digest)=32),
 csrf_token bytea NOT NULL CHECK(octet_length(csrf_token)=32),
 session_digest bytea REFERENCES bloc.administrator_session ON DELETE CASCADE,
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 CHECK(expires_at=created_at+interval '30 minutes')
);
CREATE TABLE bloc.administrator_admission_bucket (
 scope text NOT NULL CHECK(scope IN ('credential_source','login_identifier','operator_code','password_change','hash_work','form_issue_source')),
 subject_digest bytea NOT NULL CHECK(octet_length(subject_digest)=32),
 admitted_at timestamptz[] NOT NULL CHECK(cardinality(admitted_at)<=30), expires_at timestamptz NOT NULL,
 PRIMARY KEY(scope,subject_digest)
);
CREATE TABLE bloc.administrator_denial_aggregate (
 minute timestamptz NOT NULL, action text NOT NULL CHECK(action IN ('form_issue','setup','sign_in','sign_out','password_change','recovery','code_issue','restore')),
 reason text NOT NULL CHECK(reason IN ('origin','csrf','malformed','oversized','media_type','admission','capacity','authority','credentials','conflict','storage')),
 count bigint NOT NULL CHECK(count>=0), PRIMARY KEY(minute,action,reason)
);
CREATE FUNCTION bloc.owner_credentials() RETURNS TABLE(email text,phc text,version bigint,recovery_required boolean)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
 SELECT a.email,a.password_hash,a.credential_version,i.recovery_required FROM bloc.installation_administrator a JOIN bloc.installation i ON i.id=a.installation_id;
$$;
CREATE FUNCTION bloc.code_usable(purpose_value text,digest bytea) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
 SELECT EXISTS(SELECT FROM bloc.operator_code c WHERE c.purpose=purpose_value AND c.code_digest=digest AND c.consumed_at IS NULL AND c.expires_at>clock_timestamp()
 AND (c.purpose='setup' AND NOT EXISTS(SELECT FROM bloc.installation_administrator) OR c.purpose='recovery' AND EXISTS(SELECT FROM bloc.installation_administrator a WHERE a.id=c.administrator_id AND a.credential_version=c.credential_version)));
$$;
CREATE FUNCTION bloc.issue_recovery_code(digest bytea) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE a bloc.installation_administrator; checked timestamptz;
BEGIN
 PERFORM id FROM bloc.installation WHERE id=1 FOR UPDATE;
 SELECT * INTO a FROM bloc.installation_administrator WHERE installation_id=1;
 IF NOT FOUND THEN RETURN NULL; END IF;
 checked:=clock_timestamp();
 INSERT INTO bloc.operator_code VALUES(1,'recovery',digest,a.id,a.credential_version,checked,checked+interval '15 minutes',NULL)
 ON CONFLICT(installation_id,purpose) DO UPDATE SET code_digest=EXCLUDED.code_digest,administrator_id=EXCLUDED.administrator_id,credential_version=EXCLUDED.credential_version,issued_at=EXCLUDED.issued_at,expires_at=EXCLUDED.expires_at,consumed_at=NULL;
 INSERT INTO bloc.security_audit_event(installation_id,administrator_id,action,outcome) VALUES(1,a.id,'code_issue','success');
 RETURN to_char((checked+interval '15 minutes') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
END $$;
CREATE FUNCTION bloc.authenticate_session(digest bytea,expected_version bigint, browser bytea, token bytea, old_browser bytea) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE a bloc.installation_administrator; checked timestamptz;
BEGIN
 PERFORM id FROM bloc.installation WHERE id=1 FOR UPDATE;
 SELECT * INTO a FROM bloc.installation_administrator WHERE installation_id=1;
 IF NOT FOUND OR a.credential_version<>expected_version OR (SELECT recovery_required FROM bloc.installation WHERE id=1) THEN RETURN false; END IF;
 checked:=clock_timestamp();
 DELETE FROM bloc.administrator_form_state WHERE expires_at<=checked;
 IF (SELECT count(*) FROM bloc.administrator_form_state)>=10000 THEN RETURN false; END IF;
 DELETE FROM bloc.administrator_form_state WHERE browser_digest=old_browser;
 INSERT INTO bloc.administrator_session VALUES(digest,a.id,a.credential_version,checked,checked,checked+interval '12 hours',NULL);
 INSERT INTO bloc.administrator_form_state VALUES(browser,token,digest,checked,checked+interval '30 minutes');
 INSERT INTO bloc.security_audit_event(installation_id,administrator_id,action,outcome) VALUES(1,a.id,'sign_in','success');
 RETURN true;
END $$;
CREATE FUNCTION bloc.authorize_session(digest bytea) RETURNS TABLE(email text,phc text,version bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE checked timestamptz;
BEGIN
 PERFORM id FROM bloc.installation WHERE id=1 FOR UPDATE;
 checked:=clock_timestamp();
 RETURN QUERY UPDATE bloc.administrator_session s SET last_activity_at=greatest(s.last_activity_at,checked)
 FROM bloc.installation_administrator a,bloc.installation i WHERE s.session_digest=digest AND a.id=s.administrator_id AND a.credential_version=s.credential_version AND i.id=1 AND NOT i.recovery_required AND s.revoked_at IS NULL AND s.absolute_expires_at>checked AND s.last_activity_at+interval '30 minutes'>checked
 RETURNING a.email,a.password_hash,a.credential_version;
END $$;
CREATE FUNCTION bloc.sign_out(digest bytea) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE aid uuid;
BEGIN
 PERFORM id FROM bloc.installation WHERE id=1 FOR UPDATE;
 UPDATE bloc.administrator_session SET revoked_at=clock_timestamp() WHERE session_digest=digest AND revoked_at IS NULL RETURNING administrator_id INTO aid;
 IF NOT FOUND THEN RETURN false; END IF;
 DELETE FROM bloc.administrator_form_state WHERE session_digest=digest;
 INSERT INTO bloc.security_audit_event(installation_id,administrator_id,action,outcome) VALUES(1,aid,'sign_out','success');
 RETURN true;
END $$;
CREATE FUNCTION bloc.replace_password(digest bytea,expected_version bigint,phc text,recovery boolean) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE a bloc.installation_administrator; checked timestamptz;
BEGIN
 PERFORM id FROM bloc.installation WHERE id=1 FOR UPDATE;
 checked:=clock_timestamp();
 SELECT * INTO a FROM bloc.installation_administrator WHERE installation_id=1;
 IF NOT FOUND THEN RETURN false; END IF;
 IF recovery THEN
  IF NOT EXISTS(SELECT FROM bloc.operator_code c WHERE c.purpose='recovery' AND c.code_digest=digest AND c.administrator_id=a.id AND c.credential_version=a.credential_version AND c.consumed_at IS NULL AND c.expires_at>checked) THEN RETURN false; END IF;
 ELSE
  IF a.credential_version<>expected_version OR NOT EXISTS(SELECT FROM bloc.administrator_session s WHERE s.session_digest=digest AND s.administrator_id=a.id AND s.credential_version=a.credential_version AND s.revoked_at IS NULL AND s.absolute_expires_at>checked AND s.last_activity_at+interval '30 minutes'>checked) OR (SELECT recovery_required FROM bloc.installation WHERE id=1) THEN RETURN false; END IF;
 END IF;
 UPDATE bloc.installation_administrator SET password_hash=phc,credential_version=credential_version+1,password_changed_at=checked WHERE id=a.id;
 UPDATE bloc.administrator_session SET revoked_at=checked WHERE administrator_id=a.id AND revoked_at IS NULL;
 DELETE FROM bloc.administrator_form_state WHERE session_digest IS NOT NULL;
 UPDATE bloc.operator_code SET consumed_at=checked WHERE installation_id=1 AND consumed_at IS NULL;
 UPDATE bloc.installation SET recovery_required=false WHERE id=1;
 INSERT INTO bloc.security_audit_event(installation_id,administrator_id,action,outcome) VALUES(1,a.id,CASE WHEN recovery THEN 'recovery' ELSE 'password_change' END,'success');
 RETURN true;
END $$;
CREATE FUNCTION bloc.invalidate_access() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE aid uuid;
BEGIN
 PERFORM id FROM bloc.installation WHERE id=1 FOR UPDATE;
 UPDATE bloc.installation_administrator SET credential_version=credential_version+1 RETURNING id INTO aid;
 UPDATE bloc.installation SET recovery_required=(aid IS NOT NULL) WHERE id=1;
 UPDATE bloc.administrator_session SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL;
 DELETE FROM bloc.operator_code;
 DELETE FROM bloc.administrator_form_state;
 INSERT INTO bloc.security_audit_event(installation_id,administrator_id,action,outcome) VALUES(1,aid,'restore','success');
END $$;
-- The installation singleton serializes bounded global admission and form capacity.
CREATE FUNCTION bloc.reserve_admission(scopes text[],subjects bytea[],units integer[]) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE checked timestamptz; idx integer; limit_value integer; events timestamptz[]; wait_seconds integer:=0; new_keys integer:=0; n integer;
BEGIN
 IF (SELECT count(DISTINCT (scopes[i],subjects[i])) FROM generate_subscripts(scopes,1) i)<>cardinality(scopes) THEN RAISE EXCEPTION 'duplicate reservation'; END IF;
 IF cardinality(scopes)<>cardinality(subjects) OR cardinality(scopes)<>cardinality(units) OR cardinality(scopes) NOT BETWEEN 1 AND 4 THEN RAISE EXCEPTION 'invalid reservation'; END IF;
 PERFORM id FROM bloc.installation WHERE id=1 FOR UPDATE;
 checked:=clock_timestamp();
 DELETE FROM bloc.administrator_admission_bucket WHERE expires_at<=checked;
 FOR idx IN 1..cardinality(scopes) LOOP
  limit_value:=CASE scopes[idx] WHEN 'password_change' THEN 5 WHEN 'hash_work' THEN 30 ELSE 10 END;
  IF scopes[idx] NOT IN ('credential_source','login_identifier','operator_code','password_change','hash_work','form_issue_source') OR units[idx] NOT BETWEEN 1 AND 2 THEN RAISE EXCEPTION 'invalid reservation'; END IF;
  SELECT array_agg(e ORDER BY e) INTO events FROM bloc.administrator_admission_bucket b CROSS JOIN LATERAL unnest(b.admitted_at) e WHERE b.scope=scopes[idx] AND b.subject_digest=subjects[idx] AND e>checked-interval '60 seconds';
  n:=coalesce(cardinality(events),0);
  IF n+units[idx]>limit_value THEN wait_seconds:=greatest(wait_seconds,ceil(extract(epoch FROM events[n+units[idx]-limit_value]+interval '60 seconds'-checked))::integer,1); END IF;
  IF NOT EXISTS(SELECT FROM bloc.administrator_admission_bucket WHERE scope=scopes[idx] AND subject_digest=subjects[idx]) THEN new_keys:=new_keys+1; END IF;
 END LOOP;
 IF wait_seconds>0 THEN RETURN wait_seconds; END IF;
 IF (SELECT count(*) FROM bloc.administrator_admission_bucket)+new_keys>10000 THEN RETURN -1; END IF;
 FOR idx IN 1..cardinality(scopes) LOOP
  SELECT coalesce(array_agg(e ORDER BY e),ARRAY[]::timestamptz[]) INTO events FROM bloc.administrator_admission_bucket b CROSS JOIN LATERAL unnest(b.admitted_at) e WHERE b.scope=scopes[idx] AND b.subject_digest=subjects[idx] AND e>checked-interval '60 seconds';
  INSERT INTO bloc.administrator_admission_bucket VALUES(scopes[idx],subjects[idx],events||array_fill(checked,ARRAY[units[idx]]),checked+interval '2 minutes') ON CONFLICT(scope,subject_digest) DO UPDATE SET admitted_at=EXCLUDED.admitted_at,expires_at=EXCLUDED.expires_at;
 END LOOP;
 RETURN 0;
END $$;
CREATE FUNCTION bloc.form_state(browser bytea,session bytea,new_token bytea) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE checked timestamptz; result bytea;
BEGIN
 PERFORM id FROM bloc.installation WHERE id=1 FOR UPDATE;
 checked:=clock_timestamp();
 DELETE FROM bloc.administrator_form_state WHERE expires_at<=checked;
 SELECT csrf_token INTO result FROM bloc.administrator_form_state WHERE browser_digest=browser AND session_digest IS NOT DISTINCT FROM session;
 IF FOUND THEN RETURN result; END IF;
 IF new_token IS NULL THEN RETURN NULL; END IF;
 IF session IS NOT NULL AND NOT EXISTS(SELECT FROM bloc.administrator_session s JOIN bloc.installation_administrator a ON a.id=s.administrator_id WHERE s.session_digest=session AND s.revoked_at IS NULL AND s.credential_version=a.credential_version AND s.absolute_expires_at>checked AND s.last_activity_at+interval '30 minutes'>checked) THEN RETURN NULL; END IF;
 IF (SELECT count(*) FROM bloc.administrator_form_state)>=10000 THEN RETURN NULL; END IF;
 DELETE FROM bloc.administrator_form_state WHERE browser_digest=browser;
 INSERT INTO bloc.administrator_form_state VALUES(browser,new_token,session,checked,checked+interval '30 minutes');
 RETURN new_token;
END $$;
CREATE FUNCTION bloc.record_denial(action_value text,reason_value text) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
 INSERT INTO bloc.administrator_denial_aggregate VALUES(date_trunc('minute',clock_timestamp()),action_value,reason_value,1) ON CONFLICT(minute,action,reason) DO UPDATE SET count=CASE WHEN bloc.administrator_denial_aggregate.count=9223372036854775807 THEN 9223372036854775807 ELSE bloc.administrator_denial_aggregate.count+1 END;
$$;
CREATE FUNCTION bloc.maintain_access() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE n integer; total integer:=0;
BEGIN
 DELETE FROM bloc.security_audit_event WHERE id IN(SELECT id FROM bloc.security_audit_event WHERE occurred_at<clock_timestamp()-interval '90 days' ORDER BY occurred_at LIMIT 1000); GET DIAGNOSTICS n=ROW_COUNT; total:=total+n;
 DELETE FROM bloc.administrator_denial_aggregate WHERE (minute,action,reason) IN(SELECT minute,action,reason FROM bloc.administrator_denial_aggregate WHERE minute<clock_timestamp()-interval '7 days' ORDER BY minute LIMIT 1000); GET DIAGNOSTICS n=ROW_COUNT; total:=total+n;
 DELETE FROM bloc.administrator_form_state WHERE browser_digest IN(SELECT browser_digest FROM bloc.administrator_form_state WHERE expires_at<=clock_timestamp() LIMIT 1000);
 DELETE FROM bloc.administrator_admission_bucket WHERE (scope,subject_digest) IN(SELECT scope,subject_digest FROM bloc.administrator_admission_bucket WHERE expires_at<=clock_timestamp() LIMIT 1000);
 RETURN total;
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA bloc FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA bloc FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
GRANT USAGE ON SCHEMA bloc TO bloc_runtime,bloc_operator,bloc_maintenance;
GRANT SELECT ON public._sqlx_migrations TO bloc_runtime,bloc_operator,bloc_maintenance;
GRANT EXECUTE ON FUNCTION bloc.issue_setup_code(bytea),bloc.issue_recovery_code(bytea),bloc.invalidate_access() TO bloc_operator;
GRANT EXECUTE ON FUNCTION bloc.claim_owner(bytea,text,text),bloc.owner_credentials(),bloc.code_usable(text,bytea),bloc.authenticate_session(bytea,bigint,bytea,bytea,bytea),bloc.authorize_session(bytea),bloc.sign_out(bytea),bloc.replace_password(bytea,bigint,text,boolean),bloc.reserve_admission(text[],bytea[],integer[]),bloc.form_state(bytea,bytea,bytea),bloc.record_denial(text,text) TO bloc_runtime;
GRANT EXECUTE ON FUNCTION bloc.maintain_access() TO bloc_maintenance;
