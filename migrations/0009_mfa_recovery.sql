-- Recovery conveys replacement authority, never an ordinary account session.
ALTER TABLE bloc.realm_mfa_recovery_link ADD COLUMN policy_version bigint NOT NULL DEFAULT 1;
ALTER TABLE bloc.realm_mfa_flow ADD COLUMN recovery_link_digest bytea CHECK(recovery_link_digest IS NULL OR octet_length(recovery_link_digest)=32);
CREATE TABLE bloc.realm_mfa_recovery_form (
 realm_id uuid NOT NULL,user_id uuid NOT NULL,link_digest bytea NOT NULL CHECK(octet_length(link_digest)=32),browser_digest bytea PRIMARY KEY CHECK(octet_length(browser_digest)=32),csrf_token bytea NOT NULL CHECK(octet_length(csrf_token)=32),
 credential_version bigint NOT NULL,user_version bigint NOT NULL,policy_version bigint NOT NULL,factor_epoch bigint NOT NULL,created_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,failed_attempts smallint NOT NULL DEFAULT 0 CHECK(failed_attempts BETWEEN 0 AND 5),
 FOREIGN KEY(realm_id,user_id) REFERENCES bloc.realm_user(realm_id,id),CHECK(expires_at>created_at AND expires_at<=created_at+interval '30 minutes')
);
CREATE INDEX mfa_recovery_form_owner ON bloc.realm_mfa_recovery_form(realm_id,user_id);
CREATE TABLE bloc.realm_mfa_recovery_issue_bucket(realm_id uuid NOT NULL,user_id uuid NOT NULL,issued_at timestamptz[] NOT NULL,expires_at timestamptz NOT NULL,PRIMARY KEY(realm_id,user_id),FOREIGN KEY(realm_id,user_id) REFERENCES bloc.realm_user(realm_id,id));
REVOKE ALL ON bloc.realm_mfa_recovery_form,bloc.realm_mfa_recovery_issue_bucket FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
CREATE OR REPLACE FUNCTION bloc.mfa_flow_capacity(r uuid,u uuid,parent boolean) RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
 SELECT (NOT parent OR (SELECT count(*) FROM bloc.realm_mfa_flow WHERE realm_id=r AND user_id=u AND parent_id IS NULL AND consumed_at IS NULL AND expires_at>clock_timestamp())+(SELECT count(*) FROM bloc.realm_mfa_recovery_form WHERE realm_id=r AND user_id=u AND expires_at>clock_timestamp())<5)
 AND (SELECT count(*) FROM bloc.realm_mfa_flow WHERE realm_id=r)+(SELECT count(*) FROM bloc.realm_mfa_recovery_form WHERE realm_id=r)<1000 AND (SELECT count(*) FROM bloc.realm_mfa_flow)+(SELECT count(*) FROM bloc.realm_mfa_recovery_form)<10000;
$$;
CREATE FUNCTION bloc.mfa_code_material(r uuid,bearer bytea,browser bytea,token bytea) RETURNS TABLE(user_id text,generation_id text) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;f bloc.realm_mfa_flow;
BEGIN
 SELECT * INTO snapshot FROM bloc.mfa_flow_snapshot(r,bearer,browser,token);IF snapshot.status<>'ok' THEN RETURN;END IF;f:=snapshot.authority;
 IF f.purpose NOT IN('login','reauthenticate') OR NOT EXISTS(SELECT FROM bloc.realm_authentication_settings WHERE realm_id=r AND mfa_mode<>'disabled' AND mfa_recovery_codes_enabled) THEN RETURN;END IF;
 RETURN QUERY SELECT f.user_id::text,g.id::text FROM bloc.realm_mfa_recovery_generation g WHERE g.realm_id=r AND g.user_id=f.user_id AND g.invalidated_at IS NULL AND g.acknowledged_at IS NOT NULL;
END $$;
CREATE FUNCTION bloc.mfa_code_recover(r uuid,bearer bytea,browser bytea,token bytea,generation uuid,digest bytea,new_bearer bytea,new_csrf bytea) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;f bloc.realm_mfa_flow;checked timestamptz;p bloc.realm_authentication_settings;
BEGIN
 SELECT * INTO snapshot FROM bloc.mfa_flow_snapshot(r,bearer,browser,token);IF snapshot.status<>'ok' THEN RETURN snapshot.status;END IF;f:=snapshot.authority;checked:=clock_timestamp();
 SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;
 IF f.purpose NOT IN('login','reauthenticate') OR p.mfa_mode='disabled' OR NOT p.mfa_recovery_codes_enabled THEN RETURN 'stale';END IF;
 UPDATE bloc.realm_mfa_recovery_code c SET consumed_at=checked WHERE c.generation_id=generation AND c.code_digest=digest AND c.consumed_at IS NULL AND EXISTS(SELECT FROM bloc.realm_mfa_recovery_generation g WHERE g.id=c.generation_id AND g.realm_id=r AND g.user_id=f.user_id AND g.invalidated_at IS NULL AND g.acknowledged_at IS NOT NULL);
 IF NOT FOUND THEN RETURN bloc.mfa_reject(f.id);END IF;
 UPDATE bloc.realm_mfa_flow SET consumed_at=coalesce(consumed_at,checked) WHERE realm_id=r AND user_id=f.user_id;
 UPDATE bloc.realm_user_session SET revoked_at=checked WHERE realm_id=r AND user_id=f.user_id AND revoked_at IS NULL;
 DELETE FROM bloc.realm_form_state WHERE session_id IN(SELECT id FROM bloc.realm_user_session WHERE realm_id=r AND user_id=f.user_id);
 IF NOT bloc.mfa_flow_capacity(r,f.user_id,true) THEN RAISE EXCEPTION 'capacity' USING ERRCODE='54000';END IF;
 INSERT INTO bloc.realm_mfa_flow(realm_id,user_id,bearer_digest,browser_digest,purpose,credential_version,factor_epoch,policy_version,user_version,password_verified_at,csrf_token,created_at,expires_at)
 VALUES(r,f.user_id,new_bearer,browser,'recovery',f.credential_version,f.factor_epoch,f.policy_version,f.user_version,f.password_verified_at,new_csrf,checked,least(f.expires_at,checked+make_interval(secs=>p.mfa_flow_ttl_seconds)));
 INSERT INTO bloc.security_audit_event(installation_id,action,outcome,realm_id,realm_user_id,actor_realm_id,actor_user_id) VALUES(1,'realm_mfa_code_consume','success',r,f.user_id,r,f.user_id);
 RETURN 'ok';
END $$;
CREATE FUNCTION bloc.mfa_assisted_issue(r uuid,u uuid,session bytea,browser bytea,token bytea,expected bigint,admin_version bigint,confirmed boolean,digest bytea) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE checked timestamptz;aid uuid;profile bloc.realm_user;p bloc.realm_authentication_settings;v bigint;epoch bigint;events timestamptz[];old_digest bytea;
BEGIN
 checked:=bloc.realm_lock();aid:=bloc.directory_authority(session);
 IF token IS NULL OR bloc.form_state(browser,session,NULL) IS DISTINCT FROM token THEN RETURN 'csrf';END IF;
 IF NOT EXISTS(SELECT FROM bloc.installation_administrator WHERE id=aid AND credential_version=admin_version) THEN RETURN 'stale';END IF;
 SELECT * INTO profile FROM bloc.realm_user WHERE realm_id=r AND id=u;SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;
 IF profile.id IS NULL THEN RETURN 'missing';END IF;
 IF NOT confirmed THEN RETURN 'invalid';END IF;
 IF profile.version<>expected OR profile.status<>'active' OR NOT EXISTS(SELECT FROM bloc.realm WHERE id=r AND status='active') OR p.mfa_mode='disabled' OR NOT p.mfa_admin_recovery_enabled THEN RETURN 'stale';END IF;
 SELECT credential_version INTO v FROM bloc.realm_user_credential WHERE realm_id=r AND user_id=u;IF v IS NULL THEN RETURN 'stale';END IF;
 SELECT factor_epoch INTO epoch FROM bloc.realm_user_mfa_state WHERE realm_id=r AND user_id=u;
 SELECT coalesce(array_agg(t ORDER BY t),ARRAY[]::timestamptz[]) INTO events FROM bloc.realm_mfa_recovery_issue_bucket b CROSS JOIN LATERAL unnest(b.issued_at)t WHERE b.realm_id=r AND b.user_id=u AND t>checked-interval '1 hour';IF cardinality(events)>=3 THEN RETURN 'limited';END IF;
 SELECT token_digest INTO old_digest FROM bloc.realm_mfa_recovery_link WHERE realm_id=r AND user_id=u;
 DELETE FROM bloc.realm_mfa_recovery_form WHERE realm_id=r AND user_id=u;
 UPDATE bloc.realm_mfa_flow SET consumed_at=coalesce(consumed_at,checked) WHERE realm_id=r AND user_id=u AND (recovery_link_digest=old_digest OR parent_id IN(SELECT id FROM bloc.realm_mfa_flow WHERE realm_id=r AND user_id=u AND recovery_link_digest=old_digest));
 INSERT INTO bloc.realm_mfa_recovery_link(realm_id,user_id,token_digest,issued_by,credential_version,user_version,factor_epoch,issued_at,expires_at,consumed_at,policy_version) VALUES(r,u,digest,aid,v,profile.version,epoch,checked,checked+make_interval(secs=>p.mfa_admin_recovery_ttl_seconds),NULL,p.version) ON CONFLICT(realm_id,user_id) DO UPDATE SET token_digest=EXCLUDED.token_digest,issued_by=EXCLUDED.issued_by,credential_version=EXCLUDED.credential_version,user_version=EXCLUDED.user_version,factor_epoch=EXCLUDED.factor_epoch,issued_at=EXCLUDED.issued_at,expires_at=EXCLUDED.expires_at,consumed_at=NULL,policy_version=EXCLUDED.policy_version;
 INSERT INTO bloc.realm_mfa_recovery_issue_bucket VALUES(r,u,array_append(events,checked),checked+interval '1 hour') ON CONFLICT(realm_id,user_id) DO UPDATE SET issued_at=EXCLUDED.issued_at,expires_at=EXCLUDED.expires_at;
 INSERT INTO bloc.security_audit_event(installation_id,administrator_id,action,outcome,realm_id,realm_user_id) VALUES(1,aid,'realm_mfa_assisted_issue','success',r,u);
 RETURN to_char((checked+make_interval(secs=>p.mfa_admin_recovery_ttl_seconds)) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"');
END $$;
CREATE FUNCTION bloc.mfa_assisted_exchange(r uuid,anonymous bytea,token bytea,digest bytea,browser bytea,new_csrf bytea) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE l bloc.realm_mfa_recovery_link;checked timestamptz;p bloc.realm_authentication_settings;
BEGIN
 checked:=bloc.realm_lock();IF NOT coalesce(bloc.realm_form_valid(r,'anonymous',anonymous,token,NULL,NULL),false) THEN RETURN 'csrf';END IF;
 SELECT * INTO l FROM bloc.realm_mfa_recovery_link WHERE realm_id=r AND token_digest=digest;
 SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;
 IF l.user_id IS NULL OR l.consumed_at IS NOT NULL OR l.expires_at<=checked OR l.policy_version<>p.version OR p.mfa_mode='disabled' OR NOT p.mfa_admin_recovery_enabled OR NOT EXISTS(SELECT FROM bloc.realm_user u JOIN bloc.realm_user_credential c ON c.realm_id=u.realm_id AND c.user_id=u.id JOIN bloc.realm_user_mfa_state m ON m.realm_id=u.realm_id AND m.user_id=u.id JOIN bloc.realm t ON t.id=u.realm_id WHERE u.realm_id=r AND u.id=l.user_id AND u.status='active' AND t.status='active' AND u.version=l.user_version AND c.credential_version=l.credential_version AND m.factor_epoch=l.factor_epoch) THEN RETURN 'link';END IF;
 IF NOT bloc.mfa_flow_capacity(r,l.user_id,true) THEN RAISE EXCEPTION 'capacity' USING ERRCODE='54000';END IF;
 INSERT INTO bloc.realm_mfa_recovery_form VALUES(r,l.user_id,digest,browser,new_csrf,l.credential_version,l.user_version,p.version,l.factor_epoch,checked,least(l.expires_at,checked+interval '30 minutes'),0);
 RETURN 'ok';
END $$;
CREATE FUNCTION bloc.mfa_assisted_form(r uuid,browser bytea,token bytea) RETURNS TABLE(status text,user_id text,phc text,credential_version bigint,csrf bytea) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE f bloc.realm_mfa_recovery_form;checked timestamptz;
BEGIN
 checked:=bloc.realm_lock();SELECT * INTO f FROM bloc.realm_mfa_recovery_form WHERE realm_id=r AND browser_digest=browser;
 IF f.user_id IS NULL OR f.expires_at<=checked THEN status:='expired';RETURN NEXT;RETURN;END IF;
 IF token IS NOT NULL AND f.csrf_token IS DISTINCT FROM token THEN status:='csrf';RETURN NEXT;RETURN;END IF;
 IF f.failed_attempts>=5 THEN status:='limited';RETURN NEXT;RETURN;END IF;
 IF NOT EXISTS(SELECT FROM bloc.realm_mfa_recovery_link l JOIN bloc.realm_user u ON u.realm_id=l.realm_id AND u.id=l.user_id JOIN bloc.realm_user_credential c ON c.realm_id=u.realm_id AND c.user_id=u.id JOIN bloc.realm_user_mfa_state m ON m.realm_id=u.realm_id AND m.user_id=u.id JOIN bloc.realm_authentication_settings p ON p.realm_id=u.realm_id JOIN bloc.realm t ON t.id=u.realm_id WHERE l.realm_id=r AND l.user_id=f.user_id AND l.token_digest=f.link_digest AND l.consumed_at IS NULL AND l.expires_at>checked AND u.status='active' AND t.status='active' AND u.version=f.user_version AND c.credential_version=f.credential_version AND m.factor_epoch=f.factor_epoch AND p.version=f.policy_version AND p.mfa_mode<>'disabled' AND p.mfa_admin_recovery_enabled) THEN status:='stale';RETURN NEXT;RETURN;END IF;
 status:='ok';user_id:=f.user_id::text;credential_version:=f.credential_version;csrf:=f.csrf_token;SELECT password_hash INTO phc FROM bloc.realm_user_credential c WHERE c.realm_id=r AND c.user_id=f.user_id;RETURN NEXT;
END $$;
CREATE FUNCTION bloc.mfa_assisted_confirm(r uuid,browser bytea,token bytea,expected bigint,verified boolean,new_bearer bytea,new_csrf bytea) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;f bloc.realm_mfa_recovery_form;p bloc.realm_authentication_settings;checked timestamptz;n integer;
BEGIN
 SELECT * INTO snapshot FROM bloc.mfa_assisted_form(r,browser,token);IF snapshot.status<>'ok' THEN RETURN snapshot.status;END IF;
 SELECT * INTO f FROM bloc.realm_mfa_recovery_form WHERE realm_id=r AND browser_digest=browser;checked:=clock_timestamp();
 IF f.credential_version<>expected THEN RETURN 'stale';END IF;
 IF NOT verified THEN UPDATE bloc.realm_mfa_recovery_form SET failed_attempts=failed_attempts+1 WHERE browser_digest=browser RETURNING failed_attempts INTO n;RETURN CASE WHEN n>=5 THEN 'limited' ELSE 'invalid' END;END IF;
 SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;
 UPDATE bloc.realm_mfa_recovery_link SET consumed_at=checked WHERE realm_id=r AND user_id=f.user_id AND token_digest=f.link_digest AND consumed_at IS NULL AND expires_at>checked;IF NOT FOUND THEN RETURN 'stale';END IF;
 UPDATE bloc.realm_mfa_flow SET consumed_at=coalesce(consumed_at,checked) WHERE realm_id=r AND user_id=f.user_id;
 UPDATE bloc.realm_user_session SET revoked_at=checked WHERE realm_id=r AND user_id=f.user_id AND revoked_at IS NULL;
 DELETE FROM bloc.realm_form_state WHERE session_id IN(SELECT id FROM bloc.realm_user_session WHERE realm_id=r AND user_id=f.user_id);
 DELETE FROM bloc.realm_mfa_recovery_form WHERE realm_id=r AND user_id=f.user_id;
 IF NOT bloc.mfa_flow_capacity(r,f.user_id,true) THEN RAISE EXCEPTION 'capacity' USING ERRCODE='54000';END IF;
 INSERT INTO bloc.realm_mfa_flow(realm_id,user_id,bearer_digest,browser_digest,purpose,credential_version,factor_epoch,policy_version,user_version,password_verified_at,csrf_token,created_at,expires_at,recovery_link_digest)
 VALUES(r,f.user_id,new_bearer,browser,'recovery',f.credential_version,f.factor_epoch,f.policy_version,f.user_version,checked,new_csrf,checked,least(f.expires_at,checked+make_interval(secs=>p.mfa_flow_ttl_seconds)),f.link_digest);
 INSERT INTO bloc.security_audit_event(installation_id,action,outcome,realm_id,realm_user_id,actor_realm_id,actor_user_id) VALUES(1,'realm_mfa_assisted_consume','success',r,f.user_id,r,f.user_id);RETURN 'ok';
END $$;
ALTER FUNCTION bloc.mfa_flow_snapshot(uuid,bytea,bytea,bytea) RENAME TO mfa_flow_snapshot_pre_recovery;
CREATE FUNCTION bloc.mfa_flow_snapshot(r uuid,bearer bytea,browser bytea,token bytea) RETURNS TABLE(status text,authority bloc.realm_mfa_flow,now_seconds bigint,installation_id text) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;link_digest bytea;
BEGIN
 SELECT * INTO snapshot FROM bloc.mfa_flow_snapshot_pre_recovery(r,bearer,browser,token);
 status:=snapshot.status;authority:=snapshot.authority;now_seconds:=snapshot.now_seconds;installation_id:=snapshot.installation_id;
 IF status IN('stale','consumed') AND EXISTS(SELECT FROM bloc.realm_mfa_flow f JOIN bloc.realm_user u ON u.realm_id=f.realm_id AND u.id=f.user_id JOIN bloc.realm t ON t.id=f.realm_id WHERE f.realm_id=r AND f.bearer_digest=bearer AND f.browser_digest=browser AND (u.status<>'active' OR t.status<>'active')) THEN status:='missing';END IF;
 IF status='ok' THEN
  link_digest:=authority.recovery_link_digest;
  IF link_digest IS NULL AND authority.parent_id IS NOT NULL THEN SELECT recovery_link_digest INTO link_digest FROM bloc.realm_mfa_flow WHERE id=authority.parent_id;END IF;
  IF link_digest IS NOT NULL AND NOT EXISTS(SELECT FROM bloc.realm_mfa_recovery_link l WHERE l.realm_id=r AND l.user_id=authority.user_id AND l.token_digest=link_digest AND l.consumed_at IS NOT NULL AND l.expires_at>clock_timestamp()) THEN status:='stale';authority:=NULL;END IF;
 END IF;RETURN NEXT;
END $$;
CREATE OR REPLACE FUNCTION bloc.maintain_access() RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE total integer:=0;n integer;
BEGIN
 PERFORM id FROM bloc.installation WHERE id=1 FOR UPDATE;
 DELETE FROM bloc.realm_mfa_recovery_form WHERE browser_digest IN(SELECT f.browser_digest FROM bloc.realm_mfa_recovery_form f WHERE f.expires_at<=clock_timestamp() OR NOT EXISTS(SELECT FROM bloc.realm_mfa_recovery_link l WHERE l.realm_id=f.realm_id AND l.user_id=f.user_id AND l.token_digest=f.link_digest AND l.consumed_at IS NULL) LIMIT 1000);GET DIAGNOSTICS n=ROW_COUNT;total:=total+n;
 DELETE FROM bloc.realm_mfa_flow WHERE id IN(SELECT q.id FROM bloc.realm_mfa_flow q WHERE (q.expires_at<=clock_timestamp() OR q.consumed_at IS NOT NULL) AND NOT EXISTS(SELECT FROM bloc.realm_mfa_flow child WHERE child.parent_id=q.id) LIMIT 1000);GET DIAGNOSTICS n=ROW_COUNT;total:=total+n;
 DELETE FROM bloc.mfa_encrypted_payload p WHERE p.id IN(SELECT id FROM bloc.mfa_encrypted_payload q WHERE q.purpose IN(2,3) AND NOT EXISTS(SELECT FROM bloc.realm_mfa_flow f WHERE f.payload_id=q.id) LIMIT 1000);GET DIAGNOSTICS n=ROW_COUNT;total:=total+n;
 DELETE FROM bloc.realm_mfa_recovery_link WHERE (realm_id,user_id) IN(SELECT l.realm_id,l.user_id FROM bloc.realm_mfa_recovery_link l WHERE (l.expires_at<=clock_timestamp() OR l.consumed_at IS NOT NULL) AND NOT EXISTS(SELECT FROM bloc.realm_mfa_flow f WHERE f.recovery_link_digest=l.token_digest AND f.consumed_at IS NULL AND f.expires_at>clock_timestamp()) AND NOT EXISTS(SELECT FROM bloc.realm_mfa_recovery_form f WHERE f.link_digest=l.token_digest) LIMIT 1000);GET DIAGNOSTICS n=ROW_COUNT;total:=total+n;
 DELETE FROM bloc.realm_mfa_recovery_issue_bucket WHERE (realm_id,user_id) IN(SELECT realm_id,user_id FROM bloc.realm_mfa_recovery_issue_bucket WHERE expires_at<=clock_timestamp() LIMIT 1000);GET DIAGNOSTICS n=ROW_COUNT;total:=total+n;
 DELETE FROM bloc.mfa_admission_bucket WHERE (scope,subject_digest) IN(SELECT scope,subject_digest FROM bloc.mfa_admission_bucket WHERE expires_at<=clock_timestamp() LIMIT 1000);GET DIAGNOSTICS n=ROW_COUNT;total:=total+n;
 RETURN total+bloc.maintain_pre_mfa_access();
END $$;

CREATE FUNCTION bloc.mfa_reserve_proof(r uuid,u uuid,source_key bytea) RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;f bloc.realm_mfa_flow;checked timestamptz;scope_name text;subject bytea;window_seconds integer;maximum integer;events timestamptz[];oldest timestamptz;new_keys integer:=0;
BEGIN
 PERFORM bloc.realm_lock();checked:=clock_timestamp();

 IF octet_length(source_key)<>32 THEN RETURN -2;END IF;
 FOR scope_name IN SELECT unnest(ARRAY['account','source','realm']) LOOP
  subject:=CASE scope_name WHEN 'account' THEN sha256(uuid_send(r)||uuid_send(u)) WHEN 'realm' THEN sha256(uuid_send(r)) ELSE source_key END;
  window_seconds:=CASE scope_name WHEN 'account' THEN 600 ELSE 60 END;maximum:=CASE scope_name WHEN 'account' THEN 10 WHEN 'source' THEN 30 ELSE 300 END;
  SELECT array_agg(event ORDER BY event) INTO events FROM bloc.mfa_admission_bucket b CROSS JOIN LATERAL unnest(b.admitted_at) event WHERE b.scope=scope_name AND b.subject_digest=subject AND event>checked-make_interval(secs=>window_seconds);
  IF NOT EXISTS(SELECT FROM bloc.mfa_admission_bucket b WHERE b.scope=scope_name AND b.subject_digest=subject) THEN new_keys:=new_keys+1;END IF;
  IF coalesce(cardinality(events),0)>=maximum THEN RETURN greatest(1,ceil(extract(epoch FROM events[1]+make_interval(secs=>window_seconds)-checked))::integer);END IF;
 END LOOP;
 IF (SELECT count(*) FROM bloc.mfa_admission_bucket)+new_keys>10000 THEN RETURN -1;END IF;
 FOR scope_name IN SELECT unnest(ARRAY['account','source','realm']) LOOP
  subject:=CASE scope_name WHEN 'account' THEN sha256(uuid_send(r)||uuid_send(u)) WHEN 'realm' THEN sha256(uuid_send(r)) ELSE source_key END;
  window_seconds:=CASE scope_name WHEN 'account' THEN 600 ELSE 60 END;
  SELECT coalesce(array_agg(event ORDER BY event),ARRAY[]::timestamptz[]) INTO events FROM bloc.mfa_admission_bucket b CROSS JOIN LATERAL unnest(b.admitted_at) event WHERE b.scope=scope_name AND b.subject_digest=subject AND event>checked-make_interval(secs=>window_seconds);
  INSERT INTO bloc.mfa_admission_bucket VALUES(scope_name,subject,array_append(events,checked),checked+make_interval(secs=>window_seconds)) ON CONFLICT(scope,subject_digest) DO UPDATE SET admitted_at=EXCLUDED.admitted_at,expires_at=EXCLUDED.expires_at;
 END LOOP;RETURN 0;
END $$;

CREATE OR REPLACE FUNCTION bloc.mfa_admit(r uuid,bearer bytea,browser bytea,token bytea,source_key bytea) RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;f bloc.realm_mfa_flow;
BEGIN SELECT * INTO snapshot FROM bloc.mfa_flow_snapshot(r,bearer,browser,token);IF snapshot.status<>'ok' THEN RETURN -2;END IF;f:=snapshot.authority;IF f.failed_attempts>=5 THEN RETURN 60;END IF;RETURN bloc.mfa_reserve_proof(r,f.user_id,source_key);END $$;
CREATE FUNCTION bloc.mfa_assisted_admit(r uuid,browser bytea,token bytea,source_key bytea) RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;
BEGIN SELECT * INTO snapshot FROM bloc.mfa_assisted_form(r,browser,token);IF snapshot.status='limited' THEN RETURN 60;END IF;IF snapshot.status<>'ok' THEN RETURN -2;END IF;RETURN bloc.mfa_reserve_proof(r,snapshot.user_id::uuid,source_key);END $$;
ALTER FUNCTION bloc.realm_invalidate(uuid,uuid) RENAME TO realm_invalidate_pre_mfa_recovery;
CREATE FUNCTION bloc.realm_invalidate(r uuid,u uuid) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
BEGIN
 PERFORM bloc.realm_invalidate_pre_mfa_recovery(r,u);
 UPDATE bloc.realm_mfa_flow SET consumed_at=coalesce(consumed_at,clock_timestamp()) WHERE realm_id=r AND (u IS NULL OR user_id=u);
 DELETE FROM bloc.realm_mfa_recovery_form WHERE realm_id=r AND (u IS NULL OR user_id=u);
 DELETE FROM bloc.realm_mfa_recovery_link WHERE realm_id=r AND (u IS NULL OR user_id=u);
END $$;
ALTER FUNCTION bloc.realm_commit(uuid,text,bytea,bytea,bytea,bytea,uuid,bigint,bigint,text[],bytea,bytea,bytea) RENAME TO realm_commit_pre_mfa_recovery;
CREATE FUNCTION bloc.realm_commit(r uuid,operation text,session bytea,browser bytea,token bytea,link bytea,target uuid,expected bigint,policy bigint,values_text text[],new_session bytea,new_browser bytea,new_token bytea) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE s bloc.realm_user_session;p bloc.realm_authentication_settings;f bloc.realm_mfa_flow;v bigint;checked timestamptz;sid uuid;
BEGIN
 IF operation<>'password' THEN RETURN bloc.realm_commit_pre_mfa_recovery(r,operation,session,browser,token,link,target,expected,policy,values_text,new_session,new_browser,new_token);END IF;
 checked:=bloc.realm_lock();s:=bloc.realm_session(r,session,false);IF s.id IS NULL THEN RETURN 'authority';END IF;
 IF NOT coalesce(bloc.realm_form_valid(r,'account',browser,token,session,NULL),false) THEN RETURN 'csrf';END IF;
 SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;
 IF s.credential_version<>expected THEN RETURN 'authority';END IF;IF p.version<>policy THEN RETURN 'policy';END IF;
 IF p.mfa_mode='disabled' OR NOT EXISTS(SELECT FROM bloc.realm_user_factor WHERE realm_id=r AND user_id=s.user_id AND revoked_at IS NULL) THEN RETURN bloc.realm_commit_pre_mfa_recovery(r,operation,session,browser,token,link,target,expected,policy,values_text,new_session,new_browser,new_token);END IF;
 f:=bloc.mfa_take_proof(r,session,browser,'password');IF f.id IS NULL THEN RETURN 'mfa_required';END IF;
 PERFORM bloc.realm_invalidate(r,s.user_id);
 UPDATE bloc.realm_user_credential SET password_hash=values_text[1],credential_version=credential_version+1,password_changed_at=checked WHERE realm_id=r AND user_id=s.user_id RETURNING credential_version INTO v;
 sid:=bloc.mfa_issue_session(r,s.user_id,v,s.factor_epoch,f.password_verified_at,f.verified_method,f.factor_id,new_session,new_browser,new_token,values_text[2]);
 UPDATE bloc.realm_user_session SET mfa_verified_at=f.proof_verified_at WHERE id=sid;
 INSERT INTO bloc.security_audit_event(installation_id,action,outcome,realm_id,realm_user_id,actor_realm_id,actor_user_id) VALUES(1,'realm_password_change','success',r,s.user_id,r,s.user_id);RETURN 'ok';
END $$;
-- Public entry points retain only their existing narrow roles.
REVOKE ALL ON FUNCTION bloc.mfa_flow_snapshot_pre_recovery(uuid,bytea,bytea,bytea),bloc.mfa_flow_snapshot(uuid,bytea,bytea,bytea),bloc.mfa_reserve_proof(uuid,uuid,bytea),bloc.realm_invalidate_pre_mfa_recovery(uuid,uuid),bloc.realm_invalidate(uuid,uuid),bloc.realm_commit_pre_mfa_recovery(uuid,text,bytea,bytea,bytea,bytea,uuid,bigint,bigint,text[],bytea,bytea,bytea),bloc.realm_commit(uuid,text,bytea,bytea,bytea,bytea,uuid,bigint,bigint,text[],bytea,bytea,bytea),bloc.mfa_code_material(uuid,bytea,bytea,bytea),bloc.mfa_code_recover(uuid,bytea,bytea,bytea,uuid,bytea,bytea,bytea),bloc.mfa_assisted_issue(uuid,uuid,bytea,bytea,bytea,bigint,bigint,boolean,bytea),bloc.mfa_assisted_exchange(uuid,bytea,bytea,bytea,bytea,bytea),bloc.mfa_assisted_form(uuid,bytea,bytea),bloc.mfa_assisted_admit(uuid,bytea,bytea,bytea),bloc.mfa_assisted_confirm(uuid,bytea,bytea,bigint,boolean,bytea,bytea) FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
GRANT EXECUTE ON FUNCTION bloc.mfa_flow_snapshot(uuid,bytea,bytea,bytea),bloc.realm_commit(uuid,text,bytea,bytea,bytea,bytea,uuid,bigint,bigint,text[],bytea,bytea,bytea),bloc.mfa_code_material(uuid,bytea,bytea,bytea),bloc.mfa_code_recover(uuid,bytea,bytea,bytea,uuid,bytea,bytea,bytea),bloc.mfa_assisted_issue(uuid,uuid,bytea,bytea,bytea,bigint,bigint,boolean,bytea),bloc.mfa_assisted_exchange(uuid,bytea,bytea,bytea,bytea,bytea),bloc.mfa_assisted_form(uuid,bytea,bytea),bloc.mfa_assisted_admit(uuid,bytea,bytea,bytea),bloc.mfa_assisted_confirm(uuid,bytea,bytea,bigint,boolean,bytea,bytea) TO bloc_runtime;
CREATE FUNCTION bloc.mfa_choices(r uuid,bearer bytea,browser bytea) RETURNS TABLE(totp boolean,webauthn boolean,saved_codes boolean,preferred text,active_count bigint,context text) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;f bloc.realm_mfa_flow;p bloc.realm_authentication_settings;
BEGIN
 SELECT * INTO snapshot FROM bloc.mfa_flow_snapshot(r,bearer,browser,NULL);IF snapshot.status<>'ok' THEN RETURN;END IF;f:=snapshot.authority;SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;
 context:=f.purpose;IF f.parent_id IS NOT NULL THEN SELECT parent.purpose INTO context FROM bloc.realm_mfa_flow parent WHERE parent.id=f.parent_id;END IF;
 SELECT count(*) INTO active_count FROM bloc.realm_user_factor WHERE realm_id=r AND user_id=f.user_id AND revoked_at IS NULL;
 totp:=p.mfa_mode<>'disabled' AND 'totp'=ANY(p.mfa_allowed_methods) AND EXISTS(SELECT FROM bloc.realm_user_factor WHERE realm_id=r AND user_id=f.user_id AND kind='totp' AND revoked_at IS NULL);
 webauthn:=p.mfa_mode<>'disabled' AND 'webauthn'=ANY(p.mfa_allowed_methods) AND EXISTS(SELECT FROM bloc.realm_user_factor WHERE realm_id=r AND user_id=f.user_id AND kind='webauthn' AND revoked_at IS NULL);
 saved_codes:=p.mfa_mode<>'disabled' AND p.mfa_recovery_codes_enabled AND EXISTS(SELECT FROM bloc.realm_mfa_recovery_generation g JOIN bloc.realm_mfa_recovery_code c ON c.generation_id=g.id WHERE g.realm_id=r AND g.user_id=f.user_id AND g.invalidated_at IS NULL AND g.acknowledged_at IS NOT NULL AND c.consumed_at IS NULL);
 SELECT fct.kind INTO preferred FROM bloc.realm_user_mfa_state m JOIN bloc.realm_user_factor fct ON fct.realm_id=m.realm_id AND fct.user_id=m.user_id AND fct.id=m.preferred_factor_id WHERE m.realm_id=r AND m.user_id=f.user_id AND fct.revoked_at IS NULL AND fct.kind=ANY(p.mfa_allowed_methods);
 preferred:=coalesce(preferred,CASE WHEN p.mfa_preferred_method='totp' AND totp OR p.mfa_preferred_method='webauthn' AND webauthn THEN p.mfa_preferred_method END,CASE WHEN webauthn THEN 'webauthn' WHEN totp THEN 'totp' END);RETURN NEXT;
END $$;
REVOKE ALL ON FUNCTION bloc.mfa_choices(uuid,bytea,bytea) FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;GRANT EXECUTE ON FUNCTION bloc.mfa_choices(uuid,bytea,bytea) TO bloc_runtime;
DO $$ DECLARE expression text;BEGIN
 SELECT pg_get_expr(conbin,conrelid) INTO expression FROM pg_constraint WHERE conrelid='bloc.realm_denial_aggregate'::regclass AND conname='realm_denial_aggregate_action_check';ALTER TABLE bloc.realm_denial_aggregate DROP CONSTRAINT realm_denial_aggregate_action_check;
 EXECUTE 'ALTER TABLE bloc.realm_denial_aggregate ADD CONSTRAINT realm_denial_aggregate_action_check CHECK ('||expression||' OR action IN (''mfa_proof'',''mfa_enrollment'',''mfa_recovery'',''mfa_account''))';
END $$;
CREATE OR REPLACE FUNCTION bloc.mfa_flow_cancel(r uuid,bearer bytea,browser bytea,token bytea) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;root uuid;
BEGIN
 SELECT * INTO snapshot FROM bloc.mfa_flow_snapshot(r,bearer,browser,token);IF snapshot.status<>'ok' THEN RETURN snapshot.status;END IF;
 root:=coalesce((snapshot.authority).parent_id,(snapshot.authority).id);
 UPDATE bloc.realm_mfa_flow SET consumed_at=coalesce(consumed_at,clock_timestamp()) WHERE id=root OR parent_id=root;RETURN 'ok';
END $$;

CREATE OR REPLACE FUNCTION bloc.mfa_restore_fence() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
BEGIN
 IF NOT OLD.recovery_required AND NEW.recovery_required THEN
  DELETE FROM bloc.realm_mfa_recovery_form;DELETE FROM bloc.realm_mfa_flow;DELETE FROM bloc.realm_mfa_recovery_link;
  UPDATE bloc.realm_mfa_recovery_generation SET invalidated_at=coalesce(invalidated_at,clock_timestamp());
  UPDATE bloc.realm_user_mfa_state SET factor_epoch=factor_epoch+1,updated_at=clock_timestamp();
 ELSIF OLD.recovery_required AND NOT NEW.recovery_required THEN
  UPDATE bloc.realm_totp_factor SET last_accepted_step=greatest(last_accepted_step,floor(extract(epoch FROM clock_timestamp())/30)::bigint+1);
 END IF;
 RETURN NEW;
END $$;
-- References to owned authority cannot cross a principal even accidentally.
ALTER TABLE bloc.realm_mfa_flow ADD CONSTRAINT mfa_flow_owned_id UNIQUE(realm_id,user_id,id);
ALTER TABLE bloc.realm_user_session ADD CONSTRAINT mfa_session_owned_id UNIQUE(realm_id,user_id,id);
ALTER TABLE bloc.realm_mfa_recovery_generation ADD CONSTRAINT mfa_generation_owned_id UNIQUE(realm_id,user_id,id);
ALTER TABLE bloc.realm_mfa_recovery_link ADD CONSTRAINT mfa_link_owned_digest UNIQUE(realm_id,user_id,token_digest);
ALTER TABLE bloc.realm_mfa_flow
 DROP CONSTRAINT realm_mfa_flow_parent_id_fkey,
 DROP CONSTRAINT realm_mfa_flow_session_id_fkey,
 DROP CONSTRAINT realm_mfa_flow_payload_id_fkey,
 DROP CONSTRAINT realm_mfa_flow_recovery_generation_id_fkey,
 ADD CONSTRAINT mfa_flow_owned_parent FOREIGN KEY(realm_id,user_id,parent_id) REFERENCES bloc.realm_mfa_flow(realm_id,user_id,id) ON DELETE CASCADE,
 ADD CONSTRAINT mfa_flow_owned_session FOREIGN KEY(realm_id,user_id,session_id) REFERENCES bloc.realm_user_session(realm_id,user_id,id) ON DELETE CASCADE,
 ADD CONSTRAINT mfa_flow_owned_payload FOREIGN KEY(realm_id,user_id,payload_id) REFERENCES bloc.mfa_encrypted_payload(realm_id,user_id,id),
 ADD CONSTRAINT mfa_flow_owned_generation FOREIGN KEY(realm_id,user_id,recovery_generation_id) REFERENCES bloc.realm_mfa_recovery_generation(realm_id,user_id,id);
ALTER TABLE bloc.realm_mfa_recovery_form ADD CONSTRAINT mfa_form_owned_link FOREIGN KEY(realm_id,user_id,link_digest) REFERENCES bloc.realm_mfa_recovery_link(realm_id,user_id,token_digest) ON DELETE CASCADE;

CREATE OR REPLACE FUNCTION bloc.realm_new_session(r uuid,u uuid,v bigint,digest bytea,browser bytea,token bytea,device text) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE checked timestamptz; p bloc.realm_authentication_settings; sid uuid;
BEGIN
 checked:=bloc.realm_lock(); SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;
 DELETE FROM bloc.realm_user_session WHERE id IN(SELECT expired.id FROM bloc.realm_user_session expired WHERE (expired.revoked_at IS NOT NULL OR expired.expires_at<=checked) AND NOT EXISTS(SELECT FROM bloc.realm_mfa_flow f WHERE f.session_id=expired.id) LIMIT 1000);
 IF (SELECT count(*) FROM bloc.realm_user_session)>=100000 THEN RAISE EXCEPTION 'capacity' USING ERRCODE='54000'; END IF;
 UPDATE bloc.realm_user_session SET revoked_at=checked WHERE id IN(SELECT id FROM bloc.realm_user_session WHERE realm_id=r AND user_id=u AND revoked_at IS NULL ORDER BY created_at DESC,id DESC OFFSET (p.session_limit-1));
 DELETE FROM bloc.realm_form_state f USING bloc.realm_user_session s WHERE f.session_id=s.id AND s.realm_id=r AND s.user_id=u AND s.revoked_at IS NOT NULL;
 INSERT INTO bloc.realm_user_session(realm_id,user_id,session_digest,credential_version,created_at,last_activity_at,expires_at,device_label) VALUES(r,u,digest,v,checked,checked,checked+make_interval(secs=>least(p.session_idle_seconds,p.session_absolute_seconds)),device) RETURNING id INTO sid;
 IF bloc.realm_form(r,'account',browser,digest,NULL,token) IS NULL THEN RAISE EXCEPTION 'form capacity' USING ERRCODE='54000'; END IF;
 RETURN sid;
END $$;

CREATE OR REPLACE FUNCTION bloc.maintain_pre_mfa_access() RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE total integer; n integer;
BEGIN
 PERFORM id FROM bloc.installation WHERE id=1 FOR UPDATE;
 total:=bloc.maintain_administrator_access();
 DELETE FROM bloc.realm_form_state WHERE browser_digest IN(SELECT f.browser_digest FROM bloc.realm_form_state f LEFT JOIN bloc.realm_user_access_link l ON l.token_digest=f.link_digest LEFT JOIN bloc.realm_user_session s ON s.id=f.session_id WHERE f.expires_at<=clock_timestamp() OR l.expires_at<=clock_timestamp() OR l.consumed_at IS NOT NULL OR s.revoked_at IS NOT NULL OR s.expires_at<=clock_timestamp() LIMIT 1000);
 DELETE FROM bloc.realm_user_access_link l WHERE token_digest IN(SELECT token_digest FROM bloc.realm_user_access_link WHERE expires_at<=clock_timestamp() OR consumed_at IS NOT NULL LIMIT 1000) AND NOT EXISTS(SELECT FROM bloc.realm_form_state f WHERE f.link_digest=l.token_digest);
 DELETE FROM bloc.realm_user_session s WHERE id IN(SELECT id FROM bloc.realm_user_session WHERE revoked_at IS NOT NULL OR expires_at<=clock_timestamp() LIMIT 1000) AND NOT EXISTS(SELECT FROM bloc.realm_form_state f WHERE f.session_id=s.id) AND NOT EXISTS(SELECT FROM bloc.realm_mfa_flow flow WHERE flow.session_id=s.id);
 DELETE FROM bloc.realm_admission_bucket WHERE (scope,subject_digest) IN(SELECT scope,subject_digest FROM bloc.realm_admission_bucket WHERE expires_at<=clock_timestamp() LIMIT 1000);
 DELETE FROM bloc.realm_denial_aggregate WHERE (minute,action,reason) IN(SELECT minute,action,reason FROM bloc.realm_denial_aggregate WHERE minute<clock_timestamp()-interval '7 days' LIMIT 1000); GET DIAGNOSTICS n=ROW_COUNT;
 RETURN total+n;
END $$;
