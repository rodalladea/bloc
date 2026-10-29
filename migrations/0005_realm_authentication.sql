-- Realm users remain independent of installation administrators. Only guarded
-- operations below may read or change authority; all locks precede database time.
CREATE TABLE bloc.realm_authentication_settings (
 realm_id uuid PRIMARY KEY REFERENCES bloc.realm,
 registration_enabled boolean NOT NULL DEFAULT false,
 password_min_length smallint NOT NULL DEFAULT 16 CHECK(password_min_length BETWEEN 16 AND 128),
 require_uppercase boolean NOT NULL DEFAULT false, require_lowercase boolean NOT NULL DEFAULT false,
 require_number boolean NOT NULL DEFAULT false, require_special boolean NOT NULL DEFAULT false,
 activation_ttl_seconds integer NOT NULL DEFAULT 86400 CHECK(activation_ttl_seconds BETWEEN 300 AND 604800),
 reset_ttl_seconds integer NOT NULL DEFAULT 1800 CHECK(reset_ttl_seconds BETWEEN 300 AND 86400),
 session_idle_seconds integer NOT NULL DEFAULT 1800 CHECK(session_idle_seconds BETWEEN 60 AND 86400),
 session_absolute_seconds integer NOT NULL DEFAULT 43200 CHECK(session_absolute_seconds BETWEEN 300 AND 2592000),
 session_limit smallint NOT NULL DEFAULT 10 CHECK(session_limit BETWEEN 1 AND 100),
 version bigint NOT NULL DEFAULT 1 CHECK(version>0), updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(session_idle_seconds<=session_absolute_seconds)
);
INSERT INTO bloc.realm_authentication_settings(realm_id) SELECT id FROM bloc.realm;
CREATE TABLE bloc.realm_user_credential (
 realm_id uuid NOT NULL, user_id uuid NOT NULL, password_hash text NOT NULL CHECK(octet_length(password_hash) BETWEEN 1 AND 1024),
 credential_version bigint NOT NULL DEFAULT 1 CHECK(credential_version>0), password_changed_at timestamptz NOT NULL,
 PRIMARY KEY(realm_id,user_id), FOREIGN KEY(realm_id,user_id) REFERENCES bloc.realm_user(realm_id,id)
);
CREATE TABLE bloc.realm_user_session (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), realm_id uuid NOT NULL, user_id uuid NOT NULL,
 session_digest bytea NOT NULL UNIQUE CHECK(octet_length(session_digest)=32), credential_version bigint NOT NULL CHECK(credential_version>0),
 created_at timestamptz NOT NULL, last_activity_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, revoked_at timestamptz,
 device_label text NOT NULL CHECK(char_length(device_label) BETWEEN 1 AND 128 AND octet_length(device_label)<=512 AND device_label !~ '[[:cntrl:]]'),
 FOREIGN KEY(realm_id,user_id) REFERENCES bloc.realm_user(realm_id,id)
);
CREATE INDEX realm_session_owner ON bloc.realm_user_session(realm_id,user_id,created_at,id);
CREATE INDEX realm_session_expiry ON bloc.realm_user_session(expires_at);
CREATE TABLE bloc.realm_user_access_link (
 realm_id uuid NOT NULL, user_id uuid NOT NULL, purpose text NOT NULL CHECK(purpose IN('activation','reset')),
 token_digest bytea NOT NULL UNIQUE CHECK(octet_length(token_digest)=32), credential_version bigint,
 user_version bigint NOT NULL CHECK(user_version>0), issued_by uuid NOT NULL REFERENCES bloc.installation_administrator,
 issued_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, consumed_at timestamptz,
 PRIMARY KEY(realm_id,user_id,purpose), FOREIGN KEY(realm_id,user_id) REFERENCES bloc.realm_user(realm_id,id),
 CHECK((purpose='activation' AND credential_version IS NULL) OR (purpose='reset' AND credential_version>0))
);
CREATE INDEX realm_link_expiry ON bloc.realm_user_access_link(expires_at);
CREATE TABLE bloc.realm_form_state (
 browser_digest bytea PRIMARY KEY CHECK(octet_length(browser_digest)=32), realm_id uuid NOT NULL REFERENCES bloc.realm,
 purpose text NOT NULL CHECK(purpose IN('anonymous','account','activation','reset')),
 session_id uuid REFERENCES bloc.realm_user_session ON DELETE CASCADE,
 link_digest bytea REFERENCES bloc.realm_user_access_link(token_digest),
 csrf_token bytea NOT NULL CHECK(octet_length(csrf_token)=32), created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 CHECK((purpose='anonymous' AND session_id IS NULL AND link_digest IS NULL) OR (purpose='account' AND session_id IS NOT NULL AND link_digest IS NULL) OR (purpose IN('activation','reset') AND session_id IS NULL AND link_digest IS NOT NULL)),
 CHECK(expires_at<=created_at+interval '30 minutes')
);
CREATE INDEX realm_form_expiry ON bloc.realm_form_state(expires_at);
CREATE INDEX realm_form_session ON bloc.realm_form_state(session_id);
CREATE INDEX realm_form_link ON bloc.realm_form_state(link_digest);
CREATE TABLE bloc.realm_admission_bucket (
 scope text NOT NULL CHECK(scope IN('form_source','credential_source','login_identifier','registration_realm','registration_identifier','exchange_source','exchange_realm','link','password_change','link_issue','public_work','account_mutation')),
 subject_digest bytea NOT NULL CHECK(octet_length(subject_digest)=32), admitted_at timestamptz[] NOT NULL CHECK(cardinality(admitted_at)<=30), expires_at timestamptz NOT NULL,
 PRIMARY KEY(scope,subject_digest)
);
CREATE TABLE bloc.realm_denial_aggregate (
 minute timestamptz NOT NULL,
 action text NOT NULL CHECK(action IN('form_issue','registration','sign_in','sign_out','link_exchange','link_issue','activation','reset','profile','password_change','session_revoke','settings')),
 reason text NOT NULL CHECK(reason IN('origin','csrf','malformed','oversized','media_type','admission','capacity','authority','credentials','conflict','storage')),
 count bigint NOT NULL CHECK(count>=0), PRIMARY KEY(minute,action,reason)
);
ALTER TABLE bloc.security_audit_event ADD COLUMN actor_realm_id uuid, ADD COLUMN actor_user_id uuid,
 ADD CONSTRAINT realm_actor_pair CHECK((actor_realm_id IS NULL AND actor_user_id IS NULL) OR (actor_realm_id IS NOT NULL AND actor_user_id IS NOT NULL AND administrator_id IS NULL)),
 ADD CONSTRAINT realm_actor_fk FOREIGN KEY(actor_realm_id,actor_user_id) REFERENCES bloc.realm_user(realm_id,id);
ALTER TABLE bloc.security_audit_event DROP CONSTRAINT security_audit_event_action_check;
ALTER TABLE bloc.security_audit_event ADD CONSTRAINT security_audit_event_action_check CHECK(action IN('code_issue','setup','sign_in','sign_out','password_change','recovery','restore','tenant_create','tenant_update','tenant_suspend','tenant_reactivate','realm_create','realm_update','realm_suspend','realm_reactivate','tenant_user_create','tenant_user_update','tenant_user_suspend','tenant_user_reactivate','realm_user_create','realm_user_update','realm_user_suspend','realm_user_reactivate','realm_authentication_update','realm_registration','realm_activation_link_issue','realm_reset_link_issue','realm_activation','realm_password_reset','realm_sign_in','realm_sign_out','realm_profile_update','realm_password_change','realm_session_revoke'));
ALTER TABLE bloc.security_audit_event DROP CONSTRAINT directory_target;
ALTER TABLE bloc.security_audit_event ADD CONSTRAINT directory_target CHECK(
 (action IN('tenant_create','tenant_update','tenant_suspend','tenant_reactivate','realm_create','realm_update','realm_suspend','realm_reactivate','realm_authentication_update') AND realm_id IS NOT NULL AND realm_user_id IS NULL)
 OR (action IN('tenant_user_create','tenant_user_update','tenant_user_suspend','tenant_user_reactivate','realm_user_create','realm_user_update','realm_user_suspend','realm_user_reactivate','realm_registration','realm_activation_link_issue','realm_reset_link_issue','realm_activation','realm_password_reset','realm_sign_in','realm_sign_out','realm_profile_update','realm_password_change','realm_session_revoke') AND realm_id IS NOT NULL AND realm_user_id IS NOT NULL)
 OR (action NOT LIKE 'realm%' AND action NOT LIKE 'tenant%' AND realm_id IS NULL AND realm_user_id IS NULL));
CREATE FUNCTION bloc.realm_lock() RETURNS timestamptz LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
BEGIN
 PERFORM id FROM bloc.installation WHERE id=1 FOR UPDATE;
 IF (SELECT recovery_required FROM bloc.installation WHERE id=1) THEN RAISE EXCEPTION 'authority unavailable' USING ERRCODE='55000'; END IF;
 RETURN clock_timestamp();
END $$;
CREATE FUNCTION bloc.realm_invalidate(r uuid,u uuid) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
BEGIN
 DELETE FROM bloc.realm_form_state f WHERE f.realm_id=r AND (u IS NULL OR f.session_id IN(SELECT id FROM bloc.realm_user_session WHERE realm_id=r AND user_id=u) OR f.link_digest IN(SELECT token_digest FROM bloc.realm_user_access_link WHERE realm_id=r AND user_id=u));
 UPDATE bloc.realm_user_session SET revoked_at=clock_timestamp() WHERE realm_id=r AND (u IS NULL OR user_id=u) AND revoked_at IS NULL;
 DELETE FROM bloc.realm_user_access_link WHERE realm_id=r AND (u IS NULL OR user_id=u);
END $$;
CREATE FUNCTION bloc.realm_directory_change() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
BEGIN
 IF TG_TABLE_NAME='realm' THEN
  IF TG_OP='INSERT' THEN INSERT INTO bloc.realm_authentication_settings(realm_id) VALUES(NEW.id);
  ELSIF NEW.status='suspended' AND OLD.status<>NEW.status THEN PERFORM bloc.realm_invalidate(NEW.id,NULL); END IF;
 ELSIF NEW.email<>OLD.email OR (NEW.status='suspended' AND OLD.status<>NEW.status) THEN PERFORM bloc.realm_invalidate(NEW.realm_id,NEW.id);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER realm_authentication_seed AFTER INSERT OR UPDATE ON bloc.realm FOR EACH ROW EXECUTE FUNCTION bloc.realm_directory_change();
CREATE TRIGGER realm_user_authority_change AFTER UPDATE ON bloc.realm_user FOR EACH ROW EXECUTE FUNCTION bloc.realm_directory_change();
CREATE FUNCTION bloc.realm_settings(r uuid, admin_digest bytea) RETURNS SETOF bloc.realm_authentication_settings LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
BEGIN
 PERFORM bloc.realm_lock();
 IF admin_digest IS NOT NULL THEN PERFORM bloc.directory_authority(admin_digest);
 ELSIF NOT EXISTS(SELECT FROM bloc.realm WHERE id=r AND status='active') THEN RETURN; END IF;
 RETURN QUERY SELECT * FROM bloc.realm_authentication_settings WHERE realm_id=r;
END $$;
CREATE FUNCTION bloc.realm_public_name(r uuid) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
BEGIN
 PERFORM bloc.realm_lock();
 RETURN (SELECT name FROM bloc.realm WHERE id=r AND status='active');
END $$;
CREATE FUNCTION bloc.realm_session(r uuid,digest bytea,refresh boolean) RETURNS bloc.realm_user_session LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE s bloc.realm_user_session; p bloc.realm_authentication_settings; checked timestamptz;
BEGIN
 checked:=bloc.realm_lock();
 SELECT * INTO s FROM bloc.realm_user_session WHERE realm_id=r AND session_digest=digest;
 IF s.id IS NULL THEN RETURN NULL; END IF;
 SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;
 IF s.revoked_at IS NOT NULL OR s.expires_at<=checked OR s.created_at+make_interval(secs=>p.session_absolute_seconds)<=checked OR s.last_activity_at+make_interval(secs=>p.session_idle_seconds)<=checked
 OR NOT EXISTS(SELECT FROM bloc.realm_user_credential c JOIN bloc.realm_user u ON u.realm_id=c.realm_id AND u.id=c.user_id JOIN bloc.realm t ON t.id=u.realm_id WHERE c.realm_id=r AND c.user_id=s.user_id AND c.credential_version=s.credential_version AND u.status='active' AND t.status='active') THEN
  UPDATE bloc.realm_user_session SET revoked_at=coalesce(revoked_at,checked) WHERE id=s.id;
  DELETE FROM bloc.realm_form_state WHERE session_id=s.id;
  RETURN NULL;
 END IF;
 IF refresh THEN
  UPDATE bloc.realm_user_session SET last_activity_at=greatest(last_activity_at,checked),expires_at=least(created_at+make_interval(secs=>p.session_absolute_seconds),checked+make_interval(secs=>p.session_idle_seconds)) WHERE id=s.id RETURNING * INTO s;
 END IF;
 RETURN s;
END $$;
CREATE FUNCTION bloc.realm_link(r uuid,p text,digest bytea) RETURNS bloc.realm_user_access_link LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE l bloc.realm_user_access_link; checked timestamptz;
BEGIN
 checked:=bloc.realm_lock();
 SELECT * INTO l FROM bloc.realm_user_access_link WHERE realm_id=r AND purpose=p AND token_digest=digest AND consumed_at IS NULL AND expires_at>checked;
 IF l.user_id IS NULL OR NOT EXISTS(SELECT FROM bloc.realm_user u JOIN bloc.realm t ON t.id=u.realm_id WHERE u.realm_id=r AND u.id=l.user_id AND u.status='active' AND t.status='active') THEN RETURN NULL; END IF;
 IF (p='activation' AND EXISTS(SELECT FROM bloc.realm_user_credential WHERE realm_id=r AND user_id=l.user_id)) OR (p='reset' AND NOT EXISTS(SELECT FROM bloc.realm_user_credential WHERE realm_id=r AND user_id=l.user_id AND credential_version=l.credential_version)) THEN RETURN NULL; END IF;
 RETURN l;
END $$;
-- Form helpers are private. Public operations recheck these bindings at commit.
CREATE FUNCTION bloc.realm_form(r uuid,p text,browser bytea,session bytea,link bytea,new_token bytea) RETURNS bytea LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE checked timestamptz; sid uuid; l bloc.realm_user_access_link; result bytea; deadline timestamptz;
BEGIN
 checked:=bloc.realm_lock(); deadline:=checked+interval '30 minutes';
 IF NOT EXISTS(SELECT FROM bloc.realm WHERE id=r AND status='active') THEN RETURN NULL; END IF;
 IF p='account' THEN sid:=(bloc.realm_session(r,session,false)).id; IF sid IS NULL THEN RETURN NULL; END IF;
 ELSIF p IN('activation','reset') THEN l:=bloc.realm_link(r,p,link); IF l.user_id IS NULL THEN RETURN NULL; END IF; deadline:=least(deadline,l.expires_at);
 ELSIF p<>'anonymous' THEN RETURN NULL; END IF;
 SELECT csrf_token INTO result FROM bloc.realm_form_state WHERE browser_digest=browser AND realm_id=r AND purpose=p AND session_id IS NOT DISTINCT FROM sid AND link_digest IS NOT DISTINCT FROM link AND expires_at>checked;
 IF FOUND THEN RETURN result; END IF;
 IF new_token IS NULL THEN RETURN NULL; END IF;
 DELETE FROM bloc.realm_form_state WHERE browser_digest IN(SELECT browser_digest FROM bloc.realm_form_state WHERE expires_at<=checked LIMIT 1000);
 IF (SELECT count(*) FROM bloc.realm_form_state)>=10000 OR (SELECT count(*) FROM bloc.realm_form_state WHERE realm_id=r)>=1000 THEN RAISE EXCEPTION 'capacity' USING ERRCODE='54000'; END IF;
 INSERT INTO bloc.realm_form_state VALUES(browser,r,p,sid,link,new_token,checked,deadline);
 RETURN new_token;
END $$;
CREATE FUNCTION bloc.realm_form_link(r uuid,p text,browser bytea) RETURNS bytea LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE d bytea;
BEGIN
 PERFORM bloc.realm_lock();
 SELECT link_digest INTO d FROM bloc.realm_form_state WHERE realm_id=r AND purpose=p AND browser_digest=browser AND expires_at>clock_timestamp();
 IF (bloc.realm_link(r,p,d)).user_id IS NULL THEN RETURN NULL; END IF;
 RETURN d;
END $$;
CREATE FUNCTION bloc.realm_form_valid(r uuid,p text,browser bytea,token bytea,session bytea,link bytea) RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
 SELECT token IS NOT NULL AND bloc.realm_form(r,p,browser,session,link,NULL)=token;
$$;
CREATE FUNCTION bloc.realm_credentials(r uuid,identifier text) RETURNS TABLE(user_id text,phc text,version bigint,user_version bigint) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
BEGIN
 PERFORM bloc.realm_lock();
 RETURN QUERY SELECT u.id::text,c.password_hash,c.credential_version,u.version FROM bloc.realm_user u JOIN bloc.realm_user_credential c ON c.realm_id=u.realm_id AND c.user_id=u.id JOIN bloc.realm t ON t.id=u.realm_id WHERE u.realm_id=r AND u.email=identifier AND u.status='active' AND t.status='active';
END $$;
CREATE FUNCTION bloc.realm_account(r uuid,digest bytea,refresh boolean) RETURNS TABLE(user_id text,session_id text,email text,display_name text,version bigint,credential_version bigint,phc text) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE s bloc.realm_user_session;
BEGIN
 s:=bloc.realm_session(r,digest,refresh);
 RETURN QUERY SELECT u.id::text,s.id::text,u.email,u.display_name,u.version,c.credential_version,c.password_hash FROM bloc.realm_user u JOIN bloc.realm_user_credential c ON c.realm_id=u.realm_id AND c.user_id=u.id WHERE u.realm_id=r AND u.id=s.user_id;
END $$;
CREATE FUNCTION bloc.realm_sessions(r uuid,digest bytea) RETURNS TABLE(id text,device_label text,created text,last_active text,current boolean) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE s bloc.realm_user_session; checked timestamptz;
BEGIN
 s:=bloc.realm_session(r,digest,false); checked:=clock_timestamp();
 RETURN QUERY SELECT v.id::text,v.device_label,to_char(v.created_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS'),to_char(v.last_activity_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS'),v.id=s.id FROM bloc.realm_user_session v WHERE v.realm_id=r AND v.user_id=s.user_id AND v.revoked_at IS NULL AND v.expires_at>checked ORDER BY v.created_at,v.id;
END $$;
CREATE FUNCTION bloc.reserve_shared_admission(public_flow boolean,scopes text[],subjects bytea[],units integer[]) RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE checked timestamptz; idx integer; allowance integer; events timestamptz[]; wait_seconds integer:=0; new_public integer:=0; new_admin integer:=0; n integer; is_public boolean;
BEGIN
 IF cardinality(scopes)<>cardinality(subjects) OR cardinality(scopes)<>cardinality(units) OR cardinality(scopes) NOT BETWEEN 1 AND 7 OR (SELECT count(DISTINCT (scopes[i],subjects[i])) FROM generate_subscripts(scopes,1) i)<>cardinality(scopes) THEN RAISE EXCEPTION 'invalid reservation'; END IF;
 PERFORM id FROM bloc.installation WHERE id=1 FOR UPDATE;
 IF public_flow AND (SELECT recovery_required FROM bloc.installation WHERE id=1) THEN RAISE EXCEPTION 'authority unavailable'; END IF;
 checked:=clock_timestamp();
 DELETE FROM bloc.realm_admission_bucket WHERE (scope,subject_digest) IN(SELECT scope,subject_digest FROM bloc.realm_admission_bucket WHERE expires_at<=checked LIMIT 1000);
 DELETE FROM bloc.administrator_admission_bucket WHERE (scope,subject_digest) IN(SELECT scope,subject_digest FROM bloc.administrator_admission_bucket WHERE expires_at<=checked LIMIT 1000);
 FOR idx IN 1..cardinality(scopes) LOOP
  is_public:=public_flow AND scopes[idx]<>'hash_work';
  IF scopes[idx] IN('hash_work','public_work') THEN subjects[idx]:=decode(repeat('00',32),'hex'); END IF;
  IF units[idx] NOT BETWEEN 1 AND 2 OR octet_length(subjects[idx])<>32 THEN RAISE EXCEPTION 'invalid reservation'; END IF;
  IF is_public THEN
   allowance:=CASE scopes[idx] WHEN 'login_identifier' THEN 5 WHEN 'registration_identifier' THEN 3 WHEN 'link' THEN 5 WHEN 'password_change' THEN 5 WHEN 'link_issue' THEN 5 WHEN 'public_work' THEN 20 WHEN 'account_mutation' THEN 30 WHEN 'form_source' THEN 10 WHEN 'credential_source' THEN 10 WHEN 'registration_realm' THEN 10 WHEN 'exchange_source' THEN 10 WHEN 'exchange_realm' THEN 10 ELSE NULL END;
   SELECT array_agg(e ORDER BY e) INTO events FROM bloc.realm_admission_bucket b CROSS JOIN LATERAL unnest(b.admitted_at) e WHERE b.scope=scopes[idx] AND b.subject_digest=subjects[idx] AND e>checked-interval '60 seconds';
   IF NOT EXISTS(SELECT FROM bloc.realm_admission_bucket WHERE scope=scopes[idx] AND subject_digest=subjects[idx]) THEN new_public:=new_public+1; END IF;
  ELSE
   allowance:=CASE scopes[idx] WHEN 'password_change' THEN 5 WHEN 'hash_work' THEN 30 WHEN 'credential_source' THEN 10 WHEN 'login_identifier' THEN 10 WHEN 'operator_code' THEN 10 WHEN 'form_issue_source' THEN 10 ELSE NULL END;
   SELECT array_agg(e ORDER BY e) INTO events FROM bloc.administrator_admission_bucket b CROSS JOIN LATERAL unnest(b.admitted_at) e WHERE b.scope=scopes[idx] AND b.subject_digest=subjects[idx] AND e>checked-interval '60 seconds';
   IF NOT EXISTS(SELECT FROM bloc.administrator_admission_bucket WHERE scope=scopes[idx] AND subject_digest=subjects[idx]) THEN new_admin:=new_admin+1; END IF;
  END IF;
  IF allowance IS NULL THEN RAISE EXCEPTION 'invalid scope'; END IF;
  n:=coalesce(cardinality(events),0);
  IF n+units[idx]>allowance THEN wait_seconds:=greatest(wait_seconds,ceil(extract(epoch FROM events[n+units[idx]-allowance]+interval '60 seconds'-checked))::integer,1); END IF;
 END LOOP;
 IF wait_seconds>0 THEN RETURN wait_seconds; END IF;
 IF (SELECT count(*) FROM bloc.realm_admission_bucket)+new_public>10000 OR (SELECT count(*) FROM bloc.administrator_admission_bucket)+new_admin>10000 THEN RETURN -1; END IF;
 FOR idx IN 1..cardinality(scopes) LOOP
  IF public_flow AND scopes[idx]<>'hash_work' THEN
   SELECT coalesce(array_agg(e ORDER BY e),ARRAY[]::timestamptz[]) INTO events FROM bloc.realm_admission_bucket b CROSS JOIN LATERAL unnest(b.admitted_at) e WHERE b.scope=scopes[idx] AND b.subject_digest=subjects[idx] AND e>checked-interval '60 seconds';
   INSERT INTO bloc.realm_admission_bucket VALUES(scopes[idx],subjects[idx],events||array_fill(checked,ARRAY[units[idx]]),checked+interval '2 minutes') ON CONFLICT(scope,subject_digest) DO UPDATE SET admitted_at=EXCLUDED.admitted_at,expires_at=EXCLUDED.expires_at;
  ELSE
   SELECT coalesce(array_agg(e ORDER BY e),ARRAY[]::timestamptz[]) INTO events FROM bloc.administrator_admission_bucket b CROSS JOIN LATERAL unnest(b.admitted_at) e WHERE b.scope=scopes[idx] AND b.subject_digest=subjects[idx] AND e>checked-interval '60 seconds';
   INSERT INTO bloc.administrator_admission_bucket VALUES(scopes[idx],subjects[idx],events||array_fill(checked,ARRAY[units[idx]]),checked+interval '2 minutes') ON CONFLICT(scope,subject_digest) DO UPDATE SET admitted_at=EXCLUDED.admitted_at,expires_at=EXCLUDED.expires_at;
  END IF;
 END LOOP;
 RETURN 0;
END $$;
CREATE OR REPLACE FUNCTION bloc.reserve_admission(scopes text[],subjects bytea[],units integer[]) RETURNS integer LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$ SELECT bloc.reserve_shared_admission(false,scopes,subjects,units); $$;
CREATE FUNCTION bloc.realm_reserve(scopes text[],subjects bytea[],units integer[]) RETURNS integer LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$ SELECT bloc.reserve_shared_admission(true,scopes,subjects,units); $$;
CREATE FUNCTION bloc.realm_denial(a text,r text) RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
 INSERT INTO bloc.realm_denial_aggregate VALUES(date_trunc('minute',clock_timestamp()),a,r,1) ON CONFLICT(minute,action,reason) DO UPDATE SET count=CASE WHEN bloc.realm_denial_aggregate.count=9223372036854775807 THEN 9223372036854775807 ELSE bloc.realm_denial_aggregate.count+1 END;
$$;
CREATE FUNCTION bloc.realm_new_session(r uuid,u uuid,v bigint,digest bytea,browser bytea,token bytea,device text) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE checked timestamptz; p bloc.realm_authentication_settings; sid uuid;
BEGIN
 checked:=bloc.realm_lock(); SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;
 DELETE FROM bloc.realm_user_session WHERE id IN(SELECT id FROM bloc.realm_user_session WHERE revoked_at IS NOT NULL OR expires_at<=checked LIMIT 1000);
 IF (SELECT count(*) FROM bloc.realm_user_session)>=100000 THEN RAISE EXCEPTION 'capacity' USING ERRCODE='54000'; END IF;
 UPDATE bloc.realm_user_session SET revoked_at=checked WHERE id IN(SELECT id FROM bloc.realm_user_session WHERE realm_id=r AND user_id=u AND revoked_at IS NULL ORDER BY created_at DESC,id DESC OFFSET (p.session_limit-1));
 DELETE FROM bloc.realm_form_state f USING bloc.realm_user_session s WHERE f.session_id=s.id AND s.realm_id=r AND s.user_id=u AND s.revoked_at IS NOT NULL;
 INSERT INTO bloc.realm_user_session(realm_id,user_id,session_digest,credential_version,created_at,last_activity_at,expires_at,device_label) VALUES(r,u,digest,v,checked,checked,checked+make_interval(secs=>least(p.session_idle_seconds,p.session_absolute_seconds)),device) RETURNING id INTO sid;
 IF bloc.realm_form(r,'account',browser,digest,NULL,token) IS NULL THEN RAISE EXCEPTION 'form capacity' USING ERRCODE='54000'; END IF;
 RETURN sid;
END $$;
CREATE FUNCTION bloc.realm_save_settings(r uuid,digest bytea,browser bytea,token bytea,expected bigint,values_text text[],confirmed boolean) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE aid uuid; checked timestamptz; p bloc.realm_authentication_settings; proposed bloc.realm_authentication_settings;
BEGIN
 checked:=bloc.realm_lock(); aid:=bloc.directory_authority(digest);
 IF bloc.form_state(browser,digest,NULL) IS DISTINCT FROM token OR token IS NULL THEN RETURN 'csrf'; END IF;
 SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;
 IF p.realm_id IS NULL THEN RETURN 'missing'; END IF;
 IF p.version<>expected THEN RETURN 'stale'; END IF;
 IF cardinality(values_text)<>11 THEN RETURN 'invalid'; END IF;
 proposed:=p;
 BEGIN
  proposed.registration_enabled:=values_text[1]::boolean; proposed.password_min_length:=values_text[2]::smallint;
  proposed.require_uppercase:=values_text[3]::boolean; proposed.require_lowercase:=values_text[4]::boolean; proposed.require_number:=values_text[5]::boolean; proposed.require_special:=values_text[6]::boolean;
  proposed.activation_ttl_seconds:=values_text[7]::integer; proposed.reset_ttl_seconds:=values_text[8]::integer; proposed.session_idle_seconds:=values_text[9]::integer; proposed.session_absolute_seconds:=values_text[10]::integer; proposed.session_limit:=values_text[11]::smallint;
 EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN 'invalid'; END;
 IF proposed.password_min_length NOT BETWEEN 16 AND 128 OR proposed.activation_ttl_seconds NOT BETWEEN 300 AND 604800 OR proposed.reset_ttl_seconds NOT BETWEEN 300 AND 86400 OR proposed.session_idle_seconds NOT BETWEEN 60 AND 86400 OR proposed.session_absolute_seconds NOT BETWEEN 300 AND 2592000 OR proposed.session_idle_seconds>proposed.session_absolute_seconds OR proposed.session_limit NOT BETWEEN 1 AND 100 THEN RETURN 'invalid'; END IF;
 IF proposed=p THEN RETURN 'ok'; END IF;
 IF (proposed.session_idle_seconds,proposed.session_absolute_seconds,proposed.session_limit) IS DISTINCT FROM (p.session_idle_seconds,p.session_absolute_seconds,p.session_limit) THEN
  IF NOT confirmed THEN RETURN 'confirm'; END IF;
  UPDATE bloc.realm_user_session SET revoked_at=checked WHERE realm_id=r AND revoked_at IS NULL AND (expires_at<=checked OR created_at+make_interval(secs=>least(p.session_absolute_seconds,proposed.session_absolute_seconds))<=checked OR last_activity_at+make_interval(secs=>least(p.session_idle_seconds,proposed.session_idle_seconds))<=checked);
  UPDATE bloc.realm_user_session s SET revoked_at=checked WHERE s.id IN(SELECT id FROM (SELECT id,row_number() OVER(PARTITION BY user_id ORDER BY created_at DESC,id DESC) n FROM bloc.realm_user_session WHERE realm_id=r AND revoked_at IS NULL) ranked WHERE n>proposed.session_limit);
  DELETE FROM bloc.realm_form_state f USING bloc.realm_user_session s WHERE f.session_id=s.id AND s.realm_id=r AND s.revoked_at IS NOT NULL;
  UPDATE bloc.realm_user_session SET expires_at=least(created_at+make_interval(secs=>proposed.session_absolute_seconds),last_activity_at+make_interval(secs=>proposed.session_idle_seconds)) WHERE realm_id=r AND revoked_at IS NULL;
 END IF;
 UPDATE bloc.realm_authentication_settings SET registration_enabled=proposed.registration_enabled,password_min_length=proposed.password_min_length,require_uppercase=proposed.require_uppercase,require_lowercase=proposed.require_lowercase,require_number=proposed.require_number,require_special=proposed.require_special,activation_ttl_seconds=proposed.activation_ttl_seconds,reset_ttl_seconds=proposed.reset_ttl_seconds,session_idle_seconds=proposed.session_idle_seconds,session_absolute_seconds=proposed.session_absolute_seconds,session_limit=proposed.session_limit,version=version+1,updated_at=checked WHERE realm_id=r;
 INSERT INTO bloc.security_audit_event(installation_id,administrator_id,action,outcome,realm_id) VALUES(1,aid,'realm_authentication_update','success',r);
 RETURN 'ok';
END $$;
CREATE FUNCTION bloc.realm_issue_link(r uuid,u uuid,p text,digest bytea,browser bytea,token bytea,expected bigint,confirmed boolean,link bytea) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE aid uuid; checked timestamptz; v bigint; profile bloc.realm_user; ttl integer;
BEGIN
 checked:=bloc.realm_lock(); aid:=bloc.directory_authority(digest);
 IF bloc.form_state(browser,digest,NULL) IS DISTINCT FROM token OR token IS NULL THEN RETURN 'csrf'; END IF;
 SELECT * INTO profile FROM bloc.realm_user WHERE realm_id=r AND id=u;
 IF profile.id IS NULL THEN RETURN 'missing'; END IF;
 IF NOT confirmed THEN RETURN 'invalid'; END IF;
 IF profile.version<>expected OR profile.status<>'active' OR NOT EXISTS(SELECT FROM bloc.realm WHERE id=r AND status='active') THEN RETURN 'stale'; END IF;
 SELECT credential_version INTO v FROM bloc.realm_user_credential WHERE realm_id=r AND user_id=u;
 IF p NOT IN('activation','reset') OR (p='activation')<>(v IS NULL) THEN RETURN 'stale'; END IF;
 SELECT CASE p WHEN 'activation' THEN activation_ttl_seconds ELSE reset_ttl_seconds END INTO ttl FROM bloc.realm_authentication_settings WHERE realm_id=r;
 DELETE FROM bloc.realm_form_state WHERE link_digest IN(SELECT token_digest FROM bloc.realm_user_access_link WHERE realm_id=r AND user_id=u AND purpose=p);
 INSERT INTO bloc.realm_user_access_link VALUES(r,u,p,link,v,profile.version,aid,checked,checked+make_interval(secs=>ttl),NULL) ON CONFLICT(realm_id,user_id,purpose) DO UPDATE SET token_digest=EXCLUDED.token_digest,credential_version=EXCLUDED.credential_version,user_version=EXCLUDED.user_version,issued_by=EXCLUDED.issued_by,issued_at=EXCLUDED.issued_at,expires_at=EXCLUDED.expires_at,consumed_at=NULL;
 INSERT INTO bloc.security_audit_event(installation_id,administrator_id,action,outcome,realm_id,realm_user_id) VALUES(1,aid,CASE p WHEN 'activation' THEN 'realm_activation_link_issue' ELSE 'realm_reset_link_issue' END,'success',r,u);
 RETURN to_char((checked+make_interval(secs=>ttl)) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"');
END $$;
CREATE FUNCTION bloc.realm_has_credential(r uuid,u uuid,digest bytea) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
BEGIN PERFORM bloc.directory_authority(digest); RETURN EXISTS(SELECT FROM bloc.realm_user_credential WHERE realm_id=r AND user_id=u); END $$;
-- Each mutation carries the browser authority verified before expensive work.
-- Snapshot versions alone never replace the fresh lifecycle and form checks.
CREATE FUNCTION bloc.realm_commit(r uuid,operation text,session bytea,browser bytea,token bytea,link bytea,target uuid,expected bigint,policy bigint,values_text text[],new_session bytea,new_browser bytea,new_token bytea) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE checked timestamptz; p bloc.realm_authentication_settings; s bloc.realm_user_session; l bloc.realm_user_access_link; u uuid; v bigint; uv bigint; event_action text; principal uuid; n integer; target_session bloc.realm_user_session; purpose text;
BEGIN
 checked:=bloc.realm_lock();
 SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;
 IF p.realm_id IS NULL OR NOT EXISTS(SELECT FROM bloc.realm WHERE id=r AND status='active') THEN RETURN 'missing'; END IF;
 IF operation IN('profile','password','logout','revoke','revoke_others') THEN
  s:=bloc.realm_session(r,session,false); IF s.id IS NULL THEN RETURN 'authority'; END IF;
  u:=s.user_id; principal:=u; v:=s.credential_version; purpose:='account';
 ELSIF operation IN('activation','reset') THEN
  l:=bloc.realm_link(r,operation,link); IF l.user_id IS NULL THEN RETURN 'link'; END IF;
  u:=l.user_id; v:=coalesce(l.credential_version,0); purpose:=operation;
 ELSIF operation IN('register','login') THEN purpose:='anonymous';
 ELSE RAISE EXCEPTION 'invalid operation'; END IF;
 IF NOT coalesce(bloc.realm_form_valid(r,purpose,browser,token,session,link),false) THEN RETURN 'csrf'; END IF;
 IF operation='register' AND NOT p.registration_enabled THEN RETURN 'disabled'; END IF;
 IF operation IN('register','activation','reset','password') AND p.version<>policy THEN RETURN 'policy'; END IF;
 IF operation='register' THEN
  IF NOT p.registration_enabled THEN RETURN 'disabled'; END IF;
  u:=gen_random_uuid();
  BEGIN
   INSERT INTO bloc.realm_user(id,realm_id,email,display_name,created_at,updated_at) VALUES(u,r,values_text[1],nullif(values_text[2],''),checked,checked);
  EXCEPTION WHEN unique_violation THEN RETURN 'collision'; END;
  INSERT INTO bloc.realm_user_credential VALUES(r,u,values_text[3],1,checked); event_action:='realm_registration';
 ELSIF operation='login' THEN
  SELECT c.credential_version,a.version INTO v,uv FROM bloc.realm_user_credential c JOIN bloc.realm_user a ON a.realm_id=c.realm_id AND a.id=c.user_id WHERE c.realm_id=r AND c.user_id=target AND a.status='active';
  IF v IS NULL OR v<>expected OR uv<>policy THEN RETURN 'credentials'; END IF;
  u:=target; principal:=u; PERFORM bloc.realm_new_session(r,u,v,new_session,new_browser,new_token,values_text[1]); event_action:='realm_sign_in';
 ELSIF operation IN('activation','reset','password') THEN
  IF operation='password' AND v<>expected THEN RETURN 'authority'; END IF;
  PERFORM bloc.realm_invalidate(r,u);
  INSERT INTO bloc.realm_user_credential VALUES(r,u,values_text[1],1,checked) ON CONFLICT(realm_id,user_id) DO UPDATE SET password_hash=EXCLUDED.password_hash,credential_version=bloc.realm_user_credential.credential_version+1,password_changed_at=checked RETURNING credential_version INTO v;
  IF operation='password' THEN PERFORM bloc.realm_new_session(r,u,v,new_session,new_browser,new_token,values_text[2]); END IF;
  event_action:=CASE operation WHEN 'activation' THEN 'realm_activation' WHEN 'reset' THEN 'realm_password_reset' ELSE 'realm_password_change' END;
 ELSIF operation='profile' THEN
  SELECT version INTO uv FROM bloc.realm_user WHERE realm_id=r AND id=u;
  IF uv<>expected THEN RETURN 'stale'; END IF;
  UPDATE bloc.realm_user SET display_name=nullif(values_text[1],''),version=version+1,updated_at=checked WHERE realm_id=r AND id=u AND display_name IS DISTINCT FROM nullif(values_text[1],'');
  IF NOT FOUND THEN PERFORM bloc.realm_session(r,session,true); RETURN 'ok'; END IF; event_action:='realm_profile_update';
 ELSE
  IF operation='revoke' THEN
   SELECT * INTO target_session FROM bloc.realm_user_session WHERE id=target AND realm_id=r AND user_id=u;
   IF target_session.id IS NULL THEN RETURN 'missing'; END IF;
   IF target_session.revoked_at IS NOT NULL OR target_session.expires_at<=checked THEN PERFORM bloc.realm_session(r,session,true); RETURN 'ok'; END IF;
  END IF;
  UPDATE bloc.realm_user_session SET revoked_at=checked WHERE realm_id=r AND user_id=u AND revoked_at IS NULL AND (operation='revoke_others' AND id<>s.id OR operation='logout' AND id=s.id OR operation='revoke' AND id=target);
  GET DIAGNOSTICS n=ROW_COUNT; IF n=0 THEN PERFORM bloc.realm_session(r,session,true); RETURN 'ok'; END IF;
  DELETE FROM bloc.realm_form_state f USING bloc.realm_user_session x WHERE f.session_id=x.id AND x.realm_id=r AND x.user_id=u AND x.revoked_at IS NOT NULL;
  event_action:=CASE operation WHEN 'logout' THEN 'realm_sign_out' ELSE 'realm_session_revoke' END;
 END IF;
 IF operation IN('profile','revoke','revoke_others') THEN PERFORM bloc.realm_session(r,session,true); END IF;
 INSERT INTO bloc.security_audit_event(installation_id,action,outcome,realm_id,realm_user_id,actor_realm_id,actor_user_id) VALUES(1,event_action,'success',r,u,CASE WHEN principal IS NOT NULL THEN r END,principal);
 RETURN 'ok';
END $$;
CREATE FUNCTION bloc.realm_exchange(r uuid,p text,browser bytea,token bytea,link bytea,new_browser bytea,new_token bytea) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
BEGIN
 PERFORM bloc.realm_lock();
 IF NOT coalesce(bloc.realm_form_valid(r,'anonymous',browser,token,NULL,NULL),false) THEN RETURN 'csrf'; END IF;
 IF (bloc.realm_link(r,p,link)).user_id IS NULL THEN RETURN 'link'; END IF;
 IF bloc.realm_form(r,p,new_browser,NULL,link,new_token) IS NULL THEN RETURN 'link'; END IF;
 RETURN 'ok';
END $$;
CREATE OR REPLACE FUNCTION bloc.invalidate_access() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE aid uuid;
BEGIN
 PERFORM id FROM bloc.installation WHERE id=1 FOR UPDATE;
 UPDATE bloc.installation_administrator SET credential_version=credential_version+1 RETURNING id INTO aid;
 UPDATE bloc.installation SET recovery_required=(aid IS NOT NULL) WHERE id=1;
 UPDATE bloc.administrator_session SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL;
 DELETE FROM bloc.operator_code; DELETE FROM bloc.administrator_form_state;
 DELETE FROM bloc.realm_form_state; DELETE FROM bloc.realm_user_access_link;
 UPDATE bloc.realm_user_session SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL;
 INSERT INTO bloc.security_audit_event(installation_id,administrator_id,action,outcome) VALUES(1,aid,'restore','success');
END $$;
ALTER FUNCTION bloc.maintain_access() RENAME TO maintain_administrator_access;
REVOKE ALL ON FUNCTION bloc.maintain_administrator_access() FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
CREATE FUNCTION bloc.maintain_access() RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE total integer; n integer;
BEGIN
 PERFORM id FROM bloc.installation WHERE id=1 FOR UPDATE;
 total:=bloc.maintain_administrator_access();
 DELETE FROM bloc.realm_form_state WHERE browser_digest IN(SELECT f.browser_digest FROM bloc.realm_form_state f LEFT JOIN bloc.realm_user_access_link l ON l.token_digest=f.link_digest LEFT JOIN bloc.realm_user_session s ON s.id=f.session_id WHERE f.expires_at<=clock_timestamp() OR l.expires_at<=clock_timestamp() OR l.consumed_at IS NOT NULL OR s.revoked_at IS NOT NULL OR s.expires_at<=clock_timestamp() LIMIT 1000);
 DELETE FROM bloc.realm_user_access_link l WHERE token_digest IN(SELECT token_digest FROM bloc.realm_user_access_link WHERE expires_at<=clock_timestamp() OR consumed_at IS NOT NULL LIMIT 1000) AND NOT EXISTS(SELECT FROM bloc.realm_form_state f WHERE f.link_digest=l.token_digest);
 DELETE FROM bloc.realm_user_session s WHERE id IN(SELECT id FROM bloc.realm_user_session WHERE revoked_at IS NOT NULL OR expires_at<=clock_timestamp() LIMIT 1000) AND NOT EXISTS(SELECT FROM bloc.realm_form_state f WHERE f.session_id=s.id);
 DELETE FROM bloc.realm_admission_bucket WHERE (scope,subject_digest) IN(SELECT scope,subject_digest FROM bloc.realm_admission_bucket WHERE expires_at<=clock_timestamp() LIMIT 1000);
 DELETE FROM bloc.realm_denial_aggregate WHERE (minute,action,reason) IN(SELECT minute,action,reason FROM bloc.realm_denial_aggregate WHERE minute<clock_timestamp()-interval '7 days' LIMIT 1000); GET DIAGNOSTICS n=ROW_COUNT;
 RETURN total+n;
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA bloc FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
-- New private helpers receive no runtime grant. Do not revoke earlier capabilities.
DO $$ DECLARE f record; BEGIN
 FOR f IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace='bloc'::regnamespace AND (proname LIKE 'realm_%' OR proname='reserve_shared_admission') LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance',f.signature);
 END LOOP;
END $$;
GRANT EXECUTE ON FUNCTION bloc.realm_settings(uuid,bytea),bloc.realm_public_name(uuid),bloc.realm_form(uuid,text,bytea,bytea,bytea,bytea),bloc.realm_form_link(uuid,text,bytea),bloc.realm_credentials(uuid,text),bloc.realm_account(uuid,bytea,boolean),bloc.realm_sessions(uuid,bytea),bloc.realm_reserve(text[],bytea[],integer[]),bloc.realm_denial(text,text),bloc.realm_save_settings(uuid,bytea,bytea,bytea,bigint,text[],boolean),bloc.realm_issue_link(uuid,uuid,text,bytea,bytea,bytea,bigint,boolean,bytea),bloc.realm_has_credential(uuid,uuid,bytea),bloc.realm_commit(uuid,text,bytea,bytea,bytea,bytea,uuid,bigint,bigint,text[],bytea,bytea,bytea),bloc.realm_exchange(uuid,text,bytea,bytea,bytea,bytea,bytea) TO bloc_runtime;
GRANT EXECUTE ON FUNCTION bloc.maintain_access() TO bloc_maintenance;
REVOKE ALL ON FUNCTION bloc.maintain_access() FROM PUBLIC;
CREATE FUNCTION bloc.realm_form_expired(r uuid,p text,browser bytea) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE d bytea;
BEGIN
 PERFORM bloc.realm_lock();
 SELECT link_digest INTO d FROM bloc.realm_form_state WHERE realm_id=r AND purpose=p AND browser_digest=browser AND expires_at<=clock_timestamp();
 RETURN d IS NOT NULL AND (bloc.realm_link(r,p,d)).user_id IS NOT NULL;
END $$;
REVOKE ALL ON FUNCTION bloc.realm_form_expired(uuid,text,bytea) FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
GRANT EXECUTE ON FUNCTION bloc.realm_form_expired(uuid,text,bytea) TO bloc_runtime;
