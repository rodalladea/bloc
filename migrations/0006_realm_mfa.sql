-- Explicit MFA authority storage. Serving processes never apply migrations.
ALTER TABLE bloc.installation ADD COLUMN security_id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE;
ALTER TABLE bloc.realm_authentication_settings
 ADD COLUMN mfa_mode text NOT NULL DEFAULT 'optional' CHECK(mfa_mode IN('disabled','optional','required')),
 ADD COLUMN mfa_allowed_methods text[] NOT NULL DEFAULT ARRAY['totp','webauthn']::text[],
 ADD COLUMN mfa_preferred_method text DEFAULT 'webauthn',
 ADD COLUMN mfa_recovery_codes_enabled boolean NOT NULL DEFAULT true,
 ADD COLUMN mfa_admin_recovery_enabled boolean NOT NULL DEFAULT true,
 ADD COLUMN mfa_flow_ttl_seconds integer NOT NULL DEFAULT 300 CHECK(mfa_flow_ttl_seconds BETWEEN 120 AND 600),
 ADD COLUMN mfa_admin_recovery_ttl_seconds integer NOT NULL DEFAULT 1800 CHECK(mfa_admin_recovery_ttl_seconds BETWEEN 300 AND 3600),
 ADD CONSTRAINT mfa_methods CHECK(mfa_allowed_methods <@ ARRAY['totp','webauthn']::text[] AND array_position(mfa_allowed_methods,NULL) IS NULL AND cardinality(mfa_allowed_methods)<=2 AND (cardinality(mfa_allowed_methods)<>2 OR mfa_allowed_methods @> ARRAY['totp','webauthn']::text[]) AND (mfa_mode='disabled' OR cardinality(mfa_allowed_methods)>0) AND (mfa_preferred_method IS NULL OR mfa_preferred_method=ANY(mfa_allowed_methods)));
CREATE TABLE bloc.realm_user_mfa_state (
 realm_id uuid NOT NULL,user_id uuid NOT NULL,factor_epoch bigint NOT NULL DEFAULT 1 CHECK(factor_epoch>0),preferred_factor_id uuid,updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(realm_id,user_id), FOREIGN KEY(realm_id,user_id) REFERENCES bloc.realm_user(realm_id,id)
);
INSERT INTO bloc.realm_user_mfa_state(realm_id,user_id) SELECT realm_id,id FROM bloc.realm_user;
CREATE TABLE bloc.realm_user_factor (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),realm_id uuid NOT NULL,user_id uuid NOT NULL,kind text NOT NULL CHECK(kind IN('totp','webauthn')),
 label text NOT NULL CHECK(char_length(label) BETWEEN 1 AND 64 AND octet_length(label)<=256 AND label !~ '[[:cntrl:]]'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),last_used_at timestamptz,revoked_at timestamptz,
 UNIQUE(realm_id,user_id,id),FOREIGN KEY(realm_id,user_id) REFERENCES bloc.realm_user(realm_id,id)
);
CREATE UNIQUE INDEX realm_one_totp ON bloc.realm_user_factor(realm_id,user_id) WHERE kind='totp' AND revoked_at IS NULL;
ALTER TABLE bloc.realm_user_mfa_state ADD FOREIGN KEY(realm_id,user_id,preferred_factor_id) REFERENCES bloc.realm_user_factor(realm_id,user_id,id);
CREATE TABLE bloc.mfa_encryption_key_registry (
 key_id uuid PRIMARY KEY,state text NOT NULL CHECK(state IN('staged','active','decrypt_only','retired')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),retired_at timestamptz,
 CHECK((state='retired')=(retired_at IS NOT NULL))
);
CREATE UNIQUE INDEX mfa_one_active_key ON bloc.mfa_encryption_key_registry(state) WHERE state='active';
CREATE TABLE bloc.mfa_encryption_control (
 id smallint PRIMARY KEY CHECK(id=1),generation bigint NOT NULL DEFAULT 1 CHECK(generation>0),active_key_id uuid REFERENCES bloc.mfa_encryption_key_registry
);
INSERT INTO bloc.mfa_encryption_control(id) VALUES(1);
-- All three encrypted purposes share reference accounting and conditional rotation.
CREATE TABLE bloc.mfa_encrypted_payload (
 id uuid PRIMARY KEY,realm_id uuid NOT NULL,user_id uuid NOT NULL,purpose smallint NOT NULL CHECK(purpose BETWEEN 1 AND 3),payload_version smallint NOT NULL DEFAULT 1 CHECK(payload_version=1),
 encryption_key_id uuid NOT NULL REFERENCES bloc.mfa_encryption_key_registry,envelope_version smallint NOT NULL DEFAULT 1 CHECK(envelope_version=1),
 encrypted_payload bytea NOT NULL CHECK(octet_length(encrypted_payload) BETWEEN 62 AND 4096),revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 UNIQUE(realm_id,user_id,id),FOREIGN KEY(realm_id,user_id) REFERENCES bloc.realm_user(realm_id,id),
 CHECK(substring(encrypted_payload FROM 1 FOR 6)=decode('424d46410101','hex') AND substring(encrypted_payload FROM 7 FOR 16)=uuid_send(encryption_key_id))
);
CREATE INDEX mfa_payload_key ON bloc.mfa_encrypted_payload(encryption_key_id);
CREATE TABLE bloc.realm_totp_factor (
 factor_id uuid PRIMARY KEY,realm_id uuid NOT NULL,user_id uuid NOT NULL,secret_format_version smallint NOT NULL DEFAULT 1 CHECK(secret_format_version=1),
 last_accepted_step bigint NOT NULL,FOREIGN KEY(realm_id,user_id,factor_id) REFERENCES bloc.realm_user_factor(realm_id,user_id,id),
 FOREIGN KEY(realm_id,user_id,factor_id) REFERENCES bloc.mfa_encrypted_payload(realm_id,user_id,id)
);
CREATE TABLE bloc.realm_webauthn_identity (
 realm_id uuid NOT NULL,user_id uuid NOT NULL,user_handle bytea NOT NULL UNIQUE CHECK(octet_length(user_handle)=32),
 PRIMARY KEY(realm_id,user_id),FOREIGN KEY(realm_id,user_id) REFERENCES bloc.realm_user(realm_id,id)
);
CREATE TABLE bloc.realm_webauthn_factor (
 factor_id uuid PRIMARY KEY,realm_id uuid NOT NULL,user_id uuid NOT NULL,credential_id bytea NOT NULL UNIQUE CHECK(octet_length(credential_id) BETWEEN 1 AND 1024),
 public_credential bytea NOT NULL CHECK(octet_length(public_credential) BETWEEN 1 AND 16384),record_format_version smallint NOT NULL DEFAULT 1 CHECK(record_format_version=1),transports text[] NOT NULL DEFAULT '{}',
 FOREIGN KEY(realm_id,user_id,factor_id) REFERENCES bloc.realm_user_factor(realm_id,user_id,id)
);
ALTER TABLE bloc.realm_user_session
 ADD COLUMN factor_epoch bigint NOT NULL DEFAULT 1 CHECK(factor_epoch>0),
 ADD COLUMN password_verified_at timestamptz,
 ADD COLUMN mfa_method text CHECK(mfa_method IN('totp','webauthn')),
 ADD COLUMN mfa_factor_id uuid,
 ADD COLUMN mfa_verified_at timestamptz,
 ADD FOREIGN KEY(realm_id,user_id,mfa_factor_id) REFERENCES bloc.realm_user_factor(realm_id,user_id,id),
 ADD CONSTRAINT mfa_evidence CHECK((mfa_method IS NULL AND mfa_factor_id IS NULL AND mfa_verified_at IS NULL) OR (mfa_method IS NOT NULL AND mfa_factor_id IS NOT NULL AND mfa_verified_at IS NOT NULL));
UPDATE bloc.realm_user_session SET password_verified_at=created_at;
ALTER TABLE bloc.realm_user_session ALTER COLUMN password_verified_at SET NOT NULL,ALTER COLUMN password_verified_at SET DEFAULT clock_timestamp();
CREATE TABLE bloc.realm_mfa_flow (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),realm_id uuid NOT NULL,user_id uuid NOT NULL,bearer_digest bytea NOT NULL UNIQUE CHECK(octet_length(bearer_digest)=32),browser_digest bytea NOT NULL CHECK(octet_length(browser_digest)=32),
 purpose text NOT NULL CHECK(purpose IN('login','initial_enrollment','reauthenticate','recovery','totp_enrollment','webauthn_registration','webauthn_authentication','handoff')),
 operation text,credential_version bigint NOT NULL,factor_epoch bigint NOT NULL,policy_version bigint NOT NULL,user_version bigint NOT NULL,
 password_verified_at timestamptz NOT NULL,parent_id uuid REFERENCES bloc.realm_mfa_flow ON DELETE CASCADE,session_id uuid REFERENCES bloc.realm_user_session ON DELETE CASCADE,
 factor_id uuid,csrf_token bytea NOT NULL CHECK(octet_length(csrf_token)=32),server_state bytea CHECK(octet_length(server_state)<=32768),payload_id uuid REFERENCES bloc.mfa_encrypted_payload,
 recovery_generation_id uuid,created_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,failed_attempts smallint NOT NULL DEFAULT 0 CHECK(failed_attempts BETWEEN 0 AND 5),consumed_at timestamptz,
 FOREIGN KEY(realm_id,user_id) REFERENCES bloc.realm_user(realm_id,id),FOREIGN KEY(realm_id,user_id,factor_id) REFERENCES bloc.realm_user_factor(realm_id,user_id,id),
 CHECK(purpose<>'reauthenticate' OR (operation IS NOT NULL AND session_id IS NOT NULL)),CHECK(expires_at>created_at AND expires_at<=created_at+interval '600 seconds')
);
CREATE INDEX mfa_flow_owner ON bloc.realm_mfa_flow(realm_id,user_id);
CREATE INDEX mfa_flow_expiry ON bloc.realm_mfa_flow(expires_at);
CREATE TABLE bloc.realm_mfa_recovery_generation (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),realm_id uuid NOT NULL,user_id uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),acknowledged_at timestamptz,invalidated_at timestamptz,
 FOREIGN KEY(realm_id,user_id) REFERENCES bloc.realm_user(realm_id,id)
);
CREATE UNIQUE INDEX mfa_live_generation ON bloc.realm_mfa_recovery_generation(realm_id,user_id) WHERE invalidated_at IS NULL;
CREATE TABLE bloc.realm_mfa_recovery_code (
 generation_id uuid NOT NULL REFERENCES bloc.realm_mfa_recovery_generation ON DELETE CASCADE,ordinal smallint NOT NULL CHECK(ordinal BETWEEN 1 AND 10),code_digest bytea NOT NULL UNIQUE CHECK(octet_length(code_digest)=32),consumed_at timestamptz,PRIMARY KEY(generation_id,ordinal)
);
CREATE TABLE bloc.realm_mfa_recovery_link (
 realm_id uuid NOT NULL,user_id uuid NOT NULL,token_digest bytea NOT NULL UNIQUE CHECK(octet_length(token_digest)=32),issued_by uuid NOT NULL REFERENCES bloc.installation_administrator,
 credential_version bigint NOT NULL,user_version bigint NOT NULL,factor_epoch bigint NOT NULL,issued_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,consumed_at timestamptz,
 PRIMARY KEY(realm_id,user_id),FOREIGN KEY(realm_id,user_id) REFERENCES bloc.realm_user(realm_id,id)
);
CREATE FUNCTION bloc.mfa_payload_check() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
BEGIN
 IF TG_OP='UPDATE' THEN NEW.revision:=OLD.revision+1; END IF;
 IF NEW.encryption_key_id IS DISTINCT FROM (SELECT active_key_id FROM bloc.mfa_encryption_control WHERE id=1) THEN RAISE EXCEPTION 'stale writer' USING ERRCODE='40001'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER mfa_payload_writer BEFORE INSERT OR UPDATE ON bloc.mfa_encrypted_payload FOR EACH ROW EXECUTE FUNCTION bloc.mfa_payload_check();
CREATE FUNCTION bloc.mfa_factor_check() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE f bloc.realm_user_factor;
BEGIN
 SELECT * INTO f FROM bloc.realm_user_factor WHERE id=NEW.factor_id;
 IF TG_TABLE_NAME='realm_totp_factor' THEN
  IF f.kind<>'totp' OR NOT EXISTS(SELECT FROM bloc.mfa_encrypted_payload WHERE id=f.id AND purpose=1) THEN RAISE EXCEPTION 'factor payload mismatch'; END IF;
 ELSIF f.kind<>'webauthn' THEN RAISE EXCEPTION 'factor payload mismatch'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER mfa_totp_payload BEFORE INSERT OR UPDATE ON bloc.realm_totp_factor FOR EACH ROW EXECUTE FUNCTION bloc.mfa_factor_check();
CREATE TRIGGER mfa_webauthn_payload BEFORE INSERT OR UPDATE ON bloc.realm_webauthn_factor FOR EACH ROW EXECUTE FUNCTION bloc.mfa_factor_check();
CREATE FUNCTION bloc.mfa_key_status() RETURNS TABLE(installation_id text,key_id text,state text,generation bigint,active_key_id text,reference_count bigint) LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
 SELECT i.security_id::text,k.key_id::text,k.state,c.generation,c.active_key_id::text,(SELECT count(*) FROM bloc.mfa_encrypted_payload p WHERE p.encryption_key_id=k.key_id)
 FROM bloc.installation i CROSS JOIN bloc.mfa_encryption_control c LEFT JOIN bloc.mfa_encryption_key_registry k ON true WHERE i.id=1 AND c.id=1 ORDER BY k.key_id;
$$;
CREATE FUNCTION bloc.mfa_key_change(op text,k uuid,expected bigint,confirmed boolean) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE c bloc.mfa_encryption_control; current_state text;
BEGIN
 PERFORM id FROM bloc.installation WHERE id=1 FOR UPDATE;
 SELECT * INTO c FROM bloc.mfa_encryption_control WHERE id=1 FOR UPDATE;
 SELECT state INTO current_state FROM bloc.mfa_encryption_key_registry WHERE key_id=k;
 IF op='initialize' THEN
  IF EXISTS(SELECT FROM bloc.mfa_encryption_key_registry) THEN RETURN 'conflict'; END IF;
  INSERT INTO bloc.mfa_encryption_key_registry(key_id,state) VALUES(k,'active');
  UPDATE bloc.mfa_encryption_control SET active_key_id=k WHERE id=1;
 ELSIF op='stage' THEN
  IF c.active_key_id IS NULL OR current_state IS NOT NULL THEN RETURN 'conflict'; END IF;
  INSERT INTO bloc.mfa_encryption_key_registry(key_id,state) VALUES(k,'staged');
 ELSIF op='activate' THEN
  IF NOT confirmed OR expected<>c.generation OR current_state IS DISTINCT FROM 'staged' THEN RETURN 'conflict'; END IF;
  UPDATE bloc.mfa_encryption_key_registry SET state='decrypt_only' WHERE state='active';
  UPDATE bloc.mfa_encryption_key_registry SET state='active' WHERE key_id=k;
  UPDATE bloc.mfa_encryption_control SET active_key_id=k,generation=generation+1 WHERE id=1;
 ELSIF op='retire' THEN
  IF NOT confirmed OR expected<>c.generation OR current_state IS NULL OR current_state IN('active','retired') OR EXISTS(SELECT FROM bloc.mfa_encrypted_payload WHERE encryption_key_id=k) THEN RETURN 'conflict'; END IF;
  UPDATE bloc.mfa_encryption_key_registry SET state='retired',retired_at=clock_timestamp() WHERE key_id=k;
  UPDATE bloc.mfa_encryption_control SET generation=generation+1 WHERE id=1;
 ELSE RETURN 'invalid'; END IF;
 INSERT INTO bloc.security_audit_event(installation_id,action,outcome) VALUES(1,'mfa_key_'||op,'success');
 RETURN 'ok';
END $$;
CREATE FUNCTION bloc.mfa_reencrypt_read(source_key uuid,batch_size integer) RETURNS TABLE(id text,realm_id text,user_id text,purpose smallint,payload_version smallint,encrypted_payload bytea,revision bigint,generation bigint,active_key_id text,installation_id text) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
BEGIN
 IF batch_size NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION 'invalid batch'; END IF;
 PERFORM i.id FROM bloc.installation i WHERE i.id=1 FOR UPDATE;
 RETURN QUERY SELECT p.id::text,p.realm_id::text,p.user_id::text,p.purpose,p.payload_version,p.encrypted_payload,p.revision,c.generation,c.active_key_id::text,i.security_id::text
 FROM bloc.mfa_encrypted_payload p CROSS JOIN bloc.mfa_encryption_control c CROSS JOIN bloc.installation i
 WHERE p.encryption_key_id=source_key AND p.encryption_key_id<>c.active_key_id AND c.id=1 AND i.id=1 ORDER BY p.id LIMIT batch_size;
END $$;
CREATE FUNCTION bloc.mfa_reencrypt_commit(ids uuid[],revisions bigint[],envelopes bytea[],expected bigint,target uuid) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE c bloc.mfa_encryption_control;n integer;
BEGIN
 PERFORM id FROM bloc.installation WHERE id=1 FOR UPDATE;
 SELECT * INTO c FROM bloc.mfa_encryption_control WHERE id=1 FOR UPDATE;
 IF array_position(ids,NULL) IS NOT NULL OR array_position(revisions,NULL) IS NOT NULL OR array_position(envelopes,NULL) IS NOT NULL OR cardinality(ids)<>(SELECT count(DISTINCT x) FROM unnest(ids) x) OR cardinality(ids) NOT BETWEEN 1 AND 100 OR cardinality(revisions)<>cardinality(ids) OR cardinality(envelopes)<>cardinality(ids) THEN RETURN 'invalid'; END IF;
 IF c.generation<>expected OR c.active_key_id IS DISTINCT FROM target THEN RETURN 'conflict'; END IF;
 FOR n IN 1..cardinality(ids) LOOP
  IF NOT EXISTS(SELECT FROM bloc.mfa_encrypted_payload WHERE id=ids[n] AND revision=revisions[n] AND encryption_key_id<>target) THEN RETURN 'conflict'; END IF;
 END LOOP;
 FOR n IN 1..cardinality(ids) LOOP
  UPDATE bloc.mfa_encrypted_payload SET encryption_key_id=target,encrypted_payload=envelopes[n],revision=revision+1 WHERE id=ids[n];
 END LOOP;
 INSERT INTO bloc.security_audit_event(installation_id,action,outcome) VALUES(1,'mfa_key_reencrypt','success');
 RETURN 'ok';
END $$;
-- Append fixed action dimensions while retaining every historical action.
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_expr(conbin,conrelid) INTO definition FROM pg_constraint WHERE conrelid='bloc.security_audit_event'::regclass AND conname='security_audit_event_action_check';
 ALTER TABLE bloc.security_audit_event DROP CONSTRAINT security_audit_event_action_check;
 EXECUTE 'ALTER TABLE bloc.security_audit_event ADD CONSTRAINT security_audit_event_action_check CHECK ('||definition||' OR action IN (''mfa_key_initialize'',''mfa_key_stage'',''mfa_key_activate'',''mfa_key_retire'',''mfa_key_reencrypt''))';
END $$;
CREATE FUNCTION bloc.mfa_restore_fence() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
BEGIN
 IF NOT OLD.recovery_required AND NEW.recovery_required THEN
  DELETE FROM bloc.realm_mfa_flow;DELETE FROM bloc.realm_mfa_recovery_link;
  UPDATE bloc.realm_mfa_recovery_generation SET invalidated_at=coalesce(invalidated_at,clock_timestamp());
  UPDATE bloc.realm_user_mfa_state SET factor_epoch=factor_epoch+1,updated_at=clock_timestamp();
 ELSIF OLD.recovery_required AND NOT NEW.recovery_required THEN
  UPDATE bloc.realm_totp_factor SET last_accepted_step=greatest(last_accepted_step,floor(extract(epoch FROM clock_timestamp())/30)::bigint+1);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER mfa_restore BEFORE UPDATE OF recovery_required ON bloc.installation FOR EACH ROW EXECUTE FUNCTION bloc.mfa_restore_fence();
REVOKE ALL ON ALL TABLES IN SCHEMA bloc FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
REVOKE ALL ON FUNCTION bloc.mfa_payload_check(),bloc.mfa_factor_check(),bloc.mfa_key_status(),bloc.mfa_key_change(text,uuid,bigint,boolean),bloc.mfa_reencrypt_read(uuid,integer),bloc.mfa_reencrypt_commit(uuid[],bigint[],bytea[],bigint,uuid),bloc.mfa_restore_fence() FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
GRANT EXECUTE ON FUNCTION bloc.mfa_key_status() TO bloc_runtime,bloc_operator;
GRANT EXECUTE ON FUNCTION bloc.mfa_key_change(text,uuid,bigint,boolean),bloc.mfa_reencrypt_read(uuid,integer),bloc.mfa_reencrypt_commit(uuid[],bigint[],bytea[],bigint,uuid) TO bloc_operator;
CREATE FUNCTION bloc.mfa_state_seed() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
BEGIN INSERT INTO bloc.realm_user_mfa_state(realm_id,user_id) VALUES(NEW.realm_id,NEW.id);RETURN NEW;END $$;
CREATE TRIGGER mfa_user_seed AFTER INSERT ON bloc.realm_user FOR EACH ROW EXECUTE FUNCTION bloc.mfa_state_seed();
REVOKE ALL ON FUNCTION bloc.mfa_state_seed() FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
ALTER FUNCTION bloc.maintain_access() RENAME TO maintain_pre_mfa_access;
REVOKE ALL ON FUNCTION bloc.maintain_pre_mfa_access() FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
CREATE FUNCTION bloc.maintain_access() RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE n integer;total integer;
BEGIN
 PERFORM id FROM bloc.installation WHERE id=1 FOR UPDATE;
 DELETE FROM bloc.realm_mfa_flow WHERE id IN(SELECT id FROM bloc.realm_mfa_flow WHERE expires_at<=clock_timestamp() OR consumed_at IS NOT NULL LIMIT 1000);GET DIAGNOSTICS total=ROW_COUNT;
 DELETE FROM bloc.mfa_encrypted_payload p WHERE p.id IN(SELECT id FROM bloc.mfa_encrypted_payload q WHERE q.purpose IN(2,3) AND NOT EXISTS(SELECT FROM bloc.realm_mfa_flow f WHERE f.payload_id=q.id) LIMIT 1000);GET DIAGNOSTICS n=ROW_COUNT;total:=total+n;
 DELETE FROM bloc.realm_mfa_recovery_link WHERE (realm_id,user_id) IN(SELECT realm_id,user_id FROM bloc.realm_mfa_recovery_link WHERE expires_at<=clock_timestamp() OR consumed_at IS NOT NULL LIMIT 1000);GET DIAGNOSTICS n=ROW_COUNT;total:=total+n;
 DELETE FROM bloc.mfa_admission_bucket WHERE (scope,subject_digest) IN(SELECT scope,subject_digest FROM bloc.mfa_admission_bucket WHERE expires_at<=clock_timestamp() LIMIT 1000);
 RETURN total+bloc.maintain_pre_mfa_access();
END $$;
REVOKE ALL ON FUNCTION bloc.maintain_access() FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
GRANT EXECUTE ON FUNCTION bloc.maintain_access() TO bloc_maintenance;
CREATE FUNCTION bloc.mfa_session_compliant(s bloc.realm_user_session) RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
 SELECT s.factor_epoch=m.factor_epoch AND (p.mfa_mode='disabled' OR NOT p.mfa_recovery_codes_enabled OR NOT EXISTS(SELECT FROM bloc.realm_mfa_recovery_generation g WHERE g.realm_id=s.realm_id AND g.user_id=s.user_id AND g.invalidated_at IS NULL AND g.acknowledged_at IS NULL)) AND (p.mfa_mode='disabled' OR (p.mfa_mode='optional' AND NOT EXISTS(SELECT FROM bloc.realm_user_factor f WHERE f.realm_id=s.realm_id AND f.user_id=s.user_id AND f.revoked_at IS NULL)) OR EXISTS(SELECT FROM bloc.realm_user_factor f WHERE f.realm_id=s.realm_id AND f.user_id=s.user_id AND f.id=s.mfa_factor_id AND f.kind=s.mfa_method AND f.kind=ANY(p.mfa_allowed_methods) AND f.revoked_at IS NULL AND s.mfa_verified_at IS NOT NULL))
 FROM bloc.realm_authentication_settings p JOIN bloc.realm_user_mfa_state m USING(realm_id) WHERE p.realm_id=s.realm_id AND m.user_id=s.user_id;
$$;
ALTER FUNCTION bloc.realm_session(uuid,bytea,boolean) RENAME TO realm_session_pre_mfa;
REVOKE ALL ON FUNCTION bloc.realm_session_pre_mfa(uuid,bytea,boolean) FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
CREATE FUNCTION bloc.realm_session(r uuid,digest bytea,refresh boolean) RETURNS bloc.realm_user_session LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE s bloc.realm_user_session;
BEGIN
 s:=bloc.realm_session_pre_mfa(r,digest,false);IF s.id IS NULL THEN RETURN NULL; END IF;
 IF NOT coalesce(bloc.mfa_session_compliant(s),false) THEN
  UPDATE bloc.realm_user_session SET revoked_at=clock_timestamp() WHERE id=s.id;
  DELETE FROM bloc.realm_form_state WHERE session_id=s.id;
  RETURN NULL;
 END IF;
 RETURN bloc.realm_session_pre_mfa(r,digest,refresh);
END $$;
CREATE FUNCTION bloc.realm_mfa_noncompliant(r uuid,digest bytea) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE s bloc.realm_user_session;
BEGIN PERFORM bloc.realm_lock();SELECT * INTO s FROM bloc.realm_user_session WHERE realm_id=r AND session_digest=digest;RETURN s.id IS NOT NULL AND NOT coalesce(bloc.mfa_session_compliant(s),false);END $$;
CREATE FUNCTION bloc.realm_mfa_policy_impact(r uuid,digest bytea,mode text,methods text[]) RETURNS TABLE(enrollment bigint,stranded bigint) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
BEGIN
 PERFORM bloc.realm_lock();PERFORM bloc.directory_authority(digest);
 RETURN QUERY SELECT count(*) FILTER(WHERE mode='required' AND NOT EXISTS(SELECT FROM bloc.realm_user_factor f WHERE f.realm_id=r AND f.user_id=u.id AND f.revoked_at IS NULL)),count(*) FILTER(WHERE mode<>'disabled' AND EXISTS(SELECT FROM bloc.realm_user_factor f WHERE f.realm_id=r AND f.user_id=u.id AND f.revoked_at IS NULL) AND NOT EXISTS(SELECT FROM bloc.realm_user_factor f WHERE f.realm_id=r AND f.user_id=u.id AND f.revoked_at IS NULL AND f.kind=ANY(methods))) FROM bloc.realm_user u WHERE u.realm_id=r AND u.status='active';
END $$;
ALTER FUNCTION bloc.realm_save_settings(uuid,bytea,bytea,bytea,bigint,text[],boolean) RENAME TO realm_save_settings_pre_mfa;
REVOKE ALL ON FUNCTION bloc.realm_save_settings_pre_mfa(uuid,bytea,bytea,bytea,bigint,text[],boolean) FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
CREATE FUNCTION bloc.realm_save_settings(r uuid,digest bytea,browser bytea,token bytea,expected bigint,values_text text[],confirmed boolean) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE p bloc.realm_authentication_settings;mode text;methods text[];preferred text;codes boolean;assisted boolean;ttl integer;recovery_ttl integer;changed boolean;outcome text;aid uuid;old_changed boolean;
BEGIN
 PERFORM bloc.realm_lock();aid:=bloc.directory_authority(digest);
 IF bloc.form_state(browser,digest,NULL) IS DISTINCT FROM token OR token IS NULL THEN RETURN 'csrf'; END IF;
 SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;
 IF p.realm_id IS NULL THEN RETURN 'missing'; END IF;IF p.version<>expected THEN RETURN 'stale';END IF;
 IF cardinality(values_text)=11 THEN RETURN bloc.realm_save_settings_pre_mfa(r,digest,browser,token,expected,values_text,confirmed);END IF;
 IF cardinality(values_text)<>18 THEN RETURN 'invalid';END IF;
 BEGIN
 mode:=values_text[12];methods:=string_to_array(values_text[13],',');preferred:=nullif(values_text[14],'');codes:=values_text[15]::boolean;assisted:=values_text[16]::boolean;ttl:=values_text[17]::integer;recovery_ttl:=values_text[18]::integer;
 EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN 'invalid';END;
 IF mode NOT IN('disabled','optional','required') OR NOT methods <@ ARRAY['totp','webauthn']::text[] OR cardinality(methods)>2 OR (cardinality(methods)=2 AND NOT methods @> ARRAY['totp','webauthn']::text[]) OR (mode<>'disabled' AND cardinality(methods)=0) OR (preferred IS NOT NULL AND NOT preferred=ANY(methods)) OR ttl NOT BETWEEN 120 AND 600 OR recovery_ttl NOT BETWEEN 300 AND 3600 THEN RETURN 'invalid';END IF;
 changed:=(mode,methods,preferred,codes,assisted,ttl,recovery_ttl) IS DISTINCT FROM (p.mfa_mode,p.mfa_allowed_methods,p.mfa_preferred_method,p.mfa_recovery_codes_enabled,p.mfa_admin_recovery_enabled,p.mfa_flow_ttl_seconds,p.mfa_admin_recovery_ttl_seconds);
 IF changed AND NOT confirmed THEN RETURN 'mfa_confirm';END IF;
 outcome:=bloc.realm_save_settings_pre_mfa(r,digest,browser,token,expected,values_text[1:11],confirmed);IF outcome<>'ok' THEN RETURN outcome;END IF;
 IF changed THEN
  SELECT version<>expected INTO old_changed FROM bloc.realm_authentication_settings WHERE realm_id=r;
  UPDATE bloc.realm_authentication_settings SET mfa_mode=mode,mfa_allowed_methods=methods,mfa_preferred_method=preferred,mfa_recovery_codes_enabled=codes,mfa_admin_recovery_enabled=assisted,mfa_flow_ttl_seconds=ttl,mfa_admin_recovery_ttl_seconds=recovery_ttl,version=expected+1,updated_at=clock_timestamp() WHERE realm_id=r;
  UPDATE bloc.realm_mfa_flow SET consumed_at=coalesce(consumed_at,clock_timestamp()) WHERE realm_id=r;
  IF NOT old_changed THEN INSERT INTO bloc.security_audit_event(installation_id,administrator_id,action,outcome,realm_id) VALUES(1,aid,'realm_authentication_update','success',r);END IF;
 END IF;
 RETURN 'ok';
END $$;
REVOKE ALL ON FUNCTION bloc.mfa_session_compliant(bloc.realm_user_session),bloc.realm_session(uuid,bytea,boolean),bloc.realm_mfa_noncompliant(uuid,bytea),bloc.realm_mfa_policy_impact(uuid,bytea,text,text[]),bloc.realm_save_settings(uuid,bytea,bytea,bytea,bigint,text[],boolean) FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
GRANT EXECUTE ON FUNCTION bloc.realm_mfa_noncompliant(uuid,bytea),bloc.realm_mfa_policy_impact(uuid,bytea,text,text[]),bloc.realm_save_settings(uuid,bytea,bytea,bytea,bigint,text[],boolean) TO bloc_runtime;
ALTER TABLE bloc.realm_mfa_flow ADD COLUMN proof_verified_at timestamptz,ADD COLUMN verified_method text CHECK(verified_method IN('totp','webauthn')),ADD COLUMN label text CHECK(char_length(label) BETWEEN 1 AND 64 AND octet_length(label)<=256 AND label !~ '[[:cntrl:]]');
CREATE FUNCTION bloc.mfa_session_seed() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
BEGIN SELECT factor_epoch INTO NEW.factor_epoch FROM bloc.realm_user_mfa_state WHERE realm_id=NEW.realm_id AND user_id=NEW.user_id;IF NEW.password_verified_at IS NULL THEN NEW.password_verified_at:=NEW.created_at;END IF;RETURN NEW;END $$;
CREATE TRIGGER mfa_session_seed BEFORE INSERT ON bloc.realm_user_session FOR EACH ROW EXECUTE FUNCTION bloc.mfa_session_seed();
CREATE FUNCTION bloc.mfa_flow_capacity(r uuid,u uuid,parent boolean) RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
 SELECT (NOT parent OR (SELECT count(*) FROM bloc.realm_mfa_flow WHERE realm_id=r AND user_id=u AND parent_id IS NULL AND consumed_at IS NULL AND expires_at>clock_timestamp())<5)
 AND (SELECT count(*) FROM bloc.realm_mfa_flow WHERE realm_id=r)<1000 AND (SELECT count(*) FROM bloc.realm_mfa_flow)<10000;
$$;
CREATE FUNCTION bloc.mfa_flow_snapshot(r uuid,bearer bytea,browser bytea,token bytea) RETURNS TABLE(status text,authority bloc.realm_mfa_flow,now_seconds bigint,installation_id text) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE f bloc.realm_mfa_flow;checked timestamptz;
BEGIN
 checked:=bloc.realm_lock();now_seconds:=floor(extract(epoch FROM checked))::bigint;SELECT security_id::text INTO installation_id FROM bloc.installation WHERE id=1;
 SELECT * INTO f FROM bloc.realm_mfa_flow WHERE realm_id=r AND bearer_digest=bearer;
 IF f.id IS NULL THEN status:='expired';RETURN NEXT;RETURN;END IF;
 IF f.browser_digest IS DISTINCT FROM browser OR (token IS NOT NULL AND f.csrf_token IS DISTINCT FROM token) THEN status:='csrf';RETURN NEXT;RETURN;END IF;
 IF f.consumed_at IS NOT NULL THEN status:='consumed';RETURN NEXT;RETURN;END IF;
 IF f.expires_at<=checked THEN status:='expired';RETURN NEXT;RETURN;END IF;
 IF NOT EXISTS(SELECT FROM bloc.realm_user u JOIN bloc.realm t ON t.id=u.realm_id JOIN bloc.realm_user_credential c ON c.realm_id=u.realm_id AND c.user_id=u.id JOIN bloc.realm_user_mfa_state m ON m.realm_id=u.realm_id AND m.user_id=u.id JOIN bloc.realm_authentication_settings p ON p.realm_id=u.realm_id WHERE u.realm_id=r AND u.id=f.user_id AND u.status='active' AND t.status='active' AND c.credential_version=f.credential_version AND m.factor_epoch=f.factor_epoch AND p.version=f.policy_version AND u.version=f.user_version)
 OR (f.parent_id IS NOT NULL AND NOT EXISTS(SELECT FROM bloc.realm_mfa_flow parent WHERE parent.id=f.parent_id AND parent.consumed_at IS NULL AND parent.expires_at>checked AND parent.factor_epoch=f.factor_epoch AND parent.policy_version=f.policy_version AND parent.credential_version=f.credential_version)) THEN status:='stale';RETURN NEXT;RETURN;END IF;
 IF f.purpose='handoff' AND NOT EXISTS(SELECT FROM bloc.realm_mfa_recovery_generation g WHERE g.id=f.recovery_generation_id AND g.realm_id=r AND g.user_id=f.user_id AND g.invalidated_at IS NULL AND g.acknowledged_at IS NULL) THEN status:='stale';RETURN NEXT;RETURN;END IF;
 IF f.session_id IS NOT NULL AND NOT EXISTS(SELECT FROM bloc.realm_user_session s WHERE s.id=f.session_id AND (bloc.realm_session(r,s.session_digest,false)).id IS NOT NULL) THEN status:='stale';RETURN NEXT;RETURN;END IF;
 status:='ok';authority:=f;RETURN NEXT;
END $$;
ALTER FUNCTION bloc.realm_commit(uuid,text,bytea,bytea,bytea,bytea,uuid,bigint,bigint,text[],bytea,bytea,bytea) RENAME TO realm_commit_pre_mfa;
REVOKE ALL ON FUNCTION bloc.realm_commit_pre_mfa(uuid,text,bytea,bytea,bytea,bytea,uuid,bigint,bigint,text[],bytea,bytea,bytea) FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
CREATE FUNCTION bloc.realm_commit(r uuid,operation text,session bytea,browser bytea,token bytea,link bytea,target uuid,expected bigint,policy bigint,values_text text[],new_session bytea,new_browser bytea,new_token bytea) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE p bloc.realm_authentication_settings;checked timestamptz;u bloc.realm_user;c bloc.realm_user_credential;epoch bigint;count_active bigint;purpose_value text;
BEGIN
 checked:=bloc.realm_lock();
 IF operation<>'login' THEN RETURN bloc.realm_commit_pre_mfa(r,operation,session,browser,token,link,target,expected,policy,values_text,new_session,new_browser,new_token);END IF;
 IF NOT coalesce(bloc.realm_form_valid(r,'anonymous',browser,token,NULL,NULL),false) THEN RETURN 'csrf';END IF;
 SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;
 SELECT * INTO u FROM bloc.realm_user WHERE realm_id=r AND id=target;SELECT * INTO c FROM bloc.realm_user_credential WHERE realm_id=r AND user_id=target;
 IF u.id IS NULL OR c.credential_version IS DISTINCT FROM expected OR u.version IS DISTINCT FROM policy OR u.status<>'active' OR NOT EXISTS(SELECT FROM bloc.realm WHERE id=r AND status='active') THEN RETURN 'credentials';END IF;
 SELECT factor_epoch INTO epoch FROM bloc.realm_user_mfa_state WHERE realm_id=r AND user_id=target;
 SELECT count(*) INTO count_active FROM bloc.realm_user_factor WHERE realm_id=r AND user_id=target AND revoked_at IS NULL;
 IF p.mfa_mode='disabled' OR (p.mfa_mode='optional' AND count_active=0) THEN RETURN bloc.realm_commit_pre_mfa(r,operation,session,browser,token,link,target,expected,policy,values_text,new_session,new_browser,new_token);END IF;
 IF NOT bloc.mfa_flow_capacity(r,target,true) THEN RAISE EXCEPTION 'MFA flow capacity' USING ERRCODE='54000';END IF;
 purpose_value:=CASE WHEN count_active=0 THEN 'initial_enrollment' ELSE 'login' END;
 INSERT INTO bloc.realm_mfa_flow(realm_id,user_id,bearer_digest,browser_digest,purpose,credential_version,factor_epoch,policy_version,user_version,password_verified_at,csrf_token,created_at,expires_at)
 VALUES(r,target,new_session,browser,purpose_value,c.credential_version,epoch,p.version,u.version,checked,new_token,checked,checked+make_interval(secs=>p.mfa_flow_ttl_seconds));
 RETURN 'mfa';
END $$;
CREATE FUNCTION bloc.mfa_flow_cancel(r uuid,bearer bytea,browser bytea,token bytea) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;
BEGIN
 SELECT * INTO snapshot FROM bloc.mfa_flow_snapshot(r,bearer,browser,token);IF snapshot.status<>'ok' THEN RETURN snapshot.status;END IF;
 UPDATE bloc.realm_mfa_flow SET consumed_at=clock_timestamp() WHERE id=(snapshot.authority).id OR parent_id=(snapshot.authority).id;
 RETURN 'ok';
END $$;
REVOKE ALL ON FUNCTION bloc.mfa_session_seed(),bloc.mfa_flow_capacity(uuid,uuid,boolean),bloc.mfa_flow_snapshot(uuid,bytea,bytea,bytea),bloc.realm_commit(uuid,text,bytea,bytea,bytea,bytea,uuid,bigint,bigint,text[],bytea,bytea,bytea),bloc.mfa_flow_cancel(uuid,bytea,bytea,bytea) FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
GRANT EXECUTE ON FUNCTION bloc.mfa_flow_snapshot(uuid,bytea,bytea,bytea),bloc.realm_commit(uuid,text,bytea,bytea,bytea,bytea,uuid,bigint,bigint,text[],bytea,bytea,bytea),bloc.mfa_flow_cancel(uuid,bytea,bytea,bytea) TO bloc_runtime;
CREATE TABLE bloc.mfa_admission_bucket(scope text NOT NULL CHECK(scope IN('account','source','realm')),subject_digest bytea NOT NULL CHECK(octet_length(subject_digest)=32),admitted_at timestamptz[] NOT NULL CHECK(cardinality(admitted_at)<=300),expires_at timestamptz NOT NULL,PRIMARY KEY(scope,subject_digest));
CREATE FUNCTION bloc.mfa_admit(r uuid,bearer bytea,browser bytea,token bytea,source_key bytea) RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;f bloc.realm_mfa_flow;checked timestamptz;scope_name text;subject bytea;window_seconds integer;maximum integer;events timestamptz[];oldest timestamptz;new_keys integer:=0;
BEGIN
 SELECT * INTO snapshot FROM bloc.mfa_flow_snapshot(r,bearer,browser,token);IF snapshot.status<>'ok' THEN RETURN -2;END IF;f:=snapshot.authority;checked:=clock_timestamp();
 IF f.failed_attempts>=5 THEN RETURN 60;END IF;
 IF octet_length(source_key)<>32 THEN RETURN -2;END IF;
 FOR scope_name IN SELECT unnest(ARRAY['account','source','realm']) LOOP
  subject:=CASE scope_name WHEN 'account' THEN sha256(uuid_send(r)||uuid_send(f.user_id)) WHEN 'realm' THEN sha256(uuid_send(r)) ELSE source_key END;
  window_seconds:=CASE scope_name WHEN 'account' THEN 600 ELSE 60 END;maximum:=CASE scope_name WHEN 'account' THEN 10 WHEN 'source' THEN 30 ELSE 300 END;
  SELECT array_agg(event ORDER BY event) INTO events FROM bloc.mfa_admission_bucket b CROSS JOIN LATERAL unnest(b.admitted_at) event WHERE b.scope=scope_name AND b.subject_digest=subject AND event>checked-make_interval(secs=>window_seconds);
  IF NOT EXISTS(SELECT FROM bloc.mfa_admission_bucket b WHERE b.scope=scope_name AND b.subject_digest=subject) THEN new_keys:=new_keys+1;END IF;
  IF coalesce(cardinality(events),0)>=maximum THEN RETURN greatest(1,ceil(extract(epoch FROM events[1]+make_interval(secs=>window_seconds)-checked))::integer);END IF;
 END LOOP;
 IF (SELECT count(*) FROM bloc.mfa_admission_bucket)+new_keys>10000 THEN RETURN -1;END IF;
 FOR scope_name IN SELECT unnest(ARRAY['account','source','realm']) LOOP
  subject:=CASE scope_name WHEN 'account' THEN sha256(uuid_send(r)||uuid_send(f.user_id)) WHEN 'realm' THEN sha256(uuid_send(r)) ELSE source_key END;
  window_seconds:=CASE scope_name WHEN 'account' THEN 600 ELSE 60 END;
  SELECT coalesce(array_agg(event ORDER BY event),ARRAY[]::timestamptz[]) INTO events FROM bloc.mfa_admission_bucket b CROSS JOIN LATERAL unnest(b.admitted_at) event WHERE b.scope=scope_name AND b.subject_digest=subject AND event>checked-make_interval(secs=>window_seconds);
  INSERT INTO bloc.mfa_admission_bucket VALUES(scope_name,subject,array_append(events,checked),checked+make_interval(secs=>window_seconds)) ON CONFLICT(scope,subject_digest) DO UPDATE SET admitted_at=EXCLUDED.admitted_at,expires_at=EXCLUDED.expires_at;
 END LOOP;RETURN 0;
END $$;
CREATE FUNCTION bloc.mfa_totp_material(r uuid,bearer bytea,browser bytea,token bytea) RETURNS TABLE(factor_id text,user_id text,envelope bytea,replay_floor bigint,now_seconds bigint,installation_id text) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;
BEGIN
 SELECT * INTO snapshot FROM bloc.mfa_flow_snapshot(r,bearer,browser,token);IF snapshot.status<>'ok' OR (snapshot.authority).purpose NOT IN('login','reauthenticate') THEN RETURN;END IF;
 RETURN QUERY SELECT f.id::text,f.user_id::text,p.encrypted_payload,t.last_accepted_step,snapshot.now_seconds,snapshot.installation_id FROM bloc.realm_user_factor f JOIN bloc.realm_totp_factor t ON t.factor_id=f.id JOIN bloc.mfa_encrypted_payload p ON p.id=f.id JOIN bloc.realm_authentication_settings settings ON settings.realm_id=f.realm_id WHERE f.realm_id=r AND f.user_id=(snapshot.authority).user_id AND f.revoked_at IS NULL AND f.kind='totp' AND 'totp'=ANY(settings.mfa_allowed_methods) AND settings.mfa_mode<>'disabled';
END $$;
ALTER TABLE bloc.security_audit_event ADD COLUMN mfa_factor_id uuid,ADD FOREIGN KEY(realm_id,realm_user_id,mfa_factor_id) REFERENCES bloc.realm_user_factor(realm_id,user_id,id);
DO $$ DECLARE expression text;actions text:='''realm_mfa_sign_in'',''realm_mfa_factor_enroll'',''realm_mfa_factor_remove'',''realm_mfa_code_issue'',''realm_mfa_code_consume'',''realm_mfa_assisted_issue'',''realm_mfa_assisted_consume'',''realm_mfa_factor_label'',''realm_mfa_preference''';BEGIN
 SELECT pg_get_expr(conbin,conrelid) INTO expression FROM pg_constraint WHERE conrelid='bloc.security_audit_event'::regclass AND conname='security_audit_event_action_check';ALTER TABLE bloc.security_audit_event DROP CONSTRAINT security_audit_event_action_check;
 EXECUTE 'ALTER TABLE bloc.security_audit_event ADD CONSTRAINT security_audit_event_action_check CHECK ('||expression||' OR action IN ('||actions||'))';
 SELECT pg_get_expr(conbin,conrelid) INTO expression FROM pg_constraint WHERE conrelid='bloc.security_audit_event'::regclass AND conname='directory_target';ALTER TABLE bloc.security_audit_event DROP CONSTRAINT directory_target;
 EXECUTE 'ALTER TABLE bloc.security_audit_event ADD CONSTRAINT directory_target CHECK ('||expression||' OR (action IN ('||actions||') AND realm_id IS NOT NULL AND realm_user_id IS NOT NULL))';
END $$;
CREATE FUNCTION bloc.mfa_issue_session(r uuid,u uuid,v bigint,epoch bigint,password_at timestamptz,method text,factor uuid,digest bytea,browser bytea,token bytea,device text) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE p bloc.realm_authentication_settings;checked timestamptz;sid uuid;
BEGIN
 checked:=bloc.realm_lock();SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;
 IF (SELECT count(*) FROM bloc.realm_user_session)>=100000 THEN RAISE EXCEPTION 'capacity' USING ERRCODE='54000';END IF;
 UPDATE bloc.realm_user_session SET revoked_at=checked WHERE id IN(SELECT id FROM bloc.realm_user_session WHERE realm_id=r AND user_id=u AND revoked_at IS NULL ORDER BY created_at DESC,id DESC OFFSET (p.session_limit-1));
 DELETE FROM bloc.realm_form_state f USING bloc.realm_user_session s WHERE f.session_id=s.id AND s.realm_id=r AND s.user_id=u AND s.revoked_at IS NOT NULL;
 INSERT INTO bloc.realm_user_session(realm_id,user_id,session_digest,credential_version,created_at,last_activity_at,expires_at,device_label,factor_epoch,password_verified_at,mfa_method,mfa_factor_id,mfa_verified_at) VALUES(r,u,digest,v,checked,checked,checked+make_interval(secs=>least(p.session_idle_seconds,p.session_absolute_seconds)),device,epoch,password_at,method,factor,CASE WHEN method IS NULL THEN NULL ELSE checked END) RETURNING id INTO sid;
 IF bloc.realm_form(r,'account',browser,digest,NULL,token) IS NULL THEN RAISE EXCEPTION 'form capacity' USING ERRCODE='54000';END IF;RETURN sid;
END $$;
CREATE OR REPLACE FUNCTION bloc.mfa_session_seed() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
BEGIN SELECT factor_epoch INTO NEW.factor_epoch FROM bloc.realm_user_mfa_state WHERE realm_id=NEW.realm_id AND user_id=NEW.user_id;IF NEW.password_verified_at IS NULL THEN NEW.password_verified_at:=NEW.created_at;END IF;RETURN NEW;END $$;
CREATE FUNCTION bloc.mfa_verify_commit(r uuid,bearer bytea,browser bytea,token bytea,factor uuid,step bigint,verified boolean,new_session bytea,new_browser bytea,new_token bytea,device text) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;f bloc.realm_mfa_flow;checked timestamptz;accepted boolean;
BEGIN
 SELECT * INTO snapshot FROM bloc.mfa_flow_snapshot(r,bearer,browser,token);IF snapshot.status<>'ok' THEN RETURN snapshot.status;END IF;f:=snapshot.authority;checked:=clock_timestamp();
 IF f.purpose NOT IN('login','reauthenticate') THEN RETURN 'authority';END IF;
 accepted:=verified AND step BETWEEN floor(extract(epoch FROM checked)/30)::bigint-1 AND floor(extract(epoch FROM checked)/30)::bigint+1 AND EXISTS(SELECT FROM bloc.realm_user_factor a JOIN bloc.realm_totp_factor t ON t.factor_id=a.id JOIN bloc.realm_authentication_settings p ON p.realm_id=a.realm_id WHERE a.id=factor AND a.realm_id=r AND a.user_id=f.user_id AND a.kind='totp' AND a.revoked_at IS NULL AND p.mfa_mode<>'disabled' AND 'totp'=ANY(p.mfa_allowed_methods) AND t.last_accepted_step<step);
 IF NOT coalesce(accepted,false) THEN
  UPDATE bloc.realm_mfa_flow SET failed_attempts=least(5,failed_attempts+1),consumed_at=CASE WHEN failed_attempts>=4 THEN checked ELSE consumed_at END WHERE id=f.id RETURNING * INTO f;
  RETURN CASE WHEN f.failed_attempts>=5 THEN 'limited' ELSE 'invalid' END;
 END IF;
 UPDATE bloc.realm_totp_factor SET last_accepted_step=step WHERE factor_id=factor;
 UPDATE bloc.realm_user_factor SET last_used_at=checked WHERE id=factor;
 IF f.purpose='reauthenticate' THEN
  UPDATE bloc.realm_mfa_flow SET proof_verified_at=checked,verified_method='totp',factor_id=factor WHERE id=f.id;RETURN 'reauthenticated';
 END IF;
 IF EXISTS(SELECT FROM bloc.realm_authentication_settings WHERE realm_id=r AND mfa_recovery_codes_enabled) AND EXISTS(SELECT FROM bloc.realm_mfa_recovery_generation WHERE realm_id=r AND user_id=f.user_id AND invalidated_at IS NULL AND acknowledged_at IS NULL) THEN UPDATE bloc.realm_mfa_flow SET proof_verified_at=checked,verified_method='totp',factor_id=factor WHERE id=f.id;RETURN 'handoff_required';END IF;
 UPDATE bloc.realm_mfa_flow SET consumed_at=checked WHERE id=f.id;
 PERFORM bloc.mfa_issue_session(r,f.user_id,f.credential_version,f.factor_epoch,f.password_verified_at,'totp',factor,new_session,new_browser,new_token,device);
 INSERT INTO bloc.security_audit_event(installation_id,action,outcome,realm_id,realm_user_id,actor_realm_id,actor_user_id,mfa_factor_id) VALUES(1,'realm_mfa_sign_in','success',r,f.user_id,r,f.user_id,factor);
 RETURN 'ok';
END $$;
REVOKE ALL ON TABLE bloc.mfa_admission_bucket FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
REVOKE ALL ON FUNCTION bloc.mfa_admit(uuid,bytea,bytea,bytea,bytea),bloc.mfa_totp_material(uuid,bytea,bytea,bytea),bloc.mfa_issue_session(uuid,uuid,bigint,bigint,timestamptz,text,uuid,bytea,bytea,bytea,text),bloc.mfa_verify_commit(uuid,bytea,bytea,bytea,uuid,bigint,boolean,bytea,bytea,bytea,text) FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
GRANT EXECUTE ON FUNCTION bloc.mfa_admit(uuid,bytea,bytea,bytea,bytea),bloc.mfa_totp_material(uuid,bytea,bytea,bytea),bloc.mfa_verify_commit(uuid,bytea,bytea,bytea,uuid,bigint,boolean,bytea,bytea,bytea,text) TO bloc_runtime;
ALTER TABLE bloc.realm_mfa_flow ADD FOREIGN KEY(realm_id,user_id,payload_id) REFERENCES bloc.mfa_encrypted_payload(realm_id,user_id,id),ADD CONSTRAINT mfa_operation_bound CHECK(octet_length(operation)<=128);
CREATE FUNCTION bloc.mfa_totp_start(r uuid,bearer bytea,browser bytea,token bytea,payload uuid,envelope bytea,key_id uuid,generation bigint,new_bearer bytea,new_csrf bytea) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;f bloc.realm_mfa_flow;p bloc.realm_authentication_settings;old_factor uuid;checked timestamptz;c bloc.mfa_encryption_control;
BEGIN
 SELECT * INTO snapshot FROM bloc.mfa_flow_snapshot(r,bearer,browser,token);IF snapshot.status<>'ok' THEN RETURN snapshot.status;END IF;f:=snapshot.authority;checked:=clock_timestamp();
 SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;
 IF p.mfa_mode='disabled' OR NOT 'totp'=ANY(p.mfa_allowed_methods) THEN RETURN 'authority';END IF;
 SELECT id INTO old_factor FROM bloc.realm_user_factor WHERE realm_id=r AND user_id=f.user_id AND kind='totp' AND revoked_at IS NULL;
 IF f.purpose='initial_enrollment' THEN
  IF EXISTS(SELECT FROM bloc.realm_user_factor WHERE realm_id=r AND user_id=f.user_id AND revoked_at IS NULL) THEN RETURN 'stale';END IF;
 ELSIF f.purpose='reauthenticate' THEN
  IF f.proof_verified_at IS NULL OR f.password_verified_at<checked-interval '5 minutes' OR f.operation IS DISTINCT FROM (CASE WHEN old_factor IS NULL THEN 'totp_enroll' ELSE 'totp_replace:'||old_factor::text END) THEN RETURN 'authority';END IF;
 ELSIF f.purpose<>'recovery' THEN RETURN 'authority';END IF;
 SELECT * INTO c FROM bloc.mfa_encryption_control WHERE id=1;
 IF c.generation<>generation OR c.active_key_id IS DISTINCT FROM key_id THEN RETURN 'key_conflict';END IF;
 IF NOT bloc.mfa_flow_capacity(r,f.user_id,false) THEN RAISE EXCEPTION 'MFA flow capacity' USING ERRCODE='54000';END IF;
 INSERT INTO bloc.mfa_encrypted_payload(id,realm_id,user_id,purpose,encryption_key_id,encrypted_payload) VALUES(payload,r,f.user_id,2,key_id,envelope);
 INSERT INTO bloc.realm_mfa_flow(realm_id,user_id,bearer_digest,browser_digest,purpose,operation,credential_version,factor_epoch,policy_version,user_version,password_verified_at,parent_id,session_id,csrf_token,payload_id,created_at,expires_at,label)
 VALUES(r,f.user_id,new_bearer,browser,'totp_enrollment',f.operation,f.credential_version,f.factor_epoch,f.policy_version,f.user_version,f.password_verified_at,f.id,f.session_id,new_csrf,payload,checked,f.expires_at,'Authenticator app');
 RETURN 'ok';
END $$;
CREATE FUNCTION bloc.mfa_totp_pending(r uuid,bearer bytea,browser bytea,token bytea) RETURNS TABLE(factor_id text,user_id text,envelope bytea,replay_floor bigint,now_seconds bigint,installation_id text) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;
BEGIN
 SELECT * INTO snapshot FROM bloc.mfa_flow_snapshot(r,bearer,browser,token);IF snapshot.status<>'ok' OR (snapshot.authority).purpose<>'totp_enrollment' THEN RETURN;END IF;
 RETURN QUERY SELECT p.id::text,p.user_id::text,p.encrypted_payload,-1::bigint,snapshot.now_seconds,snapshot.installation_id FROM bloc.mfa_encrypted_payload p WHERE p.realm_id=r AND p.user_id=(snapshot.authority).user_id AND p.id=(snapshot.authority).payload_id AND p.purpose=2;
END $$;
REVOKE ALL ON FUNCTION bloc.mfa_totp_start(uuid,bytea,bytea,bytea,uuid,bytea,uuid,bigint,bytea,bytea),bloc.mfa_totp_pending(uuid,bytea,bytea,bytea) FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
GRANT EXECUTE ON FUNCTION bloc.mfa_totp_start(uuid,bytea,bytea,bytea,uuid,bytea,uuid,bigint,bytea,bytea),bloc.mfa_totp_pending(uuid,bytea,bytea,bytea) TO bloc_runtime;
ALTER TABLE bloc.realm_mfa_flow ADD FOREIGN KEY(recovery_generation_id) REFERENCES bloc.realm_mfa_recovery_generation;
CREATE FUNCTION bloc.mfa_reject(flow uuid) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE parent uuid;failed integer;checked timestamptz;
BEGIN
 checked:=clock_timestamp();SELECT coalesce(parent_id,id) INTO parent FROM bloc.realm_mfa_flow WHERE id=flow;
 UPDATE bloc.realm_mfa_flow SET failed_attempts=least(5,failed_attempts+1) WHERE id=parent RETURNING failed_attempts INTO failed;
 IF flow<>parent THEN UPDATE bloc.realm_mfa_flow SET failed_attempts=least(5,failed_attempts+1) WHERE id=flow;END IF;
 IF failed>=5 THEN UPDATE bloc.realm_mfa_flow SET consumed_at=coalesce(consumed_at,checked) WHERE id=parent OR parent_id=parent;RETURN 'limited';END IF;RETURN 'invalid';
END $$;
CREATE FUNCTION bloc.mfa_complete_enrollment(f bloc.realm_mfa_flow,method text,factor uuid,generation_id uuid,digests bytea[],handoff_id uuid,handoff_envelope bytea,key_id uuid,new_bearer bytea,new_csrf bytea,new_session bytea,new_browser bytea,new_token bytea,device text) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE checked timestamptz;p bloc.realm_authentication_settings;parent_purpose text;epoch bigint;handoff boolean;n integer;
BEGIN
 checked:=clock_timestamp();SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=f.realm_id;SELECT purpose INTO parent_purpose FROM bloc.realm_mfa_flow WHERE id=f.parent_id;
 IF parent_purpose='recovery' THEN
  UPDATE bloc.realm_user_factor SET revoked_at=checked WHERE realm_id=f.realm_id AND user_id=f.user_id AND id<>factor AND revoked_at IS NULL;
  UPDATE bloc.realm_mfa_recovery_generation SET invalidated_at=coalesce(invalidated_at,checked) WHERE realm_id=f.realm_id AND user_id=f.user_id;
 END IF;
 UPDATE bloc.realm_user_mfa_state s SET factor_epoch=s.factor_epoch+1,updated_at=checked,preferred_factor_id=CASE WHEN EXISTS(SELECT FROM bloc.realm_user_factor a WHERE a.id=s.preferred_factor_id AND a.revoked_at IS NULL) THEN s.preferred_factor_id ELSE factor END WHERE s.realm_id=f.realm_id AND s.user_id=f.user_id RETURNING factor_epoch INTO epoch;
 UPDATE bloc.realm_mfa_flow SET consumed_at=coalesce(consumed_at,checked) WHERE realm_id=f.realm_id AND user_id=f.user_id;
 UPDATE bloc.realm_user_session SET revoked_at=checked WHERE realm_id=f.realm_id AND user_id=f.user_id AND revoked_at IS NULL;
 DELETE FROM bloc.realm_form_state WHERE session_id IN(SELECT id FROM bloc.realm_user_session WHERE realm_id=f.realm_id AND user_id=f.user_id);
 DELETE FROM bloc.realm_mfa_recovery_link WHERE realm_id=f.realm_id AND user_id=f.user_id;
 handoff:=p.mfa_recovery_codes_enabled AND NOT EXISTS(SELECT FROM bloc.realm_mfa_recovery_generation WHERE realm_id=f.realm_id AND user_id=f.user_id AND invalidated_at IS NULL AND acknowledged_at IS NOT NULL);
 INSERT INTO bloc.security_audit_event(installation_id,action,outcome,realm_id,realm_user_id,actor_realm_id,actor_user_id,mfa_factor_id) VALUES(1,'realm_mfa_factor_enroll','success',f.realm_id,f.user_id,f.realm_id,f.user_id,factor);
 IF handoff THEN
  PERFORM bloc.mfa_create_handoff(f,epoch,method,factor,generation_id,digests,handoff_id,handoff_envelope,key_id,new_bearer,new_csrf);
  RETURN 'handoff';
 END IF;
 PERFORM bloc.mfa_issue_session(f.realm_id,f.user_id,f.credential_version,epoch,f.password_verified_at,method,factor,new_session,new_browser,new_token,device);
 INSERT INTO bloc.security_audit_event(installation_id,action,outcome,realm_id,realm_user_id,actor_realm_id,actor_user_id,mfa_factor_id) VALUES(1,'realm_mfa_sign_in','success',f.realm_id,f.user_id,f.realm_id,f.user_id,factor);
 RETURN 'ok';
END $$;
CREATE FUNCTION bloc.mfa_totp_confirm(r uuid,bearer bytea,browser bytea,token bytea,step bigint,verified boolean,active_envelope bytea,key_id uuid,key_generation bigint,generation_id uuid,digests bytea[],handoff_id uuid,handoff_envelope bytea,new_bearer bytea,new_csrf bytea,new_session bytea,new_browser bytea,new_token bytea,device text) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;f bloc.realm_mfa_flow;p bloc.realm_authentication_settings;c bloc.mfa_encryption_control;checked timestamptz;
BEGIN
 SELECT * INTO snapshot FROM bloc.mfa_flow_snapshot(r,bearer,browser,token);IF snapshot.status<>'ok' THEN RETURN snapshot.status;END IF;f:=snapshot.authority;checked:=clock_timestamp();
 SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;
 IF f.purpose<>'totp_enrollment' OR f.payload_id IS NULL OR p.mfa_mode='disabled' OR NOT 'totp'=ANY(p.mfa_allowed_methods) THEN RETURN 'authority';END IF;
 IF NOT coalesce(verified AND step BETWEEN floor(extract(epoch FROM checked)/30)::bigint-1 AND floor(extract(epoch FROM checked)/30)::bigint+1,false) THEN RETURN bloc.mfa_reject(f.id);END IF;
 SELECT * INTO c FROM bloc.mfa_encryption_control WHERE id=1;IF c.generation<>key_generation OR c.active_key_id IS DISTINCT FROM key_id THEN RETURN 'key_conflict';END IF;
 IF NOT EXISTS(SELECT FROM bloc.mfa_encrypted_payload WHERE id=f.payload_id AND realm_id=r AND user_id=f.user_id AND purpose=2) THEN RETURN 'stale';END IF;
 UPDATE bloc.realm_user_factor SET revoked_at=checked WHERE realm_id=r AND user_id=f.user_id AND kind='totp' AND revoked_at IS NULL;
 UPDATE bloc.mfa_encrypted_payload SET purpose=1,encryption_key_id=key_id,encrypted_payload=active_envelope WHERE id=f.payload_id;
 INSERT INTO bloc.realm_user_factor(id,realm_id,user_id,kind,label,last_used_at) VALUES(f.payload_id,r,f.user_id,'totp',f.label,checked);
 INSERT INTO bloc.realm_totp_factor(factor_id,realm_id,user_id,last_accepted_step) VALUES(f.payload_id,r,f.user_id,step);
 RETURN bloc.mfa_complete_enrollment(f,'totp',f.payload_id,generation_id,digests,handoff_id,handoff_envelope,key_id,new_bearer,new_csrf,new_session,new_browser,new_token,device);
END $$;
CREATE FUNCTION bloc.mfa_handoff_present(r uuid,bearer bytea,browser bytea) RETURNS TABLE(status text,payload_id text,envelope bytea,user_id text,installation_id text) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;f bloc.realm_mfa_flow;payload bloc.mfa_encrypted_payload;
BEGIN
 SELECT * INTO snapshot FROM bloc.mfa_flow_snapshot(r,bearer,browser,NULL);IF snapshot.status<>'ok' THEN status:=snapshot.status;RETURN NEXT;RETURN;END IF;f:=snapshot.authority;
 IF f.purpose<>'handoff' THEN status:='authority';RETURN NEXT;RETURN;END IF;
 SELECT * INTO payload FROM bloc.mfa_encrypted_payload ep WHERE ep.id=f.payload_id AND ep.realm_id=r AND ep.user_id=f.user_id AND ep.purpose=3;
 IF payload.id IS NULL THEN status:='lost';RETURN NEXT;RETURN;END IF;
 status:='ok';payload_id:=payload.id::text;envelope:=payload.encrypted_payload;user_id:=f.user_id::text;installation_id:=snapshot.installation_id;
 UPDATE bloc.realm_mfa_flow SET payload_id=NULL WHERE id=f.id;DELETE FROM bloc.mfa_encrypted_payload WHERE id=payload.id;RETURN NEXT;
END $$;
CREATE FUNCTION bloc.mfa_handoff_ack(r uuid,bearer bytea,browser bytea,token bytea,saved boolean,new_session bytea,new_browser bytea,new_token bytea,device text) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;f bloc.realm_mfa_flow;checked timestamptz;
BEGIN
 SELECT * INTO snapshot FROM bloc.mfa_flow_snapshot(r,bearer,browser,token);IF snapshot.status<>'ok' THEN RETURN snapshot.status;END IF;f:=snapshot.authority;checked:=clock_timestamp();
 IF f.purpose<>'handoff' OR f.proof_verified_at IS NULL OR f.factor_id IS NULL OR f.verified_method IS NULL THEN RETURN 'authority';END IF;
 IF NOT saved THEN RETURN 'invalid';END IF;
 UPDATE bloc.realm_mfa_recovery_generation SET acknowledged_at=checked WHERE id=f.recovery_generation_id AND realm_id=r AND user_id=f.user_id AND invalidated_at IS NULL AND acknowledged_at IS NULL;IF NOT FOUND THEN RETURN 'stale';END IF;
 UPDATE bloc.realm_mfa_flow SET consumed_at=checked,payload_id=NULL WHERE id=f.id;DELETE FROM bloc.mfa_encrypted_payload WHERE id=f.payload_id;
 PERFORM bloc.mfa_issue_session(r,f.user_id,f.credential_version,f.factor_epoch,f.password_verified_at,f.verified_method,f.factor_id,new_session,new_browser,new_token,device);
 UPDATE bloc.realm_user_session SET mfa_verified_at=f.proof_verified_at WHERE realm_id=r AND session_digest=new_session;
 INSERT INTO bloc.security_audit_event(installation_id,action,outcome,realm_id,realm_user_id,actor_realm_id,actor_user_id,mfa_factor_id) VALUES(1,'realm_mfa_sign_in','success',r,f.user_id,r,f.user_id,f.factor_id);
 RETURN 'ok';
END $$;
REVOKE ALL ON FUNCTION bloc.mfa_reject(uuid),bloc.mfa_complete_enrollment(bloc.realm_mfa_flow,text,uuid,uuid,bytea[],uuid,bytea,uuid,bytea,bytea,bytea,bytea,bytea,text),bloc.mfa_totp_confirm(uuid,bytea,bytea,bytea,bigint,boolean,bytea,uuid,bigint,uuid,bytea[],uuid,bytea,bytea,bytea,bytea,bytea,bytea,text),bloc.mfa_handoff_present(uuid,bytea,bytea),bloc.mfa_handoff_ack(uuid,bytea,bytea,bytea,boolean,bytea,bytea,bytea,text) FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
GRANT EXECUTE ON FUNCTION bloc.mfa_totp_confirm(uuid,bytea,bytea,bytea,bigint,boolean,bytea,uuid,bigint,uuid,bytea[],uuid,bytea,bytea,bytea,bytea,bytea,bytea,text),bloc.mfa_handoff_present(uuid,bytea,bytea),bloc.mfa_handoff_ack(uuid,bytea,bytea,bytea,boolean,bytea,bytea,bytea,text) TO bloc_runtime;
CREATE FUNCTION bloc.mfa_create_handoff(f bloc.realm_mfa_flow,epoch bigint,method text,factor uuid,generation_id uuid,digests bytea[],handoff_id uuid,handoff_envelope bytea,key_id uuid,new_bearer bytea,new_csrf bytea) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE checked timestamptz;n integer;
BEGIN
 checked:=clock_timestamp();
 IF NOT bloc.mfa_flow_capacity(f.realm_id,f.user_id,true) THEN RAISE EXCEPTION 'MFA flow capacity' USING ERRCODE='54000';END IF;
 IF cardinality(digests) IS DISTINCT FROM 10 OR EXISTS(SELECT FROM unnest(digests) digest WHERE octet_length(digest)<>32 OR digest IS NULL) THEN RAISE EXCEPTION 'invalid recovery generation';END IF;
 UPDATE bloc.realm_mfa_recovery_generation SET invalidated_at=coalesce(invalidated_at,checked) WHERE realm_id=f.realm_id AND user_id=f.user_id;
 INSERT INTO bloc.realm_mfa_recovery_generation(id,realm_id,user_id) VALUES(generation_id,f.realm_id,f.user_id);
 FOR n IN 1..10 LOOP INSERT INTO bloc.realm_mfa_recovery_code(generation_id,ordinal,code_digest) VALUES(generation_id,n,digests[n]);END LOOP;
 INSERT INTO bloc.mfa_encrypted_payload(id,realm_id,user_id,purpose,encryption_key_id,encrypted_payload) VALUES(handoff_id,f.realm_id,f.user_id,3,key_id,handoff_envelope);
 INSERT INTO bloc.realm_mfa_flow(id,realm_id,user_id,bearer_digest,browser_digest,purpose,credential_version,factor_epoch,policy_version,user_version,password_verified_at,factor_id,csrf_token,payload_id,created_at,expires_at,proof_verified_at,verified_method,recovery_generation_id)
 VALUES(handoff_id,f.realm_id,f.user_id,new_bearer,f.browser_digest,'handoff',f.credential_version,epoch,f.policy_version,f.user_version,f.password_verified_at,factor,new_csrf,handoff_id,checked,f.expires_at,coalesce(f.proof_verified_at,checked),method,generation_id);
 INSERT INTO bloc.security_audit_event(installation_id,action,outcome,realm_id,realm_user_id,actor_realm_id,actor_user_id) VALUES(1,'realm_mfa_code_issue','success',f.realm_id,f.user_id,f.realm_id,f.user_id);
END $$;
CREATE FUNCTION bloc.mfa_replace_handoff(r uuid,bearer bytea,browser bytea,token bytea,generation_id uuid,digests bytea[],handoff_id uuid,handoff_envelope bytea,key_id uuid,key_generation bigint,new_bearer bytea,new_csrf bytea,new_session bytea,new_browser bytea,new_token bytea,device text) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;f bloc.realm_mfa_flow;p bloc.realm_authentication_settings;c bloc.mfa_encryption_control;checked timestamptz;
BEGIN
 SELECT * INTO snapshot FROM bloc.mfa_flow_snapshot(r,bearer,browser,token);IF snapshot.status<>'ok' THEN RETURN snapshot.status;END IF;f:=snapshot.authority;checked:=clock_timestamp();
 SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;
 IF f.purpose NOT IN('handoff','login') OR f.proof_verified_at IS NULL OR f.factor_id IS NULL OR f.verified_method IS NULL OR NOT EXISTS(SELECT FROM bloc.realm_user_factor WHERE id=f.factor_id AND realm_id=r AND user_id=f.user_id AND revoked_at IS NULL AND kind=f.verified_method AND kind=ANY(p.mfa_allowed_methods)) THEN RETURN 'authority';END IF;
 IF f.purpose='login' AND (NOT p.mfa_recovery_codes_enabled OR NOT EXISTS(SELECT FROM bloc.realm_mfa_recovery_generation WHERE realm_id=r AND user_id=f.user_id AND invalidated_at IS NULL AND acknowledged_at IS NULL)) THEN
  UPDATE bloc.realm_mfa_flow SET consumed_at=checked WHERE id=f.id;
  PERFORM bloc.mfa_issue_session(r,f.user_id,f.credential_version,f.factor_epoch,f.password_verified_at,f.verified_method,f.factor_id,new_session,new_browser,new_token,device);
 UPDATE bloc.realm_user_session SET mfa_verified_at=f.proof_verified_at WHERE realm_id=r AND session_digest=new_session;
  INSERT INTO bloc.security_audit_event(installation_id,action,outcome,realm_id,realm_user_id,actor_realm_id,actor_user_id,mfa_factor_id) VALUES(1,'realm_mfa_sign_in','success',r,f.user_id,r,f.user_id,f.factor_id);RETURN 'ok';
 END IF;
 IF NOT p.mfa_recovery_codes_enabled THEN RETURN 'authority';END IF;
 SELECT * INTO c FROM bloc.mfa_encryption_control WHERE id=1;IF c.generation<>key_generation OR c.active_key_id IS DISTINCT FROM key_id THEN RETURN 'key_conflict';END IF;
 UPDATE bloc.realm_mfa_flow SET consumed_at=checked,payload_id=NULL WHERE id=f.id OR parent_id=f.id;
 DELETE FROM bloc.mfa_encrypted_payload WHERE id=f.payload_id AND purpose=3;
 PERFORM bloc.mfa_create_handoff(f,f.factor_epoch,f.verified_method,f.factor_id,generation_id,digests,handoff_id,handoff_envelope,key_id,new_bearer,new_csrf);
 RETURN 'handoff';
END $$;
REVOKE ALL ON FUNCTION bloc.mfa_create_handoff(bloc.realm_mfa_flow,bigint,text,uuid,uuid,bytea[],uuid,bytea,uuid,bytea,bytea),bloc.mfa_replace_handoff(uuid,bytea,bytea,bytea,uuid,bytea[],uuid,bytea,uuid,bigint,bytea,bytea,bytea,bytea,bytea,text) FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
GRANT EXECUTE ON FUNCTION bloc.mfa_replace_handoff(uuid,bytea,bytea,bytea,uuid,bytea[],uuid,bytea,uuid,bigint,bytea,bytea,bytea,bytea,bytea,text) TO bloc_runtime;
