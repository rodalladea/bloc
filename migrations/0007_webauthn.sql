-- WebAuthn library state is private authority; public ceremony UUIDs never act as bearers.
CREATE FUNCTION bloc.mfa_webauthn_parent(r uuid,bearer bytea,browser bytea,token bytea) RETURNS bloc.realm_mfa_flow LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;f bloc.realm_mfa_flow;
BEGIN
 IF token IS NULL OR octet_length(token)<>32 THEN RETURN NULL;END IF;
 SELECT * INTO snapshot FROM bloc.mfa_flow_snapshot(r,bearer,browser,token);
 IF snapshot.status<>'ok' THEN RETURN NULL;END IF;f:=snapshot.authority;
 IF f.parent_id IS NOT NULL THEN SELECT * INTO f FROM bloc.realm_mfa_flow WHERE id=f.parent_id;END IF;
 IF f.purpose NOT IN('initial_enrollment','login','reauthenticate','recovery') THEN RETURN NULL;END IF;
 RETURN f;
END $$;
CREATE FUNCTION bloc.mfa_webauthn_reject(r uuid,bearer bytea,browser bytea,token bytea) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE f bloc.realm_mfa_flow;
BEGIN
 f:=bloc.mfa_webauthn_parent(r,bearer,browser,token);
 IF f.id IS NULL THEN RETURN 'stale';END IF;
 RETURN bloc.mfa_reject(f.id);
END $$;
CREATE FUNCTION bloc.mfa_webauthn_eligible(f bloc.realm_mfa_flow,registration boolean) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE checked timestamptz;p bloc.realm_authentication_settings;target uuid;
BEGIN
 checked:=clock_timestamp();SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=f.realm_id;
 IF f.id IS NULL OR p.mfa_mode='disabled' OR NOT 'webauthn'=ANY(p.mfa_allowed_methods) THEN RETURN false;END IF;
 IF NOT registration THEN RETURN f.purpose IN('login','reauthenticate') AND EXISTS(SELECT FROM bloc.realm_user_factor WHERE realm_id=f.realm_id AND user_id=f.user_id AND kind='webauthn' AND revoked_at IS NULL);END IF;
 IF f.purpose='initial_enrollment' THEN RETURN NOT EXISTS(SELECT FROM bloc.realm_user_factor WHERE realm_id=f.realm_id AND user_id=f.user_id AND revoked_at IS NULL);
 ELSIF f.purpose='recovery' THEN RETURN true;
 ELSIF f.purpose='reauthenticate' AND f.proof_verified_at IS NOT NULL AND f.proof_verified_at>=checked-interval '5 minutes' AND f.password_verified_at>=checked-interval '5 minutes' THEN
  IF f.operation='webauthn_enroll' THEN RETURN (SELECT count(*) FROM bloc.realm_user_factor WHERE realm_id=f.realm_id AND user_id=f.user_id AND kind='webauthn' AND revoked_at IS NULL)<10;END IF;
  IF f.operation ~ '^webauthn_replace:[0-9a-f-]{36}$' THEN
   target:=substring(f.operation FROM 18)::uuid;
   RETURN EXISTS(SELECT FROM bloc.realm_user_factor WHERE realm_id=f.realm_id AND user_id=f.user_id AND id=target AND kind='webauthn' AND revoked_at IS NULL);
  END IF;
 END IF;RETURN false;
END $$;
CREATE FUNCTION bloc.mfa_webauthn_material(r uuid,bearer bytea,browser bytea,token bytea,registration boolean,new_handle bytea) RETURNS TABLE(user_handle bytea,credential_ids bytea[],public_records bytea[]) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE f bloc.realm_mfa_flow;
BEGIN
 f:=bloc.mfa_webauthn_parent(r,bearer,browser,token);IF NOT bloc.mfa_webauthn_eligible(f,registration) THEN RETURN;END IF;
 IF registration THEN INSERT INTO bloc.realm_webauthn_identity(realm_id,user_id,user_handle) VALUES(r,f.user_id,new_handle) ON CONFLICT(realm_id,user_id) DO NOTHING;END IF;
 SELECT i.user_handle INTO user_handle FROM bloc.realm_webauthn_identity i WHERE i.realm_id=r AND i.user_id=f.user_id;
 IF user_handle IS NULL THEN RETURN;END IF;
 SELECT coalesce(array_agg(w.credential_id ORDER BY w.factor_id),'{}'::bytea[]),coalesce(array_agg(w.public_credential ORDER BY w.factor_id),'{}'::bytea[]) INTO credential_ids,public_records FROM bloc.realm_webauthn_factor w JOIN bloc.realm_user_factor a ON a.id=w.factor_id WHERE w.realm_id=r AND w.user_id=f.user_id AND a.revoked_at IS NULL;
 RETURN NEXT;
END $$;
CREATE FUNCTION bloc.mfa_webauthn_start(r uuid,bearer bytea,browser bytea,token bytea,registration boolean,ceremony uuid,child_bearer bytea,state bytea,label text) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE f bloc.realm_mfa_flow;checked timestamptz;
BEGIN
 f:=bloc.mfa_webauthn_parent(r,bearer,browser,token);IF NOT bloc.mfa_webauthn_eligible(f,registration) THEN RETURN 'authority';END IF;checked:=clock_timestamp();
 IF registration AND (label IS NULL OR char_length(label) NOT BETWEEN 1 AND 64 OR octet_length(label)>256 OR label ~ '[[:cntrl:]]') THEN RETURN 'invalid';END IF;
 IF NOT bloc.mfa_flow_capacity(r,f.user_id,false) THEN RAISE EXCEPTION 'MFA flow capacity' USING ERRCODE='54000';END IF;
 INSERT INTO bloc.realm_mfa_flow(id,realm_id,user_id,bearer_digest,browser_digest,purpose,operation,credential_version,factor_epoch,policy_version,user_version,password_verified_at,parent_id,session_id,csrf_token,server_state,created_at,expires_at,label)
 VALUES(ceremony,r,f.user_id,child_bearer,browser,CASE WHEN registration THEN 'webauthn_registration' ELSE 'webauthn_authentication' END,f.operation,f.credential_version,f.factor_epoch,f.policy_version,f.user_version,f.password_verified_at,f.id,f.session_id,f.csrf_token,state,checked,least(f.expires_at,checked+interval '300 seconds'),CASE WHEN registration THEN label ELSE NULL END);
 RETURN 'ok';
END $$;
CREATE FUNCTION bloc.mfa_webauthn_ceremony(r uuid,bearer bytea,browser bytea,token bytea,ceremony uuid,registration boolean) RETURNS TABLE(state bytea,user_handle bytea,public_records bytea[]) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE f bloc.realm_mfa_flow;child bloc.realm_mfa_flow;
BEGIN
 f:=bloc.mfa_webauthn_parent(r,bearer,browser,token);IF NOT bloc.mfa_webauthn_eligible(f,registration) THEN RETURN;END IF;
 SELECT * INTO child FROM bloc.realm_mfa_flow WHERE id=ceremony AND realm_id=r AND user_id=f.user_id AND parent_id=f.id AND consumed_at IS NULL AND expires_at>clock_timestamp() AND purpose=CASE WHEN registration THEN 'webauthn_registration' ELSE 'webauthn_authentication' END;
 IF child.id IS NULL THEN RETURN;END IF;
 state:=child.server_state;SELECT i.user_handle INTO user_handle FROM bloc.realm_webauthn_identity i WHERE i.realm_id=r AND i.user_id=f.user_id;
 SELECT coalesce(array_agg(w.public_credential ORDER BY w.factor_id),'{}'::bytea[]) INTO public_records FROM bloc.realm_webauthn_factor w JOIN bloc.realm_user_factor a ON a.id=w.factor_id WHERE w.realm_id=r AND w.user_id=f.user_id AND a.revoked_at IS NULL;RETURN NEXT;
END $$;
CREATE FUNCTION bloc.mfa_webauthn_finish(r uuid,bearer bytea,browser bytea,token bytea,ceremony uuid,registration boolean,verified boolean,credential bytea,original bytea,updated bytea,transports text[],factor uuid,key_id uuid,key_generation bigint,generation_id uuid,digests bytea[],handoff_id uuid,handoff_envelope bytea,new_bearer bytea,new_csrf bytea,new_session bytea,new_browser bytea,new_token bytea,device text) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE f bloc.realm_mfa_flow;child bloc.realm_mfa_flow;checked timestamptz;c bloc.mfa_encryption_control;target uuid;p bloc.realm_authentication_settings;
BEGIN
 f:=bloc.mfa_webauthn_parent(r,bearer,browser,token);IF NOT bloc.mfa_webauthn_eligible(f,registration) THEN RETURN 'stale';END IF;checked:=clock_timestamp();
 SELECT * INTO child FROM bloc.realm_mfa_flow WHERE id=ceremony AND realm_id=r AND user_id=f.user_id AND parent_id=f.id AND consumed_at IS NULL AND expires_at>checked AND purpose=CASE WHEN registration THEN 'webauthn_registration' ELSE 'webauthn_authentication' END;
 IF child.id IS NULL THEN RETURN 'stale';END IF;
 IF NOT coalesce(verified,false) THEN RETURN bloc.mfa_reject(child.id);END IF;
 SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;
 IF registration OR (f.purpose='login' AND p.mfa_recovery_codes_enabled AND EXISTS(SELECT FROM bloc.realm_mfa_recovery_generation WHERE realm_id=r AND user_id=f.user_id AND invalidated_at IS NULL AND acknowledged_at IS NULL)) THEN
  SELECT * INTO c FROM bloc.mfa_encryption_control WHERE id=1;IF c.generation<>key_generation OR c.active_key_id IS DISTINCT FROM key_id THEN RETURN 'key_conflict';END IF;
 END IF;
 IF registration THEN
  IF EXISTS(SELECT FROM bloc.realm_webauthn_factor WHERE credential_id=credential) THEN RETURN bloc.mfa_reject(child.id);END IF;
  IF f.operation LIKE 'webauthn_replace:%' THEN target:=substring(f.operation FROM 18)::uuid;END IF;
  IF f.purpose<>'recovery' AND (SELECT count(*) FROM bloc.realm_user_factor WHERE realm_id=r AND user_id=f.user_id AND kind='webauthn' AND revoked_at IS NULL)>=(CASE WHEN target IS NULL THEN 10 ELSE 11 END) THEN RETURN 'stale';END IF;
  IF target IS NOT NULL THEN UPDATE bloc.realm_user_factor SET revoked_at=checked WHERE realm_id=r AND user_id=f.user_id AND id=target AND revoked_at IS NULL;END IF;
  INSERT INTO bloc.realm_user_factor(id,realm_id,user_id,kind,label,last_used_at) VALUES(factor,r,f.user_id,'webauthn',child.label,checked);
  INSERT INTO bloc.realm_webauthn_factor(factor_id,realm_id,user_id,credential_id,public_credential,transports) VALUES(factor,r,f.user_id,credential,updated,transports);
  RETURN bloc.mfa_complete_enrollment(child,'webauthn',factor,generation_id,digests,handoff_id,handoff_envelope,key_id,new_bearer,new_csrf,new_session,new_browser,new_token,device);
 END IF;
 SELECT w.factor_id INTO factor FROM bloc.realm_webauthn_factor w JOIN bloc.realm_user_factor a ON a.id=w.factor_id WHERE w.realm_id=r AND w.user_id=f.user_id AND w.credential_id=credential AND a.revoked_at IS NULL AND w.public_credential=original;
 IF factor IS NULL THEN RETURN 'stale';END IF;
 UPDATE bloc.realm_webauthn_factor w SET public_credential=updated WHERE w.factor_id=factor;
 UPDATE bloc.realm_user_factor SET last_used_at=checked WHERE id=factor;
 UPDATE bloc.realm_mfa_flow SET consumed_at=checked WHERE id=child.id;
 IF f.purpose='reauthenticate' THEN UPDATE bloc.realm_mfa_flow SET proof_verified_at=checked,verified_method='webauthn',factor_id=factor WHERE id=f.id;RETURN 'reauthenticated';END IF;
 IF p.mfa_recovery_codes_enabled AND EXISTS(SELECT FROM bloc.realm_mfa_recovery_generation WHERE realm_id=r AND user_id=f.user_id AND invalidated_at IS NULL AND acknowledged_at IS NULL) THEN
  PERFORM bloc.mfa_create_handoff(f,f.factor_epoch,'webauthn',factor,generation_id,digests,handoff_id,handoff_envelope,key_id,new_bearer,new_csrf);RETURN 'handoff';
 END IF;
 UPDATE bloc.realm_mfa_flow SET consumed_at=checked WHERE id=f.id OR parent_id=f.id;
 PERFORM bloc.mfa_issue_session(r,f.user_id,f.credential_version,f.factor_epoch,f.password_verified_at,'webauthn',factor,new_session,new_browser,new_token,device);
 INSERT INTO bloc.security_audit_event(installation_id,action,outcome,realm_id,realm_user_id,actor_realm_id,actor_user_id,mfa_factor_id) VALUES(1,'realm_mfa_sign_in','success',r,f.user_id,r,f.user_id,factor);RETURN 'ok';
END $$;
REVOKE ALL ON FUNCTION bloc.mfa_webauthn_parent(uuid,bytea,bytea,bytea),bloc.mfa_webauthn_eligible(bloc.realm_mfa_flow,boolean),bloc.mfa_webauthn_material(uuid,bytea,bytea,bytea,boolean,bytea),bloc.mfa_webauthn_start(uuid,bytea,bytea,bytea,boolean,uuid,bytea,bytea,text),bloc.mfa_webauthn_ceremony(uuid,bytea,bytea,bytea,uuid,boolean),bloc.mfa_webauthn_finish(uuid,bytea,bytea,bytea,uuid,boolean,boolean,bytea,bytea,bytea,text[],uuid,uuid,bigint,uuid,bytea[],uuid,bytea,bytea,bytea,bytea,bytea,bytea,text) FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
GRANT EXECUTE ON FUNCTION bloc.mfa_webauthn_material(uuid,bytea,bytea,bytea,boolean,bytea),bloc.mfa_webauthn_start(uuid,bytea,bytea,bytea,boolean,uuid,bytea,bytea,text),bloc.mfa_webauthn_ceremony(uuid,bytea,bytea,bytea,uuid,boolean),bloc.mfa_webauthn_finish(uuid,bytea,bytea,bytea,uuid,boolean,boolean,bytea,bytea,bytea,text[],uuid,uuid,bigint,uuid,bytea[],uuid,bytea,bytea,bytea,bytea,bytea,bytea,text) TO bloc_runtime;

REVOKE ALL ON FUNCTION bloc.mfa_webauthn_reject(uuid,bytea,bytea,bytea) FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
GRANT EXECUTE ON FUNCTION bloc.mfa_webauthn_reject(uuid,bytea,bytea,bytea) TO bloc_runtime;
