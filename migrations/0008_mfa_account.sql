-- Personal factor management retains the same guarded authority as login.
CREATE FUNCTION bloc.mfa_account_factors(r uuid,session bytea) RETURNS TABLE(id text,label text,kind text,created text,last_used text,preferred boolean,allowed boolean,epoch bigint,unused_codes bigint) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE s bloc.realm_user_session;
BEGIN
 s:=bloc.realm_session(r,session,false);IF s.id IS NULL THEN RETURN;END IF;
 RETURN QUERY SELECT f.id::text,f.label,f.kind,to_char(f.created_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS'),coalesce(to_char(f.last_used_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS'),'Never used'),f.id IS NOT DISTINCT FROM m.preferred_factor_id,f.kind=ANY(p.mfa_allowed_methods),m.factor_epoch,(SELECT count(*) FROM bloc.realm_mfa_recovery_code c JOIN bloc.realm_mfa_recovery_generation g ON g.id=c.generation_id WHERE g.realm_id=r AND g.user_id=s.user_id AND g.invalidated_at IS NULL AND g.acknowledged_at IS NOT NULL AND c.consumed_at IS NULL) FROM bloc.realm_user_mfa_state m JOIN bloc.realm_authentication_settings p ON p.realm_id=m.realm_id LEFT JOIN bloc.realm_user_factor f ON f.realm_id=m.realm_id AND f.user_id=m.user_id AND f.revoked_at IS NULL WHERE m.realm_id=r AND m.user_id=s.user_id ORDER BY f.created_at,f.id;
END $$;
CREATE FUNCTION bloc.mfa_account_operation(r uuid,u uuid,op text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE p bloc.realm_authentication_settings;f bloc.realm_user_factor;target text;prefix text;
BEGIN
 SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;
 IF op='password' THEN RETURN true;END IF;
 IF op='recovery_codes_regenerate' THEN RETURN p.mfa_mode<>'disabled' AND p.mfa_recovery_codes_enabled AND EXISTS(SELECT FROM bloc.realm_user_factor WHERE realm_id=r AND user_id=u AND revoked_at IS NULL AND kind=ANY(p.mfa_allowed_methods));END IF;
 IF op IN('totp_enroll','webauthn_enroll') THEN
  RETURN p.mfa_mode<>'disabled' AND split_part(op,'_',1)=ANY(p.mfa_allowed_methods) AND (op<>'totp_enroll' OR NOT EXISTS(SELECT FROM bloc.realm_user_factor WHERE realm_id=r AND user_id=u AND revoked_at IS NULL AND kind='totp')) AND (op<>'webauthn_enroll' OR (SELECT count(*) FROM bloc.realm_user_factor WHERE realm_id=r AND user_id=u AND revoked_at IS NULL AND kind='webauthn')<10);
 END IF;
 prefix:=split_part(op,':',1);target:=split_part(op,':',2);
 IF prefix NOT IN('factor_remove','totp_replace','webauthn_replace') OR target !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR op<>prefix||':'||target THEN RETURN false;END IF;
 SELECT * INTO f FROM bloc.realm_user_factor WHERE realm_id=r AND user_id=u AND id=target::uuid AND revoked_at IS NULL;
 RETURN f.id IS NOT NULL AND (prefix='factor_remove' OR (p.mfa_mode<>'disabled' AND f.kind=split_part(prefix,'_',1) AND f.kind=ANY(p.mfa_allowed_methods)));
END $$;
CREATE FUNCTION bloc.mfa_account_reauthenticate(r uuid,session bytea,browser bytea,token bytea,expected bigint,op text,new_bearer bytea,new_csrf bytea) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE s bloc.realm_user_session;p bloc.realm_authentication_settings;u bloc.realm_user;checked timestamptz;need_factor boolean;
BEGIN
 checked:=bloc.realm_lock();s:=bloc.realm_session(r,session,false);IF s.id IS NULL THEN RETURN 'authority';END IF;
 IF NOT coalesce(bloc.realm_form_valid(r,'account',browser,token,session,NULL),false) THEN RETURN 'csrf';END IF;
 IF s.credential_version<>expected THEN RETURN 'stale';END IF;
 IF NOT bloc.mfa_account_operation(r,s.user_id,op) THEN RETURN 'missing';END IF;
 SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;SELECT * INTO u FROM bloc.realm_user WHERE realm_id=r AND id=s.user_id;
 need_factor:=p.mfa_mode<>'disabled' AND EXISTS(SELECT FROM bloc.realm_user_factor WHERE realm_id=r AND user_id=s.user_id AND revoked_at IS NULL);
 IF need_factor AND NOT EXISTS(SELECT FROM bloc.realm_user_factor WHERE realm_id=r AND user_id=s.user_id AND revoked_at IS NULL AND kind=ANY(p.mfa_allowed_methods)) THEN RETURN 'authority';END IF;
 IF NOT bloc.mfa_flow_capacity(r,s.user_id,true) THEN RAISE EXCEPTION 'capacity' USING ERRCODE='54000';END IF;
 INSERT INTO bloc.realm_mfa_flow(realm_id,user_id,bearer_digest,browser_digest,purpose,operation,credential_version,factor_epoch,policy_version,user_version,password_verified_at,session_id,csrf_token,created_at,expires_at,proof_verified_at)
 VALUES(r,s.user_id,new_bearer,browser,'reauthenticate',op,s.credential_version,s.factor_epoch,p.version,u.version,checked,s.id,new_csrf,checked,least(s.expires_at,checked+make_interval(secs=>least(300,p.mfa_flow_ttl_seconds))),CASE WHEN need_factor THEN NULL ELSE checked END);
 RETURN CASE WHEN need_factor THEN 'mfa' ELSE 'ok' END;
END $$;
-- Private, exact-action proof consumer. A public UUID never authorizes a mutation.
CREATE FUNCTION bloc.mfa_take_proof(r uuid,session_digest bytea,browser_digest bytea,operation text,expected_flow uuid DEFAULT NULL) RETURNS bloc.realm_mfa_flow LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE s bloc.realm_user_session;f bloc.realm_mfa_flow;snapshot record;p bloc.realm_authentication_settings;checked timestamptz;
BEGIN
 checked:=bloc.realm_lock();s:=bloc.realm_session(r,session_digest,false);IF s.id IS NULL THEN RETURN NULL;END IF;
 SELECT q.* INTO f FROM bloc.realm_mfa_flow q WHERE q.realm_id=r AND q.user_id=s.user_id AND q.session_id=s.id AND q.browser_digest=mfa_take_proof.browser_digest AND q.operation=mfa_take_proof.operation AND q.purpose='reauthenticate' AND q.consumed_at IS NULL ORDER BY q.created_at DESC,q.id DESC LIMIT 1;
 IF f.id IS NULL OR (expected_flow IS NOT NULL AND f.id<>expected_flow) THEN RETURN NULL;END IF;
 SELECT * INTO snapshot FROM bloc.mfa_flow_snapshot(r,f.bearer_digest,browser_digest,NULL);IF snapshot.status<>'ok' THEN RETURN NULL;END IF;
 IF f.password_verified_at<checked-interval '5 minutes' OR f.proof_verified_at IS NULL OR f.proof_verified_at<checked-interval '5 minutes' OR f.proof_verified_at>checked OR NOT bloc.mfa_account_operation(r,s.user_id,operation) THEN RETURN NULL;END IF;
 SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;
 IF p.mfa_mode<>'disabled' AND EXISTS(SELECT FROM bloc.realm_user_factor WHERE realm_id=r AND user_id=s.user_id AND revoked_at IS NULL) AND NOT EXISTS(SELECT FROM bloc.realm_user_factor WHERE realm_id=r AND user_id=s.user_id AND id=f.factor_id AND kind=f.verified_method AND kind=ANY(p.mfa_allowed_methods) AND revoked_at IS NULL) THEN RETURN NULL;END IF;
 UPDATE bloc.realm_mfa_flow SET consumed_at=checked WHERE id=f.id;RETURN f;
END $$;
CREATE FUNCTION bloc.mfa_account_continue(r uuid,bearer bytea,browser bytea) RETURNS TABLE(status text,operation text,epoch bigint) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;f bloc.realm_mfa_flow;
BEGIN
 SELECT * INTO snapshot FROM bloc.mfa_flow_snapshot(r,bearer,browser,NULL);status:=snapshot.status;
 IF status='ok' THEN f:=snapshot.authority;IF f.purpose<>'reauthenticate' OR f.proof_verified_at IS NULL OR f.password_verified_at<clock_timestamp()-interval '5 minutes' OR f.proof_verified_at<clock_timestamp()-interval '5 minutes' OR NOT bloc.mfa_account_operation(r,f.user_id,f.operation) THEN status:='stale';ELSE operation:=f.operation;epoch:=f.factor_epoch;END IF;END IF;RETURN NEXT;
END $$;
CREATE FUNCTION bloc.mfa_account_edit(r uuid,session bytea,browser bytea,token bytea,expected bigint,target uuid,op text,value text) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE s bloc.realm_user_session;checked timestamptz;
BEGIN
 checked:=bloc.realm_lock();s:=bloc.realm_session(r,session,false);IF s.id IS NULL THEN RETURN 'authority';END IF;
 IF NOT coalesce(bloc.realm_form_valid(r,'account',browser,token,session,NULL),false) THEN RETURN 'csrf';END IF;
 IF s.factor_epoch<>expected THEN RETURN 'stale';END IF;
 IF (target IS NOT NULL OR op='label') AND NOT EXISTS(SELECT FROM bloc.realm_user_factor WHERE realm_id=r AND user_id=s.user_id AND id=target AND revoked_at IS NULL) THEN RETURN 'missing';END IF;
 IF op='label' THEN
  IF value IS NULL OR char_length(value) NOT BETWEEN 1 AND 64 OR octet_length(value)>256 OR value ~ '[[:cntrl:]]' THEN RETURN 'invalid';END IF;
  UPDATE bloc.realm_user_factor SET label=value WHERE realm_id=r AND user_id=s.user_id AND id=target;
 ELSIF op='preferred' THEN UPDATE bloc.realm_user_mfa_state SET preferred_factor_id=target,updated_at=checked WHERE realm_id=r AND user_id=s.user_id;
 ELSE RETURN 'invalid';END IF;
 INSERT INTO bloc.security_audit_event(installation_id,action,outcome,realm_id,realm_user_id,actor_realm_id,actor_user_id,mfa_factor_id) VALUES(1,CASE WHEN op='label' THEN 'realm_mfa_factor_label' ELSE 'realm_mfa_preference' END,'success',r,s.user_id,r,s.user_id,target);RETURN 'ok';
END $$;
CREATE FUNCTION bloc.mfa_account_remove(r uuid,bearer bytea,browser bytea,token bytea,session bytea,expected bigint,target uuid,confirmed boolean,new_session bytea,new_browser bytea,new_token bytea,device text) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;f bloc.realm_mfa_flow;s bloc.realm_user_session;p bloc.realm_authentication_settings;checked timestamptz;remaining bigint;eligible bigint;epoch bigint;method text;factor uuid;factor_at timestamptz;
BEGIN
 SELECT * INTO snapshot FROM bloc.mfa_flow_snapshot(r,bearer,browser,token);IF snapshot.status<>'ok' THEN RETURN snapshot.status;END IF;f:=snapshot.authority;checked:=clock_timestamp();s:=bloc.realm_session(r,session,false);
 IF s.id IS NULL OR s.id IS DISTINCT FROM f.session_id OR f.operation IS DISTINCT FROM 'factor_remove:'||target::text THEN RETURN 'stale';END IF;
 IF f.factor_epoch<>expected THEN RETURN 'stale';END IF;
 IF NOT EXISTS(SELECT FROM bloc.realm_user_factor WHERE realm_id=r AND user_id=f.user_id AND id=target AND revoked_at IS NULL) THEN RETURN 'missing';END IF;
 SELECT * INTO p FROM bloc.realm_authentication_settings WHERE realm_id=r;
 SELECT count(*),count(*) FILTER(WHERE kind=ANY(p.mfa_allowed_methods)) INTO remaining,eligible FROM bloc.realm_user_factor WHERE realm_id=r AND user_id=f.user_id AND revoked_at IS NULL AND id<>target;
 IF p.mfa_mode='required' AND eligible=0 THEN RETURN 'required';END IF;
 IF p.mfa_mode<>'disabled' AND remaining>0 AND eligible=0 THEN RETURN 'required';END IF;
 IF remaining=0 AND p.mfa_mode='optional' AND NOT confirmed THEN RETURN 'confirm';END IF;
 IF p.mfa_mode<>'disabled' AND remaining>0 THEN
  IF f.factor_id<>target THEN method:=f.verified_method;factor:=f.factor_id;factor_at:=f.proof_verified_at;
  ELSIF EXISTS(SELECT FROM bloc.realm_user_factor WHERE realm_id=r AND user_id=s.user_id AND id=s.mfa_factor_id AND id<>target AND revoked_at IS NULL AND kind=ANY(p.mfa_allowed_methods)) THEN method:=s.mfa_method;factor:=s.mfa_factor_id;factor_at:=s.mfa_verified_at;END IF;
  IF factor IS NULL THEN RETURN 'remaining_factor';END IF;
 END IF;
 f:=bloc.mfa_take_proof(r,session,browser,'factor_remove:'||target::text,f.id);IF f.id IS NULL THEN RETURN 'stale';END IF;
 UPDATE bloc.realm_user_factor SET revoked_at=checked WHERE id=target;
 UPDATE bloc.realm_user_mfa_state m SET factor_epoch=m.factor_epoch+1,preferred_factor_id=CASE WHEN m.preferred_factor_id=target THEN NULL ELSE m.preferred_factor_id END,updated_at=checked WHERE realm_id=r AND user_id=f.user_id RETURNING factor_epoch INTO epoch;
 UPDATE bloc.realm_user_session SET revoked_at=coalesce(revoked_at,checked) WHERE realm_id=r AND user_id=f.user_id;
 DELETE FROM bloc.realm_form_state WHERE session_id IN(SELECT id FROM bloc.realm_user_session WHERE realm_id=r AND user_id=f.user_id);
 UPDATE bloc.realm_mfa_flow SET consumed_at=coalesce(consumed_at,checked) WHERE realm_id=r AND user_id=f.user_id;
 DELETE FROM bloc.realm_mfa_recovery_link WHERE realm_id=r AND user_id=f.user_id;
 IF remaining=0 THEN UPDATE bloc.realm_mfa_recovery_generation SET invalidated_at=coalesce(invalidated_at,checked) WHERE realm_id=r AND user_id=f.user_id;END IF;
 INSERT INTO bloc.security_audit_event(installation_id,action,outcome,realm_id,realm_user_id,actor_realm_id,actor_user_id,mfa_factor_id) VALUES(1,'realm_mfa_factor_remove','success',r,f.user_id,r,f.user_id,target);
 PERFORM bloc.mfa_issue_session(r,f.user_id,f.credential_version,epoch,f.password_verified_at,method,factor,new_session,new_browser,new_token,device);
 UPDATE bloc.realm_user_session SET mfa_verified_at=CASE WHEN method IS NULL THEN NULL ELSE factor_at END WHERE realm_id=r AND session_digest=new_session;
 RETURN 'ok';
END $$;
CREATE FUNCTION bloc.mfa_account_regenerate(r uuid,bearer bytea,browser bytea,token bytea,session bytea,generation_id uuid,digests bytea[],handoff_id uuid,envelope bytea,key_id uuid,key_generation bigint,new_bearer bytea,new_csrf bytea) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
DECLARE snapshot record;f bloc.realm_mfa_flow;s bloc.realm_user_session;c bloc.mfa_encryption_control;checked timestamptz;epoch bigint;
BEGIN
 SELECT * INTO snapshot FROM bloc.mfa_flow_snapshot(r,bearer,browser,token);IF snapshot.status<>'ok' THEN RETURN snapshot.status;END IF;f:=snapshot.authority;s:=bloc.realm_session(r,session,false);
 IF s.id IS NULL OR s.id IS DISTINCT FROM f.session_id OR f.operation IS DISTINCT FROM 'recovery_codes_regenerate' THEN RETURN 'stale';END IF;
 SELECT * INTO c FROM bloc.mfa_encryption_control WHERE id=1;IF c.generation<>key_generation OR c.active_key_id IS DISTINCT FROM key_id THEN RETURN 'key_conflict';END IF;
 f:=bloc.mfa_take_proof(r,session,browser,'recovery_codes_regenerate');IF f.id IS NULL THEN RETURN 'stale';END IF;checked:=clock_timestamp();
 UPDATE bloc.realm_user_mfa_state m SET factor_epoch=m.factor_epoch+1,updated_at=checked WHERE realm_id=r AND user_id=f.user_id RETURNING factor_epoch INTO epoch;
 UPDATE bloc.realm_user_session SET revoked_at=coalesce(revoked_at,checked) WHERE realm_id=r AND user_id=f.user_id;
 DELETE FROM bloc.realm_form_state WHERE session_id IN(SELECT id FROM bloc.realm_user_session WHERE realm_id=r AND user_id=f.user_id);
 UPDATE bloc.realm_mfa_flow SET consumed_at=coalesce(consumed_at,checked) WHERE realm_id=r AND user_id=f.user_id;
 DELETE FROM bloc.realm_mfa_recovery_link WHERE realm_id=r AND user_id=f.user_id;
 PERFORM bloc.mfa_create_handoff(f,epoch,f.verified_method,f.factor_id,generation_id,digests,handoff_id,envelope,key_id,new_bearer,new_csrf);RETURN 'handoff';
END $$;
REVOKE ALL ON FUNCTION bloc.mfa_account_factors(uuid,bytea),bloc.mfa_account_operation(uuid,uuid,text),bloc.mfa_account_reauthenticate(uuid,bytea,bytea,bytea,bigint,text,bytea,bytea),bloc.mfa_take_proof(uuid,bytea,bytea,text,uuid),bloc.mfa_account_continue(uuid,bytea,bytea),bloc.mfa_account_edit(uuid,bytea,bytea,bytea,bigint,uuid,text,text),bloc.mfa_account_remove(uuid,bytea,bytea,bytea,bytea,bigint,uuid,boolean,bytea,bytea,bytea,text),bloc.mfa_account_regenerate(uuid,bytea,bytea,bytea,bytea,uuid,bytea[],uuid,bytea,uuid,bigint,bytea,bytea) FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
GRANT EXECUTE ON FUNCTION bloc.mfa_account_factors(uuid,bytea),bloc.mfa_account_reauthenticate(uuid,bytea,bytea,bytea,bigint,text,bytea,bytea),bloc.mfa_account_continue(uuid,bytea,bytea),bloc.mfa_account_edit(uuid,bytea,bytea,bytea,bigint,uuid,text,text),bloc.mfa_account_remove(uuid,bytea,bytea,bytea,bytea,bigint,uuid,boolean,bytea,bytea,bytea,text),bloc.mfa_account_regenerate(uuid,bytea,bytea,bytea,bytea,uuid,bytea[],uuid,bytea,uuid,bigint,bytea,bytea) TO bloc_runtime;
