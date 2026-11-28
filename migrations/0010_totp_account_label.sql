CREATE FUNCTION bloc.mfa_totp_account_email(r uuid, bearer bytea, browser bytea)
RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,bloc,pg_temp AS $$
    SELECT u.email
    FROM bloc.mfa_totp_pending(r, bearer, browser, NULL) AS pending
    JOIN bloc.realm_user AS u ON u.realm_id = r AND u.id = pending.user_id::uuid
$$;
REVOKE ALL ON FUNCTION bloc.mfa_totp_account_email(uuid,bytea,bytea) FROM PUBLIC,bloc_runtime,bloc_operator,bloc_maintenance;
GRANT EXECUTE ON FUNCTION bloc.mfa_totp_account_email(uuid,bytea,bytea) TO bloc_runtime;
