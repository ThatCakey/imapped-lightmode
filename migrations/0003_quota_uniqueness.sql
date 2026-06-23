BEGIN;

CREATE UNIQUE INDEX IF NOT EXISTS quotas_account_id_unique_idx
    ON quotas(account_id)
    WHERE account_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS quotas_user_id_unique_idx
    ON quotas(user_id)
    WHERE user_id IS NOT NULL;

COMMIT;
