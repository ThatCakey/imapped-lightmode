BEGIN;

CREATE UNIQUE INDEX IF NOT EXISTS sync_state_account_mailbox_unique
    ON sync_state(account_id, mailbox_id);

COMMIT;
