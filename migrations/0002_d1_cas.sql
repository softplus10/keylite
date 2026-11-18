-- Apply after 0001_init.sql on the Cloudflare D1 database.
-- SQLite triggers make the conditional INSERT and HEAD update one atomic operation.
CREATE TRIGGER IF NOT EXISTS vault_revision_commit
AFTER INSERT ON vault_revisions
BEGIN
    UPDATE vaults SET latest_revision = NEW.revision, latest_hash = NEW.hash
    WHERE id = NEW.vault_id AND latest_revision = NEW.revision - 1;
    SELECT CASE WHEN changes() != 1 THEN RAISE(ABORT, 'stale head') END;
    DELETE FROM vault_revisions
    WHERE vault_id = NEW.vault_id AND revision <= NEW.revision - 5;
END;
