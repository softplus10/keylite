import sqlite3
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DatabaseContractTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.executescript((ROOT / "migrations/0001_init.sql").read_text())
        self.db.executescript((ROOT / "migrations/0002_d1_cas.sql").read_text())
        self.db.execute("INSERT INTO users(id,email,password_hash) VALUES ('u','a@example.org','hash')")
        self.db.execute("INSERT INTO vaults(id,user_id,name) VALUES ('v','u','test')")

    def upload(self, revision, previous_hash, new_hash):
        return self.db.execute(
            """INSERT INTO vault_revisions(vault_id,revision,hash,blob)
               SELECT id,latest_revision+1,?,? FROM vaults
               WHERE id='v' AND user_id='u' AND latest_revision=? AND latest_hash IS ?""",
            (new_hash, new_hash.encode(), revision - 1, previous_hash),
        ).rowcount

    def test_cas_and_bounded_history(self):
        self.assertEqual(self.upload(1, None, "h1"), 1)
        self.assertEqual(self.upload(1, None, "stale"), 0)
        for revision in range(2, 9):
            self.assertEqual(self.upload(revision, f"h{revision-1}", f"h{revision}"), 1)
        rows = self.db.execute(
            "SELECT revision FROM vault_revisions WHERE vault_id='v' ORDER BY revision"
        ).fetchall()
        self.assertEqual(rows, [(4,), (5,), (6,), (7,), (8,)])
        self.assertEqual(
            self.db.execute("SELECT latest_revision,latest_hash FROM vaults WHERE id='v'").fetchone(),
            (8, "h8"),
        )

    def test_trigger_rejects_out_of_sequence_revision(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "INSERT INTO vault_revisions(vault_id,revision,hash,blob) VALUES ('v',3,'bad',X'01')"
            )

    def test_atomic_registration_and_vault_quotas(self):
        max_users = 1
        self.assertEqual(self.db.execute(
            "INSERT INTO users(id,email,password_hash) SELECT 'second','b@example.org','hash' "
            "WHERE ?=0 OR (SELECT count(*) FROM users)<?",
            (max_users, max_users),
        ).rowcount, 0)
        max_vaults = 1
        self.assertEqual(self.db.execute(
            "INSERT INTO vaults(id,user_id,name) SELECT 'extra','u','second' WHERE ?=0 OR "
            "(SELECT count(*) FROM vaults WHERE user_id='u')<?",
            (max_vaults, max_vaults),
        ).rowcount, 0)
        self.assertEqual(self.db.execute(
            "INSERT INTO vaults(id,user_id,name) SELECT 'extra','u','second' WHERE ?=0 OR "
            "(SELECT count(*) FROM vaults WHERE user_id='u')<?",
            (0, 0),
        ).rowcount, 1)

    def tearDown(self):
        self.db.close()


if __name__ == "__main__":
    unittest.main()
