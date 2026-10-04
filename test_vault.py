"""
Test and sanity check script for SentinelBit.
Verifies cryptography, TOTP, WebAuthn passkey generation and API flow.
"""
import unittest
import os
import json
import secrets
import crypto_utils
import database
from fastapi.testclient import TestClient
from server import app

class TestSentinelBit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        database.init_db()
        cls.client = TestClient(app)

    def test_totp_flow(self):
        secret = crypto_utils.generate_totp_secret()
        self.assertTrue(len(secret) >= 16)
        
        info = crypto_utils.generate_current_totp(secret)
        self.assertEqual(len(info["code"]), 6)
        self.assertTrue(info["remaining_seconds"] <= 30)

        # Verification of valid code
        is_valid = crypto_utils.verify_totp_code(secret, info["code"])
        self.assertTrue(is_valid)

        # Verification of bogus code
        self.assertFalse(crypto_utils.verify_totp_code(secret, "000000" if info["code"] != "000000" else "111111"))

    def test_passkey_keypair_and_assertion(self):
        # 1. Generate ES256 keypair
        keypair = crypto_utils.generate_passkey_keypair()
        self.assertIn("credential_id", keypair)
        self.assertIn("private_key_pem", keypair)
        self.assertIn("public_key_pem", keypair)
        self.assertIn("cose_key", keypair)

        # 2. Test assertion signature
        client_data = '{"type":"webauthn.get","challenge":"dGVzdA","origin":"https://test.com"}'
        auth_data_hex = "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000001"

        res = crypto_utils.sign_webauthn_assertion(
            keypair["private_key_pem"],
            client_data,
            auth_data_hex
        )
        self.assertIn("signature_b64", res)
        self.assertIn("signature_hex", res)
        self.assertTrue(len(res["signature_b64"]) > 20)

    def test_api_user_flow(self):
        # Unique test username
        uname = f"testuser_{secrets.token_hex(4)}"
        client_salt = crypto_utils.generate_salt()
        enc_salt = crypto_utils.generate_salt()
        
        # Simulated client auth key
        fake_client_auth_key = secrets.token_hex(32)

        # 1. Register
        reg_res = self.client.post("/api/auth/register", json={
            "username": uname,
            "auth_salt": client_salt,
            "auth_hash": fake_client_auth_key,
            "enc_salt": enc_salt
        })
        self.assertEqual(reg_res.status_code, 200)

        # 2. Login Init
        init_res = self.client.post("/api/auth/login-init", json={"username": uname})
        self.assertEqual(init_res.status_code, 200)
        init_data = init_res.json()
        self.assertIn(client_salt, init_data["auth_salt"])
        self.assertEqual(init_data["enc_salt"], enc_salt)
        self.assertFalse(init_data["totp_required"])

        # 3. Login Verify
        login_res = self.client.post("/api/auth/login-verify", json={
            "username": uname,
            "client_auth_key": fake_client_auth_key
        })
        self.assertEqual(login_res.status_code, 200)
        token = login_res.json()["token"]

        # 4. Create encrypted vault item
        headers = {"Authorization": f"Bearer {token}"}
        item_res = self.client.post("/api/vault/items", headers=headers, json={
            "type": "login",
            "title": "GitHub",
            "folder": "Entwicklung",
            "favorite": True,
            "encrypted_payload": '{"iv":"abcdef","data":"123456"}'
        })
        self.assertEqual(item_res.status_code, 200)
        item_id = item_res.json()["id"]

        # 5. List items
        list_res = self.client.get("/api/vault/items", headers=headers)
        self.assertEqual(list_res.status_code, 200)
        self.assertEqual(len(list_res.json()), 1)
        self.assertEqual(list_res.json()[0]["title"], "GitHub")

        # 6. Generate Passkey
        pk_gen = self.client.post("/api/passkeys/generate", headers=headers, json={
            "rp_id": "github.com",
            "rp_name": "GitHub",
            "username": uname
        })
        self.assertEqual(pk_gen.status_code, 200)
        pk_data = pk_gen.json()

        # 7. Save Passkey
        pk_save = self.client.post("/api/passkeys", headers=headers, json={
            "rp_id": "github.com",
            "rp_name": "GitHub",
            "username": uname,
            "credential_id": pk_data["credential_id"],
            "encrypted_private_key": '{"iv":"1111","data":"2222"}',
            "public_key_cose": pk_data["public_key_cose"],
            "public_key_pem": pk_data["public_key_pem"]
        })
        self.assertEqual(pk_save.status_code, 200)

        # 8. List Passkeys
        pk_list = self.client.get("/api/passkeys", headers=headers)
        self.assertEqual(pk_list.status_code, 200)
        self.assertEqual(len(pk_list.json()), 1)

        # 9. Test Soft-Delete (Move to Trash)
        del_res = self.client.delete(f"/api/vault/items/{item_id}", headers=headers)
        self.assertEqual(del_res.status_code, 200)

        # Verify active items is now 0
        active_res = self.client.get("/api/vault/items", headers=headers)
        self.assertEqual(len(active_res.json()), 0)

        # Verify trash items is now 1
        trash_res = self.client.get("/api/vault/trash", headers=headers)
        self.assertEqual(len(trash_res.json()), 1)
        self.assertEqual(trash_res.json()[0]["id"], item_id)

        # 10. Restore from Trash
        restore_res = self.client.post(f"/api/vault/items/{item_id}/restore", headers=headers)
        self.assertEqual(restore_res.status_code, 200)
        active_after_restore = self.client.get("/api/vault/items", headers=headers)
        self.assertEqual(len(active_after_restore.json()), 1)

        # 11. Test WebAuthn Key Registration
        bio_reg = self.client.post("/api/auth/webauthn/register-key", headers=headers, json={
            "credential_id": "test_cred_12345",
            "public_key": "dummy_pk",
            "device_name": "Test Windows PC"
        })
        self.assertEqual(bio_reg.status_code, 200)

        # 12. Test HIBP Prefix Proxy (5 chars)
        hibp_res = self.client.get("/api/tools/hibp/5BAA6")
        self.assertEqual(hibp_res.status_code, 200)
        self.assertIn("status", hibp_res.json())

        # 13. Test Backup & Sync Settings
        test_backup_dir = os.path.abspath("./test_sync_output")
        sync_save = self.client.post("/api/sync/settings", headers=headers, json={
            "target_dir": test_backup_dir,
            "interval_minutes": 5,
            "sync_on_change": True,
            "retention_count": 3,
            "is_active": True
        })
        self.assertEqual(sync_save.status_code, 200)

        # Immediate manual sync trigger
        sync_now = self.client.post("/api/sync/now", headers=headers)
        self.assertEqual(sync_now.status_code, 200)
        self.assertEqual(sync_now.json()["status"], "ok")
        self.assertTrue(os.path.exists(test_backup_dir))

        # 14. Test Email Aliases
        alias_res = self.client.post("/api/aliases", headers=headers, json={
            "service_name": "Netflix"
        })
        self.assertEqual(alias_res.status_code, 200)
        alias_data = alias_res.json()
        self.assertIn("netflix", alias_data["alias_email"])

        aliases_list = self.client.get("/api/aliases", headers=headers)
        self.assertEqual(len(aliases_list.json()), 1)

        # 15. Test Sharing
        share_res = self.client.post("/api/share/send", headers=headers, json={
            "recipient_username": uname, # Share with self for test
            "type": "login",
            "title": "Shared WiFi",
            "encrypted_payload": '{"iv":"0000","data":"9999"}'
        })
        self.assertEqual(share_res.status_code, 200)

        inbox_res = self.client.get("/api/share/inbox", headers=headers)
        self.assertEqual(len(inbox_res.json()), 1)
        self.assertEqual(inbox_res.json()[0]["title"], "Shared WiFi")

        # 16. Test Emergency Kit
        kit_res = self.client.get("/api/auth/emergency-kit", headers=headers)
        self.assertEqual(kit_res.status_code, 200)
        self.assertEqual(kit_res.json()["username"], uname)
        self.assertIn("enc_salt", kit_res.json())

    def test_security_defenses(self):
        # 1. Security Headers
        resp = self.client.get("/")
        self.assertIn("x-content-type-options", resp.headers)
        self.assertEqual(resp.headers["x-content-type-options"], "nosniff")
        self.assertIn("x-frame-options", resp.headers)
        self.assertEqual(resp.headers["x-frame-options"], "DENY")
        self.assertIn("content-security-policy", resp.headers)

        # 2. Unauthenticated access blocked on passkey generation
        unauth_pk = self.client.post("/api/passkeys/generate", json={
            "rp_id": "test.com", "rp_name": "Test", "username": "nobody"
        })
        self.assertEqual(unauth_pk.status_code, 401)

        # 3. Path Traversal blocked in backup settings
        # Register test user
        uname = f"sec_{secrets.token_hex(4)}"
        self.client.post("/api/auth/register", json={
            "username": uname,
            "auth_salt": crypto_utils.generate_salt(),
            "auth_hash": secrets.token_hex(32),
            "enc_salt": crypto_utils.generate_salt()
        })
        # Login
        log_res = self.client.post("/api/auth/login-verify", json={
            "username": uname,
            "client_auth_key": secrets.token_hex(32)
        })
        # Will fail login hash check, let's use correct login flow
        user_row = database.get_connection().cursor().execute("SELECT auth_salt, auth_hash FROM users WHERE username = ?", (uname,)).fetchone()
        client_auth_key = secrets.token_hex(32)
        server_salt = user_row["auth_salt"].split(":")[1]
        stored_hash = crypto_utils.hash_auth_key(client_auth_key, server_salt)
        conn = database.get_connection()
        conn.cursor().execute("UPDATE users SET auth_hash = ? WHERE username = ?", (stored_hash, uname))
        conn.commit()
        conn.close()

        valid_login = self.client.post("/api/auth/login-verify", json={
            "username": uname,
            "client_auth_key": client_auth_key
        })
        self.assertEqual(valid_login.status_code, 200)
        user_token = valid_login.json()["token"]
        auth_hdr = {"Authorization": f"Bearer {user_token}"}

        # Try directory traversal
        traversal_res = self.client.post("/api/sync/settings", headers=auth_hdr, json={
            "target_dir": "../../../../../etc",
            "interval_minutes": 15,
            "sync_on_change": True,
            "retention_count": 5,
            "is_active": True
        })
        self.assertEqual(traversal_res.status_code, 400)

        # Try Windows system directory write
        sys_res = self.client.post("/api/sync/settings", headers=auth_hdr, json={
            "target_dir": r"C:\Windows\System32",
            "interval_minutes": 15,
            "sync_on_change": True,
            "retention_count": 5,
            "is_active": True
        })
        self.assertEqual(sys_res.status_code, 400)

        # 4. Rate Limiting on repeated failed logins (5 failures -> 429)
        victim = f"rate_{secrets.token_hex(4)}"
        for _ in range(5):
            self.client.post("/api/auth/login-verify", json={
                "username": victim,
                "client_auth_key": secrets.token_hex(32)
            })
        blocked_res = self.client.post("/api/auth/login-verify", json={
            "username": victim,
            "client_auth_key": secrets.token_hex(32)
        })
        self.assertEqual(blocked_res.status_code, 429)

if __name__ == "__main__":
    unittest.main()



