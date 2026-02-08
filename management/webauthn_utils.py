import base64
import json
import pickle
import sqlite3

from datetime import datetime, timedelta
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.structs import (
    AuthenticatorAttestationResponse,
    AuthenticatorAssertionResponse,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticationCredential,
    AuthenticationCredential,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
)

from mailconfig import open_database, get_mail_users

# Function to handle database operations for WebAuthn credentials

def ensure_webauthn_schema(env):
    """Ensure the WebAuthn table and columns exist."""
    conn, c = open_database(env, with_connection=True)
    # 1. Create table if not exists
    c.execute("""
        CREATE TABLE IF NOT EXISTS webauthn_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            credential_id TEXT NOT NULL UNIQUE,
            public_key TEXT NOT NULL,
            sign_count INTEGER NOT NULL,
            transports TEXT,
            label TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_used_at DATETIME,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    # 2. Migration: ensure last_used_at exists even on older databases.
    c.execute("PRAGMA table_info(webauthn_credentials)")
    columns = [row[1] for row in c.fetchall()]
    if "last_used_at" not in columns:
        try:
            c.execute("ALTER TABLE webauthn_credentials ADD COLUMN last_used_at DATETIME")
        except sqlite3.OperationalError:
            # If another migration added the column concurrently, ignore the error.
            pass
    # 3. Create webauthn_challenges table if not exists
    c.execute("""
        CREATE TABLE IF NOT EXISTS webauthn_challenges (
            key TEXT PRIMARY KEY,
            options BLOB NOT NULL,
            expires_at DATETIME NOT NULL
        )
    """)
    conn.commit()

def get_user_email_by_id(user_id, env):
    """Retrieve user email by integer ID."""
    c = open_database(env)
    c.execute("SELECT email FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    print(f"DEBUG: get_user_email_by_id({user_id}) -> {row[0] if row else 'None'}")
    return row[0] if row else None

def get_webauthn_credentials(email, env):
    """Retrieve all WebAuthn credentials for a user."""
    conn, c = open_database(env, with_connection=True) # Get connection to potentially re-use for schema update and retry
    
    # First get user_id
    c.execute("SELECT id FROM users WHERE email=?", (email,))
    user_row = c.fetchone()
    if not user_row:
        return [] # User not found, no credentials

    user_id = user_row[0]

    # Self-healing: If schema update missed, try to catch it here.
    try:
        c.execute(
            "SELECT id, credential_id, public_key, sign_count, transports, label, created_at, last_used_at FROM webauthn_credentials WHERE user_id=?",
            (user_id,),
        )
    except sqlite3.OperationalError as e:
        if "no such column: last_used_at" in str(e):
            # Schema migration didn't run? Run it now.
            ensure_webauthn_schema(env)
            # Retry query on the same connection
            c.execute(
                "SELECT id, credential_id, public_key, sign_count, transports, label, created_at, last_used_at FROM webauthn_credentials WHERE user_id=?",
                (user_id,),
            )
        else:
            raise e
            
    credentials = []
    for row in c.fetchall():
        transports = json.loads(row[4]) if row[4] else []
        credentials.append({
            "id": row[0],
            "credential_id": row[1],
            "public_key": row[2],
            "sign_count": row[3],
            "transports": transports,
            "label": row[5],
            "created_at": str(row[6]) if row[6] else None,
            "last_used_at": str(row[7]) if row[7] else None,
        })
    return credentials

def get_credential_by_id(credential_id, env):
    """Retrieve a specific credential by its ID (base64url encoded)."""
    c = open_database(env)
    c.execute(
        "SELECT id, user_id, public_key, sign_count, transports FROM webauthn_credentials WHERE credential_id=?",
        (credential_id,),
    )
    row = c.fetchone()
    if row:
        transports = json.loads(row[4]) if row[4] else []
        return {
            "id": row[0],
            "user_id": row[1],
            "public_key": row[2],
            "sign_count": row[3],
            "transports": transports,
        }
    return None

def add_webauthn_credential(email, credential_data, label, env):
    """Store a new WebAuthn credential."""
    # First get user_id
    c = open_database(env)
    c.execute("SELECT id FROM users WHERE email=?", (email,))
    user_row = c.fetchone()
    if not user_row:
        raise ValueError("User not found")
    user_id = user_row[0]

    # Insert credential
    conn, c = open_database(env, with_connection=True)
    c.execute(
        "INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, transports, label, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            user_id,
            credential_data["credential_id"],
            credential_data["public_key"],
            credential_data["sign_count"],
            json.dumps(credential_data.get("transports", [])),
            label,
            datetime.now(),  # Initialize last_used_at when the credential is first registered
        ),
    )
    conn.commit()


def update_credential_sign_count(credential_id, sign_count, env):
    """Update the sign count and last_used_at for a credential."""
    # credential_id is base64url encoded
    conn, c = open_database(env, with_connection=True)
    c.execute(
        "UPDATE webauthn_credentials SET sign_count=?, last_used_at=? WHERE credential_id=?",
        (sign_count, datetime.now(), credential_id),
    )
    conn.commit()

def remove_webauthn_credential(email, credential_id, env):
    """Remove a WebAuthn credential by ID, ensuring ownership."""
    # Resolve email to user_id to ensure ownership
    c = open_database(env)
    # Resolve email to user_id to ensure ownership using a single connection
    conn, c = open_database(env, with_connection=True)
    c.execute("SELECT id FROM users WHERE email=?", (email,))
    user_row = c.fetchone()
    if not user_row:
        return False  # User not found
    user_id = user_row[0]
    c.execute(
        "DELETE FROM webauthn_credentials WHERE credential_id=? AND user_id=?",
        (credential_id, user_id),
    )
    conn.commit()
    return c.rowcount > 0

# WebAuthn Logic Wrappers

def begin_registration(email, env, rp_id, rp_name):
    """Generate registration options."""
    # Get existing credentials to exclude them
    existing_credentials = get_webauthn_credentials(email, env)
    
    # Simple user handle (using email as ID for simplicity, though internal ID is better strictly speaking, 
    # but existing auth uses email heavily)
    # Using byte representation of email for user_id in WebAuthn
    # The webauthn library's generate_registration_options function expects user_id to be a string
    # and will encode it to bytes internally.
    if isinstance(email, bytes):
        user_id = email.decode('utf-8')
    else:
        user_id = email

    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=user_id,
        user_name=str(user_id), # Ensure user_name is also a string
        exclude_credentials=[
            {"id": base64url_to_bytes(cred["credential_id"]), "transports": cred["transports"]}
            for cred in existing_credentials
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED,
            resident_key=ResidentKeyRequirement.PREFERRED,
            authenticator_attachment=None, # Allow both Platform (Touch ID/Face ID) and Cross-Platform (YubiKey)
        ),
    )
    return options

def complete_registration(email, options, response_data, env, rp_id, expected_origin=None):
    """Verify registration response and store credential."""
    # Build list of accepted origins: the RP ID domain and any explicitly provided origin
    origins = [f"https://{rp_id}"]
    if expected_origin and expected_origin not in origins:
        origins.append(expected_origin)

    try:
        # Manually parse the JSON and construct RegistrationCredential with
        # base64url_to_bytes. RegistrationCredential.parse_raw() uses Pydantic's
        # standard base64 decoder which chokes on base64url characters ('-', '_'),
        # and the older py_webauthn doesn't accept raw strings.
        data = json.loads(response_data)
        reg_cred = RegistrationCredential(
            id=data['id'],
            raw_id=base64url_to_bytes(data['rawId']),
            response=AuthenticatorAttestationResponse(
                client_data_json=base64url_to_bytes(data['response']['clientDataJSON']),
                attestation_object=base64url_to_bytes(data['response']['attestationObject']),
            ),
            type=data.get('type', 'public-key'),
        )
        credential = verify_registration_response(
            credential=reg_cred,
            expected_challenge=options.challenge,
            expected_origin=origins,
            expected_rp_id=rp_id,
            require_user_verification=False, # Depends on requirements
        )
    except Exception as e:
        raise ValueError(f"Registration failed: {str(e)}")

    # Prepare data for storage
    # Convert bytes to base64url string for storage
    credential_id = base64.urlsafe_b64encode(credential.credential_id).decode('ascii').rstrip('=')
    public_key = base64.urlsafe_b64encode(credential.credential_public_key).decode('ascii').rstrip('=')

    cred_data = {
        "credential_id": credential_id,
        "public_key": public_key,
        "sign_count": credential.sign_count,
        "transports": [], # Not always available in response easily without parsing attestation object deeply or assuming from request
    }
    
    # For now we won't try to extract transports perfectly unless provided, 
    # or rely on client hint. 
    # The parsing logic might need adjustment if strict transport storage is required.

    return cred_data

def begin_authentication(email, env, rp_id):
    """Generate authentication options."""
    # If email provided, we can allow-list credentials.
    # If no email (usernameless flow), we wouldn't filter (Passwordless).
    
    allow_credentials = None
    if email:
        existing_credentials = get_webauthn_credentials(email, env)
        if existing_credentials:
            allow_credentials = [
                {"id": base64url_to_bytes(cred["credential_id"]), "transports": cred["transports"]}
                for cred in existing_credentials
            ]
        else:
             # If email is provided but no credentials found, we return error
             raise ValueError("No WebAuthn credentials found for this user.")

    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED if email else UserVerificationRequirement.REQUIRED,
    )
    return options

def complete_authentication(options, response_data, env, rp_id, expected_origin=None):
    """Verify authentication response."""
    
    # Parse response JSON to extract credential ID for DB lookup
    parsed_response = json.loads(response_data)
    credential_id_b64 = parsed_response.get("id", "")
    
    # Retrieve stored credential
    stored_cred = get_credential_by_id(credential_id_b64, env)
    if not stored_cred:
        raise ValueError("Credential not found.")

    # Build list of accepted origins
    origins = [f"https://{rp_id}"]
    if expected_origin and expected_origin not in origins:
        origins.append(expected_origin)

    try:
        # Manually construct AuthenticationCredential with base64url decoding.
        # The older py_webauthn doesn't accept raw strings.
        auth_cred = AuthenticationCredential(
            id=parsed_response['id'],
            raw_id=base64url_to_bytes(parsed_response['rawId']),
            response=AuthenticatorAssertionResponse(
                client_data_json=base64url_to_bytes(parsed_response['response']['clientDataJSON']),
                authenticator_data=base64url_to_bytes(parsed_response['response']['authenticatorData']),
                signature=base64url_to_bytes(parsed_response['response']['signature']),
                user_handle=base64url_to_bytes(parsed_response['response']['userHandle']) if parsed_response['response'].get('userHandle') else None,
            ),
            type=parsed_response.get('type', 'public-key'),
        )
        verification = verify_authentication_response(
            credential=auth_cred,
            expected_challenge=options.challenge,
            expected_origin=origins,
            expected_rp_id=rp_id,
            credential_public_key=base64url_to_bytes(stored_cred["public_key"]),
            credential_current_sign_count=stored_cred["sign_count"],
            require_user_verification=False, # Adjust based on requirement
        )
    except Exception as e:
        raise ValueError(f"Authentication failed: {str(e)}")
        
    # Update sign count
    update_credential_sign_count(credential_id_b64, verification.new_sign_count, env)
    
    # Return user_id (which is integer in DB) but also fetch email for session creation
    # The caller needs to resolve user_id integer to email if they don't have it (Resident Key case)
    return stored_cred["user_id"]

# Challenge store (SQLite-backed)

_CHALLENGE_TTL = timedelta(seconds=300)

def store_challenge(key, options, env):
    """Persist a WebAuthn challenge options object, expiring in 5 minutes."""
    conn, c = open_database(env, with_connection=True)
    expires_at = datetime.utcnow() + _CHALLENGE_TTL
    c.execute(
        "INSERT OR REPLACE INTO webauthn_challenges (key, options, expires_at) VALUES (?, ?, ?)",
        (key, pickle.dumps(options), expires_at),
    )
    conn.commit()

def get_and_delete_challenge(key, env):
    """Retrieve and atomically delete a non-expired challenge; returns None if missing/expired."""
    conn, c = open_database(env, with_connection=True)
    c.execute(
        "SELECT options FROM webauthn_challenges WHERE key=? AND expires_at > ?",
        (key, datetime.utcnow()),
    )
    row = c.fetchone()
    if row is None:
        return None
    c.execute("DELETE FROM webauthn_challenges WHERE key=?", (key,))
    conn.commit()
    return pickle.loads(row[0])

def clean_expired_challenges(env):
    """Delete all expired challenge rows."""
    conn, c = open_database(env, with_connection=True)
    c.execute(
        "DELETE FROM webauthn_challenges WHERE expires_at <= ?",
        (datetime.utcnow(),),
    )
    conn.commit()
