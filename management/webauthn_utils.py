import base64
import json
import sqlite3

from datetime import datetime
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticationCredential,
    AuthenticatorAttachment,
)

from mailconfig import open_database, get_mail_users

# Function to handle database operations for WebAuthn credentials

def get_webauthn_credentials(email, env):
    """Retrieve all WebAuthn credentials for a user."""
    c = open_database(env)
    c.execute(
        "SELECT id, credential_id, public_key, sign_count, transports, label, created_at FROM webauthn_credentials JOIN users ON webauthn_credentials.user_id = users.id WHERE users.email=?",
        (email,),
    )
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
            "created_at": row[6],
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
        "INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, transports, label) VALUES (?, ?, ?, ?, ?, ?)",
        (
            user_id,
            credential_data["credential_id"],
            credential_data["public_key"],
            credential_data["sign_count"],
            json.dumps(credential_data.get("transports", [])),
            label,
        ),
    )
    conn.commit()

def update_credential_sign_count(credential_id, new_sign_count, env):
    """Update the signature count for a credential."""
    conn, c = open_database(env, with_connection=True)
    c.execute(
        "UPDATE webauthn_credentials SET sign_count=? WHERE credential_id=?",
        (new_sign_count, credential_id),
    )
    conn.commit()


# WebAuthn Logic Wrappers

def begin_registration(email, env, rp_id, rp_name):
    """Generate registration options."""
    # Get existing credentials to exclude them
    existing_credentials = get_webauthn_credentials(email, env)
    
    # Simple user handle (using email as ID for simplicity, though internal ID is better strictly speaking, 
    # but existing auth uses email heavily)
    # Using byte representation of email for user_id in WebAuthn
    user_id_bytes = email.encode('utf-8')

    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=user_id_bytes,
        user_name=email,
        exclude_credentials=[
            {"id": base64url_to_bytes(cred["credential_id"]), "transports": cred["transports"]}
            for cred in existing_credentials
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED,
            resident_key=None, #/Requirement.PREFERRED,
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM, 

        ),
    )
    return options

def complete_registration(email, options, response_data, env, rp_id):
    """Verify registration response and store credential."""
    try:
        credential = verify_registration_response(
            credential=RegistrationCredential.parse_raw(response_data),
            expected_challenge=base64url_to_bytes(options.challenge),
            expected_origin=f"https://{rp_id}", # Or configure globally
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
    # Assuming email is provided for now as per requirements.
    
    existing_credentials = get_webauthn_credentials(email, env)
    if not existing_credentials:
         raise ValueError("No WebAuthn credentials found for this user.")

    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[
            {"id": base64url_to_bytes(cred["credential_id"]), "transports": cred["transports"]}
            for cred in existing_credentials
        ],
         user_verification=UserVerificationRequirement.PREFERRED,
    )
    return options

def complete_authentication(options, response_data, env, rp_id):
    """Verify authentication response."""
    
    # Parse response first to get credential ID
    # We need to find the stored public key for this credential ID
    
    # This part is tricky because we need to parse JSON first to look up DB
    # or use the library's struct
    
    auth_cred = AuthenticationCredential.parse_raw(response_data)
    credential_id_b64 = base64.urlsafe_b64encode(auth_cred.id).decode('ascii').rstrip('=')
    
    # Retrieve stored credential
    stored_cred = get_credential_by_id(credential_id_b64, env)
    if not stored_cred:
        raise ValueError("Credential not found.")

    try:
        verification = verify_authentication_response(
            credential=auth_cred,
            expected_challenge=base64url_to_bytes(options.challenge),
            expected_origin=f"https://{rp_id}",
            expected_rp_id=rp_id,
            credential_public_key=base64url_to_bytes(stored_cred["public_key"]),
            credential_current_sign_count=stored_cred["sign_count"],
            require_user_verification=False, # Adjust based on requirement
        )
    except Exception as e:
        raise ValueError(f"Authentication failed: {str(e)}")
        
    # Update sign count
    update_credential_sign_count(credential_id_b64, verification.new_sign_count, env)
    
    return stored_cred["user_id"]
