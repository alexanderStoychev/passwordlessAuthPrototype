from flask import Flask, render_template, request, jsonify, session
from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    UserVerificationRequirement
)
import base64
import os

app = Flask(__name__)
app.secret_key = os.urandom(32)

# Set up RP info
rp = PublicKeyCredentialRpEntity(id="127.0.0.1", name="Passwordless Demo")

server = Fido2Server(rp)
users = {}

def encode_challenge(challenge):
    """
    Ensures the challenge is returned as a standard base64 string.
    If challenge is bytes, it uses base64.b64encode.
    If it's already a string (likely base64url), convert it to standard base64.
    """
    if isinstance(challenge, bytes):
        return base64.b64encode(challenge).decode()
    # Assume challenge is base64url-encoded; convert to standard base64.
    challenge_std = challenge.replace('-', '+').replace('_', '/')
    # Pad with '=' characters if necessary
    padding = len(challenge_std) % 4
    if padding:
        challenge_std += '=' * (4 - padding)
    return challenge_std

@app.route("/")
def index():
    return render_template("index.html")

# -------------------------
# REGISTER OPTIONS
# -------------------------
@app.route("/register/options", methods=["POST"])
def register_options():
    # Create a new user.
    user_id = os.urandom(16)
    user = PublicKeyCredentialUserEntity(
        id=user_id,
        name="testuser",
        display_name="Test User"
    )
    # Begin registration.
    reg_opts, state = server.register_begin(
        user,
        user_verification=UserVerificationRequirement.PREFERRED
    )
    # Save state and user info in session.
    session["state"] = state
    session["user"] = {
        "id": base64.b64encode(user.id).decode(),
        "name": user.name,
        "display_name": user.display_name
    }
    # Use the challenge from state and encode it properly.
    challenge = encode_challenge(state["challenge"])
    # Build options manually.
    options = {
        "challenge": challenge,
        "rp": {"id": rp.id, "name": rp.name},
        "user": {
            "id": base64.b64encode(user.id).decode(),
            "name": user.name,
            "displayName": user.display_name
        },
        "pubKeyCredParams": reg_opts.get("pubKeyCredParams", []),
        "timeout": reg_opts.get("timeout", 60000),
        "attestation": reg_opts.get("attestation", "none"),
        "authenticatorSelection": reg_opts.get("authenticatorSelection"),
        "excludeCredentials": reg_opts.get("excludeCredentials", [])
    }
    return jsonify(options)

# -------------------------
# REGISTER VERIFY
# -------------------------
@app.route("/register/verify", methods=["POST"])
def register_verify():
    data = request.get_json()
    client_data = {
        "clientDataJSON": base64.b64decode(data["response"]["clientDataJSON"]),
        "attestationObject": base64.b64decode(data["response"]["attestationObject"])
    }
    # Rebuild the user from session data.
    user = PublicKeyCredentialUserEntity(
        id=base64.b64decode(session["user"]["id"]),
        name=session["user"]["name"],
        display_name=session["user"]["display_name"]
    )
    auth_data = server.register_complete(session["state"], client_data)
    # Store the credential in the in-memory user store.
    users[user.name] = {
        "user": user,
        "cred": auth_data.credential_data
    }
    return "✅ Registered successfully!"

# -------------------------
# LOGIN OPTIONS
# -------------------------
@app.route("/login/options", methods=["POST"])
def login_options():
    user = users.get("testuser")
    if not user:
        return "User not registered", 404
    auth_opts, state = server.authenticate_begin(
        [user["cred"]],
        user_verification=UserVerificationRequirement.PREFERRED
    )
    session["login_state"] = state
    challenge = encode_challenge(state["challenge"])
    options = {
        "challenge": challenge,
        "timeout": auth_opts.get("timeout", 60000),
        "rpId": auth_opts.get("rpId", rp.id),
        "allowCredentials": [{
            "type": cred["type"],
            "id": base64.b64encode(cred["id"]).decode() if isinstance(cred["id"], bytes) else cred["id"],
            "transports": cred.get("transports", [])
        } for cred in auth_opts.get("allowCredentials", [])],
        "userVerification": auth_opts.get("userVerification", "preferred")
    }
    return jsonify(options)

# -------------------------
# LOGIN VERIFY
# -------------------------
@app.route("/login/verify", methods=["POST"])
def login_verify():
    data = request.get_json()
    # Build the assertion response mapping.
    assertion_response = {
        "credentialId": base64.b64decode(data["rawId"]),
        "clientDataJSON": base64.b64decode(data["response"]["clientDataJSON"]),
        "authenticatorData": base64.b64decode(data["response"]["authenticatorData"]),
        "signature": base64.b64decode(data["response"]["signature"]),
        "userHandle": base64.b64decode(data["response"]["userHandle"]) if data["response"]["userHandle"] else None
    }
    user = users.get("testuser")
    if not user:
        return "User not found", 404
    # Call authenticate_complete with the full assertion response as a mapping.
    server.authenticate_complete(
        session["login_state"],
        [user["cred"]],
        assertion_response
    )
    return "✅ Logged in successfully!"

if __name__ == "__main__":
    app.run(debug=True)
