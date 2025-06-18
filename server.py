from flask import Flask, request, jsonify
import rsa
import json
import time
import os
import base64
app = Flask(__name__)

# Load from environment
API_SECRET = os.environ.get("AUTH_TOKEN")

# Load keys
with open("server_private.pem", "rb") as f:
    server_priv = rsa.PrivateKey.load_pkcs1(f.read())

with open("clint_public.pem", "rb") as f:
    client_pub = rsa.PublicKey.load_pkcs1(f.read())

@app.route("/receive", methods=["POST"])
def server_receive():
    token = request.headers.get("X-API-TOKEN")
    if token != API_SECRET:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        data = request.get_json()
        encrypted = bytes.fromhex(data['encrypted'])
        signature = bytes.fromhex(data['signature'])

        decrypted = rsa.decrypt(encrypted, server_priv)
        rsa.verify(decrypted, signature, client_pub)

        payload = json.loads(decrypted.decode())
        msg = payload["message"]
        timestamp = payload["timestamp"]

        current = int(time.time())
        if abs(current - timestamp) > 30:
            return jsonify({"status": "error", "message": "Timestamp expired!", "timestamp": timestamp}), 400
        
        response_payload = {
           "message": f"Encryption and Verification Successful and your message is {msg}",
            "timestamp": int(time.time())
        }
        response_message = json.dumps(response_payload).encode()
        encrypted_response = rsa.encrypt(response_message, client_pub)
        signature_response = rsa.sign(response_message, server_priv, "SHA-256")

        return jsonify({
            "status": "success",
            "message": msg,
            "timestamp": timestamp,
            "response_encrypted": encrypted_response.hex(),
            "response_signature": signature_response.hex()
        })

    except rsa.VerificationError:
        return jsonify({"status": "error", "message": "Signature verification failed"}), 403
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
