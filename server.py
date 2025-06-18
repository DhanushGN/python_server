from flask import Flask, request, jsonify
import rsa
import json
import time
import os

app = Flask(__name__)

# Load from environment
API_SECRET = os.environ.get("AUTH_TOKEN")

# If PEM keys are stored as base64 strings in Render
server_priv = base64.b64decode(os.environ.get("SERVER_PRIV"))
client_pub = base64.b64decode(os.environ.get("CLINT_PUB"))


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

        return jsonify({
            "status": "success",
            "message": msg,
            "timestamp": timestamp
        })

    except rsa.VerificationError:
        return jsonify({"status": "error", "message": "Signature verification failed"}), 403
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
