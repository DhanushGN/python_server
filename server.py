from flask import Flask, request, jsonify
import rsa
import json
import time

app = Flask(__name__)

# Load keys
with open("server_private.pem", "rb") as f:
    server_priv = rsa.PrivateKey.load_pkcs1(f.read())

with open("clint_public.pem", "rb") as f:
    client_pub = rsa.PublicKey.load_pkcs1(f.read())

@app.route("/receive", methods=["POST"])
def server_receive():
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
