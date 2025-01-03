from flask import Flask, request, jsonify
from ledger_backend import LedgerBackend  # Import your backend class

app = Flask(__name__)
backend = LedgerBackend()

@app.route('/api/store_credentials', methods=['POST'])
def store_credentials():
    data = request.json
    user_id = data.get('user_id')
    username = data.get('username')
    password = data.get('password')
    hint = data.get('hint', '')

    if not user_id or not username or not password:
        return jsonify({"error": "Missing required fields"}), 400

    backend.store_credentials(user_id, username, password, hint)
    return jsonify({"message": "Credentials stored successfully"}), 200

@app.route('/api/retrieve_credentials/<user_id>', methods=['GET'])
def retrieve_credentials(user_id):
    creds = backend.retrieve_credentials(user_id)
    if not creds:
        return jsonify({"error": "User not found"}), 404

    return jsonify(creds), 200

if __name__ == '__main__':
    app.run(debug=True)
