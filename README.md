# MyChart Ledger

## Overview
MyChart Ledger is a secure, user-friendly application for managing user credentials, featuring:
- PyQt-based GUI for interaction
- Flask-based API backend
- SQLite database with encrypted credential storage

## Features
- Secure user login system
- Encrypted credential storage
- Password reset functionality with secure tokens
- Backend API integration

## Requirements
- Python 3.8+
- Dependencies:
  - PyQt5
  - cryptography
  - requests
  - flask

Install via:
```bash
pip install -r requirements.txt
```

## Setup
1. **Start Backend**
```bash
python app_api.py
```

2. **Launch Frontend**
```bash
python app.py
```

## Usage

### Authentication
Log in with your credentials through the GUI interface.

### API Examples
Store credentials:
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"user_id": "testuser", "username": "test", "password": "password123"}' \
  http://127.0.0.1:5000/api/store_credentials
```

### API Endpoints
- `POST /api/store_credentials`: Store user credentials
- `GET /api/retrieve_credentials/<user_id>`: Retrieve credentials
- Password reset functionality available through GUI

## Development
- SQLite database auto-initializes on first run
- Encryption ensures secure credential storage
- API runs on `http://127.0.0.1:5000`

## Contributing
1. Fork repository
2. Create feature branch
3. Commit changes:
```bash
git commit -m "Add feature or fix"
```
4. Submit pull request

## Troubleshooting
- **API Connection Issues**: Verify `app_api.py` is running on port 5000
- **Dependency Errors**: Reinstall requirements
```bash
pip install -r requirements.txt
```
