"""
PQC Audio - Local Key Registry Server
Runs on localhost:5001
Stores public key registrations in JSON file
"""

from flask import Flask, request, jsonify
import json
import os
from datetime import datetime

app = Flask(__name__)

# Key registry file (stores username -> public_key mappings)
KEY_REGISTRY_FILE = "key_registry.json"

def load_registry():
    """Load key registry from JSON file."""
    if os.path.exists(KEY_REGISTRY_FILE):
        try:
            with open(KEY_REGISTRY_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_registry(registry):
    """Save key registry to JSON file."""
    with open(KEY_REGISTRY_FILE, 'w') as f:
        json.dump(registry, f, indent=2)

# ==================== API ENDPOINTS ====================

@app.route('/register', methods=['POST'])
def register_key():
    """
    Register a user's public key with listening IP and port.
    
    Request Body:
    {
        "username": "alice",
        "public_key": "a3b4c5d6...",  // hex string
        "listening_ip": "192.168.1.100",
        "listening_port": 5000
    }
    
    Response:
    {
        "status": "success",
        "message": "User alice registered and listening on 192.168.1.100:5000",
        "username": "alice",
        "listening_address": "192.168.1.100:5000",
        "timestamp": "2025-12-22 10:30:45"
    }
    """
    try:
        data = request.json
        username = data.get('username', '').strip().lower()
        public_key = data.get('public_key', '').strip()
        public_key = data.get('public_key', '').strip()
        # Use the client-provided IP if it's a real LAN IP.
        # Only fall back to remote_addr if client sends 'internal' or '127.x'
        client_ip = data.get('listening_ip', 'internal').strip()
        if client_ip and client_ip != 'internal' and not client_ip.startswith('127.'):
            listening_ip = client_ip
        else:
            listening_ip = request.remote_addr
        listening_port = data.get('listening_port', 0)
        
        # Validation
        if not username or len(username) < 2:
            return jsonify({
                "status": "error",
                "message": "Username must be at least 2 characters"
            }), 400
        
        if not public_key or len(public_key) < 100:  # Kyber public key is ~1184 hex chars
            return jsonify({
                "status": "error",
                "message": "Invalid public key format"
            }), 400
        
        if not listening_ip:
            return jsonify({
                "status": "error",
                "message": "Listening IP address is required"
            }), 400
        
        if listening_port <= 0 or listening_port > 65535:
            return jsonify({
                "status": "error",
                "message": "Valid listening port (1-65535) is required"
            }), 400
        
        # Load registry, update, and save
        registry = load_registry()
        registry[username] = {
            "public_key": public_key,
            "listening_ip": listening_ip,
            "listening_port": listening_port,
            "registered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        save_registry(registry)
        
        return jsonify({
            "status": "success",
            "message": f"User {username} registered and listening on {listening_ip}:{listening_port}",
            "username": username,
            "listening_address": f"{listening_ip}:{listening_port}",
            "timestamp": registry[username]["registered_at"]
        }), 201
    
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Registration failed: {str(e)}"
        }), 500

@app.route('/fetch/<username>', methods=['GET'])
def fetch_key(username):
    """
    Fetch a user's public key and listening address.
    
    URL: /fetch/alice
    
    Response:
    {
        "status": "success",
        "username": "alice",
        "public_key": "a3b4c5d6...",
        "listening_ip": "192.168.1.100",
        "listening_port": 5000,
        "listening_address": "192.168.1.100:5000",
        "registered_at": "2025-12-22 10:30:45"
    }
    """
    try:
        username = username.strip().lower()
        registry = load_registry()
        
        if username not in registry:
            return jsonify({
                "status": "error",
                "message": f"User '{username}' not found in registry"
            }), 404
        
        user_data = registry[username]
        return jsonify({
            "status": "success",
            "username": username,
            "public_key": user_data["public_key"],
            "listening_ip": user_data.get("listening_ip", "unknown"),
            "listening_port": user_data.get("listening_port", 0),
            "listening_address": f"{user_data.get('listening_ip', 'unknown')}:{user_data.get('listening_port', 0)}",
            "registered_at": user_data.get("registered_at", "unknown")
        }), 200
    
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Fetch failed: {str(e)}"
        }), 500

@app.route('/list', methods=['GET'])
def list_users():
    """
    List all registered users with their listening addresses.
    
    URL: /list
    
    Response:
    {
        "status": "success",
        "total_users": 2,
        "users": [
            {
                "username": "alice",
                "listening_address": "192.168.1.100:5000",
                "registered_at": "2025-12-22 10:30:45"
            },
            {
                "username": "bob",
                "listening_address": "192.168.1.101:5000",
                "registered_at": "2025-12-22 10:35:20"
            }
        ]
    }
    """
    try:
        registry = load_registry()
        users = [
            {
                "username": username,
                "listening_address": f"{data.get('listening_ip', 'unknown')}:{data.get('listening_port', 0)}",
                "registered_at": data.get("registered_at", "unknown")
            }
            for username, data in registry.items()
        ]
        
        return jsonify({
            "status": "success",
            "total_users": len(users),
            "users": sorted(users, key=lambda x: x["username"])
        }), 200
    
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"List failed: {str(e)}"
        }), 500

@app.route('/unregister/<username>', methods=['DELETE'])
def unregister_key(username):
    """
    Unregister a user's public key.
    
    URL: /unregister/alice
    
    Response:
    {
        "status": "success",
        "message": "Public key unregistered for alice"
    }
    """
    try:
        username = username.strip().lower()
        registry = load_registry()
        
        if username not in registry:
            return jsonify({
                "status": "error",
                "message": f"User '{username}' not found"
            }), 404
        
        del registry[username]
        save_registry(registry)
        
        return jsonify({
            "status": "success",
            "message": f"Public key unregistered for {username}"
        }), 200
    
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Unregister failed: {str(e)}"
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "PQC Key Registry Server",
        "version": "1.0",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }), 200

# ============================================================
# CALL SIGNALING ENDPOINTS (for voice calls)
# ============================================================

# In-memory call sessions (stores active calls)
CALL_SESSIONS = {}

@app.route('/call/initiate', methods=['POST'])
def initiate_call():
    """
    Initiate a voice call.
    
    Request:
    {
        "caller": "alice",
        "callee": "bob",
        "caller_listen_port": 5555,
        "session_key_ciphertext": "..."  (Kyber encapsulated key)
    }
    
    Response:
    {
        "status": "success",
        "call_id": "uuid-string",
        "callee_ip": "192.168.1.x",
        "callee_listen_port": 5000,
        "timestamp": "2025-12-22 10:30:00"
    }
    """
    try:
        data = request.json
        caller = data.get('caller', '').strip().lower()
        callee = data.get('callee', '').strip().lower()
        caller_listen_port = data.get('caller_listen_port')
        session_key_ciphertext = data.get('session_key_ciphertext')
        
        if not all([caller, callee, caller_listen_port, session_key_ciphertext]):
            return jsonify({
                "status": "error",
                "message": "Missing required fields: caller, callee, caller_listen_port, session_key_ciphertext"
            }), 400
        
        # Validate callee exists and registered
        registry = load_registry()
        if callee not in registry:
            return jsonify({
                "status": "error",
                "message": f"Callee '{callee}' not registered"
            }), 404
        
        callee_info = registry[callee]
        
        # Generate call ID
        import uuid
        call_id = str(uuid.uuid4())
        
        # Store call session
        CALL_SESSIONS[call_id] = {
            'caller': caller,
            'callee': callee,
            'caller_ip': registry.get(caller, {}).get('listening_ip', request.remote_addr),
            'caller_port': caller_listen_port,
            'callee_ip': callee_info['listening_ip'],
            'callee_port': callee_info['listening_port'],
            'session_key_ciphertext': session_key_ciphertext,
            'status': 'ringing',
            'initiated_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'answered_at': None
        }
        
        return jsonify({
            "status": "success",
            "call_id": call_id,
            "message": f"Call initiated from {caller} to {callee}",
            "callee_ip": callee_info['listening_ip'],
            "callee_port": callee_info['listening_port'],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 200
    
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Call initiation failed: {str(e)}"
        }), 500

@app.route('/call/accept', methods=['POST'])
def accept_call():
    """
    Accept an incoming call.
    
    Request:
    {
        "call_id": "uuid-string"
    }
    
    Response:
    {
        "status": "success",
        "caller_ip": "192.168.1.x",
        "caller_listen_port": 5555,
        "session_key_ciphertext": "..."
    }
    """
    try:
        data = request.json
        call_id = data.get('call_id', '')
        
        if call_id not in CALL_SESSIONS:
            return jsonify({
                "status": "error",
                "message": f"Call '{call_id}' not found"
            }), 404
        
        call = CALL_SESSIONS[call_id]
        call['status'] = 'active'
        call['answered_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return jsonify({
            "status": "success",
            "message": "Call accepted",
            "caller_ip": call['caller_ip'],
            "caller_port": call['caller_port'],
            "callee_ip": call['callee_ip'],
            "callee_port": call['callee_port'],
            "session_key_ciphertext": call['session_key_ciphertext'],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 200
    
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Call acceptance failed: {str(e)}"
        }), 500

@app.route('/call/reject', methods=['POST'])
def reject_call():
    """
    Reject an incoming call.
    
    Request:
    {
        "call_id": "uuid-string"
    }
    
    Response:
    {
        "status": "success",
        "message": "Call rejected"
    }
    """
    try:
        data = request.json
        call_id = data.get('call_id', '')
        
        if call_id not in CALL_SESSIONS:
            return jsonify({
                "status": "error",
                "message": f"Call '{call_id}' not found"
            }), 404
        
        call = CALL_SESSIONS[call_id]
        call['status'] = 'rejected'
        
        return jsonify({
            "status": "success",
            "message": "Call rejected",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 200
    
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Call rejection failed: {str(e)}"
        }), 500

@app.route('/call/hangup', methods=['POST'])
def hangup_call():
    """
    End an active call.
    
    Request:
    {
        "call_id": "uuid-string"
    }
    
    Response:
    {
        "status": "success",
        "message": "Call ended"
    }
    """
    try:
        data = request.json
        call_id = data.get('call_id', '')
        
        if call_id not in CALL_SESSIONS:
            return jsonify({
                "status": "error",
                "message": f"Call '{call_id}' not found"
            }), 404
        
        call = CALL_SESSIONS[call_id]
        call['status'] = 'ended'
        call['ended_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Remove from active sessions after 60 seconds
        # (keep for call history briefly)
        
        return jsonify({
            "status": "success",
            "message": "Call ended",
            "duration": "call duration calculation",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 200
    
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Call hangup failed: {str(e)}"
        }), 500

@app.route('/call/status/<call_id>', methods=['GET'])
def call_status(call_id):
    """
    Get status of a call.
    
    URL: /call/status/uuid-string
    
    Response:
    {
        "call_id": "uuid-string",
        "status": "active|ringing|rejected|ended",
        "caller": "alice",
        "callee": "bob",
        "initiated_at": "2025-12-22 10:30:00",
        "answered_at": "2025-12-22 10:30:02"
    }
    """
    try:
        if call_id not in CALL_SESSIONS:
            return jsonify({
                "status": "error",
                "message": f"Call '{call_id}' not found"
            }), 404
        
        call = CALL_SESSIONS[call_id]
        
        return jsonify({
            "call_id": call_id,
            "status": call['status'],
            "caller": call['caller'],
            "callee": call['callee'],
            "initiated_at": call['initiated_at'],
            "answered_at": call['answered_at'],
            "caller_ip": call['caller_ip'],
            "caller_port": call['caller_port'],
            "callee_ip": call['callee_ip'],
            "callee_port": call['callee_port']
        }), 200
    
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Status check failed: {str(e)}"
        }), 500

@app.route('/call/pending/<username>', methods=['GET'])
def get_pending_calls(username):
    """
    Get all pending (incoming) calls for a specific user.
    
    Response:
    {
        "status": "success",
        "username": "bob",
        "pending_calls": [
            {
                "call_id": "uuid",
                "caller": "alice",
                "status": "ringing",
                "initiated_at": "2025-12-22 10:30:00",
                "session_key_ciphertext": "..."
            }
        ]
    }
    """
    try:
        username = username.strip().lower()
        
        # Find all calls where this user is the callee and status is ringing
        pending = []
        for call_id, call_info in CALL_SESSIONS.items():
            if call_info['callee'] == username and call_info['status'] == 'ringing':
                pending.append({
                    'call_id': call_id,
                    'caller': call_info['caller'],
                    'status': call_info['status'],
                    'initiated_at': call_info['initiated_at'],
                    'session_key_ciphertext': call_info['session_key_ciphertext']
                })
        
        return jsonify({
            "status": "success",
            "username": username,
            "pending_calls": pending
        }), 200
    
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to fetch pending calls: {str(e)}"
        }), 500

@app.route('/users/<username>', methods=['GET'])
def get_user_info(username):
    """
    Get information about a registered user.
    """
    try:
        username = username.strip().lower()
        registry = load_registry()
        
        if username not in registry:
            return jsonify({
                "status": "error",
                "message": f"User '{username}' not found"
            }), 404
        
        user = registry[username]
        return jsonify({
            "status": "success",
            "username": username,
            "public_key": user['public_key'],
            "listening_ip": user['listening_ip'],
            "listening_port": user['listening_port'],
            "registered_at": user.get('registered_at')
        }), 200
    
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to fetch user info: {str(e)}"
        }), 500

@app.route('/', methods=['GET'])
def info():
    """API information endpoint."""
    return jsonify({
        "service": "PQC Audio - Local Key Registry Server",
        "version": "2.0",
        "endpoints": {
            "registration": {
                "POST /register": "Register a public key with username",
                "GET /fetch/<username>": "Fetch public key by username",
                "GET /list": "List all registered users",
                "GET /users/<username>": "Get full user info",
                "DELETE /unregister/<username>": "Unregister a user"
            },
            "voice_calls": {
                "POST /call/initiate": "Initiate a voice call",
                "POST /call/accept": "Accept an incoming call",
                "POST /call/reject": "Reject an incoming call",
                "POST /call/hangup": "End an active call",
                "GET /call/status/<call_id>": "Get call status",
                "GET /call/pending/<username>": "Get pending calls for user"
            },
            "system": {
                "GET /health": "Health check",
                "GET /": "This info page"
            }
        },
        "docs": {
            "register": "POST /register with JSON: {username, public_key, listening_ip, listening_port}",
            "call_initiate": "POST /call/initiate with JSON: {caller, callee, caller_listen_port, session_key_ciphertext}",
            "call_accept": "POST /call/accept with JSON: {call_id}",
            "call_pending": "GET /call/pending/<username> - Get all ringing calls for user"
        }
    }), 200

if __name__ == '__main__':
    import os
    
    # Get host from environment variable or default to 0.0.0.0 (all interfaces)
    REGISTRY_HOST = os.getenv('REGISTRY_HOST', '0.0.0.0')
    REGISTRY_PORT = int(os.getenv('REGISTRY_PORT', 5001))
    
    print("=" * 60)
    print("      PQC KEY REGISTRY SERVER IS RUNNING")
    print("=" * 60)
    print(f" PORT: {REGISTRY_PORT}")
    print(f" STATUS: Online and Listening...")
    print("-" * 60)
    print(" HOW TO CONNECT FROM OTHER PCs:")
    
    import socket
    hostname = socket.gethostname()
    try:
        ips = socket.gethostbyname_ex(hostname)[2]
        for ip in ips:
            if not ip.startswith("127."):
                print(f" URL: http://{ip}:{REGISTRY_PORT}")
    except:
        print(f" URL: http://<your-computer-ip>:{REGISTRY_PORT}")
        
    print("-" * 60)
    print(" Check your IP using 'ipconfig' if unsure.")
    print("=" * 60)
    print()
    
    app.run(host=REGISTRY_HOST, port=REGISTRY_PORT, debug=False, use_reloader=False)
