"""
PQC Audio Sender Panel — Flask + WebSocket
Browser captures mic via getUserMedia() → sends PCM over WebSocket → server encrypts → UDP.
Works on any device with a browser (laptop, phone, tablet).
"""

import socket, threading, requests, json, time, os, struct, math
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import crypto_utils
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify, redirect
from flask_socketio import SocketIO, emit

# ─── Audio Config ───────────────────────────────────
CHUNK = 1024
RATE = 16000
REGISTRY_URL_DEFAULT = "http://127.0.0.1:5001"


def get_local_ip(registry_url=None):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if registry_url:
            host = urlparse(registry_url).hostname
            if host and not host.startswith("127.") and host != "localhost":
                s.connect((host, 5001))
            else:
                s.connect(("8.8.8.8", 80))
        else:
            s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        try: return socket.gethostbyname(socket.gethostname())
        except: return "127.0.0.1"


# ═══════════════════════════════════════════════════
#  CORE: Network, User
# ═══════════════════════════════════════════════════

class NetworkHandler:
    def __init__(self):
        self.listen_sock = None
        self.send_sock = None
        self.target_ip = None
        self.target_port = None
        self.running = False
        self.session_key = None
        self.packet_counter_send = 0
        self.crypt = None
        self.pkts_sent = self.pkts_recv = self.pkts_lost = 0
        self.bytes_sent = self.bytes_recv = 0
        self.sender_obfuscation = True
        self.latency_ms = 0.0
        self.jitter_ms = 0.0
        self._prev_latency = 0.0
        self.latency_history = []
        self.throughput_history = []
        self._call_start_time = 0
        self._last_throughput_check = 0
        self._last_bytes_sent = self._last_bytes_recv = 0

    def set_session_key(self, key):
        self.session_key = key
        self.crypt = AESGCM(key)
        self.packet_counter_send = 0
        self.pkts_sent = self.pkts_recv = self.pkts_lost = 0
        self.bytes_sent = self.bytes_recv = 0
        self.latency_ms = self.jitter_ms = self._prev_latency = 0.0
        self.latency_history = []
        self.throughput_history = []
        self._call_start_time = time.time()
        self._last_throughput_check = time.time()
        self._last_bytes_sent = self._last_bytes_recv = 0

    def start_listening(self, port):
        self.running = True
        if self.listen_sock:
            try: self.listen_sock.close()
            except: pass
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listen_sock.bind(('0.0.0.0', int(port)))
        self.listen_sock.settimeout(1.0)
        if self.send_sock:
            try: self.send_sock.close()
            except: pass
        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send_data(self, audio_data):
        """
        Packet: nonce(12) + index(4) + encrypted(timestamp(8) + obf_flag(1) + audio)
        Always obfuscates ALL audio when sender_obfuscation ON.
        """
        if self.target_ip and self.target_port and self.session_key and self.send_sock:
            try:
                idx = self.packet_counter_send
                if self.sender_obfuscation:
                    payload = crypto_utils.obfuscate_audio(audio_data, self.session_key, idx)
                    obf_flag = b'\x01'
                else:
                    payload = audio_data
                    obf_flag = b'\x00'
                nonce = os.urandom(12)
                index_bytes = idx.to_bytes(4, 'big')
                ts = struct.pack('!d', time.time())
                plaintext = ts + obf_flag + payload
                ciphertext = self.crypt.encrypt(nonce, plaintext, associated_data=index_bytes)
                packet = nonce + index_bytes + ciphertext
                self.send_sock.sendto(packet, (self.target_ip, int(self.target_port)))
                self.packet_counter_send += 1
                self.pkts_sent += 1
                self.bytes_sent += len(packet)
            except Exception as e:
                print(f"[SEND ERR] {e}")

    def record_metrics_snapshot(self):
        now = time.time()
        elapsed = now - self._call_start_time
        self.latency_history.append((elapsed, self.latency_ms))
        dt = now - self._last_throughput_check
        if dt > 0:
            tx = (self.bytes_sent - self._last_bytes_sent) / dt / 1024.0
            rx = (self.bytes_recv - self._last_bytes_recv) / dt / 1024.0
            self.throughput_history.append((elapsed, tx, rx))
        self._last_throughput_check = now
        self._last_bytes_sent = self.bytes_sent
        self._last_bytes_recv = self.bytes_recv

    def stop(self):
        self.running = False
        for s in [self.listen_sock, self.send_sock]:
            if s:
                try: s.close()
                except: pass
        self.listen_sock = self.send_sock = None


class UserManager:
    def __init__(self, registry_url):
        self.registry_url = registry_url.rstrip('/')
        self.username = None
        self.public_key = None
        self.secret_key = None
        self.listening_port = None

    def register(self, username, port):
        try:
            self.public_key, self.secret_key = crypto_utils.kyber_generate_keypair()
            pk_hex = self.public_key.hex()
            uname = username.strip().lower()
            my_real_ip = get_local_ip(self.registry_url)
            payload = {
                "username": uname, "public_key": pk_hex,
                "listening_ip": my_real_ip, "listening_port": port
            }
            resp = requests.post(f"{self.registry_url}/register", json=payload)
            if resp.status_code in [200, 201]:
                self.username = uname
                self.listening_port = port
                return True, resp.json().get("message")
            return False, resp.json().get("message", "Registration failed")
        except Exception as e:
            return False, str(e)

    def initiate_call(self, callee_username):
        try:
            uname = callee_username.strip().lower()
            resp = requests.get(f"{self.registry_url}/fetch/{uname}")
            if resp.status_code != 200:
                return False, f"User {uname} not found", None
            data = resp.json()
            callee_pk = bytes.fromhex(data['public_key'])
            session_key, ciphertext = crypto_utils.kyber_encapsulate(callee_pk)
            payload = {
                "caller": self.username, "callee": uname,
                "caller_listen_port": self.listening_port,
                "session_key_ciphertext": ciphertext.hex()
            }
            call_resp = requests.post(f"{self.registry_url}/call/initiate", json=payload)
            if call_resp.status_code != 200:
                return False, call_resp.json().get("message"), None
            cd = call_resp.json()
            return True, cd['call_id'], (cd.get('callee_ip'), cd.get('callee_port'), session_key)
        except Exception as e:
            return False, str(e), None

    def fetch_online_users(self):
        try:
            resp = requests.get(f"{self.registry_url}/list", timeout=1)
            if resp.status_code == 200:
                data = resp.json()
                users_raw = data.get("users", [])
                if isinstance(users_raw, list):
                    return [u["username"] for u in users_raw
                            if u.get("username") != self.username]
                elif isinstance(users_raw, dict):
                    return [u for u in users_raw.keys() if u != self.username]
        except: pass
        return []

    def check_call_status(self, call_id):
        try:
            resp = requests.get(f"{self.registry_url}/call/status/{call_id}", timeout=1)
            if resp.status_code == 200:
                return resp.json().get("status")
        except: pass
        return "unknown"

    def hangup_call(self, call_id):
        try:
            requests.post(f"{self.registry_url}/call/hangup",
                          json={"call_id": call_id}, timeout=1)
        except: pass

    def unregister(self):
        if self.username:
            try: requests.delete(f"{self.registry_url}/unregister/{self.username}")
            except: pass


# ═══════════════════════════════════════════════════
#  APP STATE
# ═══════════════════════════════════════════════════

network = NetworkHandler()
user_mgr = None
my_ip = get_local_ip()
my_listen_port = 50007
is_call_active = False
peer_username = ""
peer_ip = ""
call_start_time = 0
active_call_id = None
status_log = []


def add_log(msg, level="info"):
    global status_log
    status_log.insert(0, {"msg": msg, "level": level, "time": time.strftime("%H:%M:%S")})
    if len(status_log) > 30:
        status_log = status_log[:30]


def call_monitor_loop():
    global is_call_active, active_call_id, peer_username, peer_ip
    while is_call_active and active_call_id and user_mgr:
        try:
            status = user_mgr.check_call_status(active_call_id)
            if status in ('ended', 'rejected'):
                is_call_active = False
                add_log(f"Call ended by {peer_username}", "info")
                peer_username = ""
                peer_ip = ""
                active_call_id = None
                return
        except: pass
        time.sleep(2)


# ═══════════════════════════════════════════════════
#  FLASK + SOCKETIO
# ═══════════════════════════════════════════════════

_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__,
            template_folder=os.path.join(_DIR, 'sender_templates'),
            static_folder=os.path.join(_DIR, 'sender_static'),
            static_url_path='/static')
app.config['SECRET_KEY'] = 'pqc-sender-secret'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')


@app.route('/')
def index():
    if user_mgr and user_mgr.username:
        return redirect('/dashboard')
    return render_template('sender_login.html', my_ip=my_ip, default_url=REGISTRY_URL_DEFAULT)


@app.route('/login', methods=['POST'])
def do_login():
    global user_mgr, my_ip
    reg_url = request.form.get('registry_url', REGISTRY_URL_DEFAULT).strip()
    username = request.form.get('username', '').strip()
    if not username:
        return render_template('sender_login.html', my_ip=my_ip, default_url=reg_url, error="Username required")
    if reg_url and not reg_url.startswith("http"):
        reg_url = f"http://{reg_url}"
    if ":" not in reg_url[7:]:
        reg_url = f"{reg_url}:5001"
    my_ip = get_local_ip(reg_url)
    user_mgr = UserManager(reg_url)
    ok, msg = user_mgr.register(username, my_listen_port)
    if ok:
        try:
            network.start_listening(my_listen_port)
        except Exception as e:
            return render_template('sender_login.html', my_ip=my_ip, default_url=reg_url, error=f"Port error: {e}")
        add_log(f"Registered as {username}", "success")
        return redirect('/dashboard')
    else:
        return render_template('sender_login.html', my_ip=my_ip, default_url=reg_url, error=msg)


@app.route('/dashboard')
def dashboard():
    if not user_mgr or not user_mgr.username:
        return redirect('/')
    return render_template('sender_dashboard.html',
        username=user_mgr.username, my_ip=my_ip,
        is_call_active=is_call_active, peer=peer_username)


# ─── WebSocket: receive mic audio from browser ──────

@socketio.on('audio_chunk')
def handle_audio_chunk(data):
    """Browser sends Int16 PCM audio chunks via WebSocket."""
    if is_call_active and network.session_key:
        # data is raw bytes (Int16 PCM from browser)
        network.send_data(data)


# ─── HTTP API ──────────────────────────────────────

@app.route('/api/online-users')
def api_online_users():
    if not user_mgr: return jsonify({"users": []})
    return jsonify({"users": user_mgr.fetch_online_users()})


@app.route('/api/call', methods=['POST'])
def api_call():
    global is_call_active, peer_username, peer_ip, call_start_time, active_call_id
    target = request.json.get('target', '').strip()
    if not target: return jsonify({"ok": False, "msg": "No target"})
    ok, call_id, details = user_mgr.initiate_call(target)
    if not ok:
        add_log(f"Call to {target} failed: {call_id}", "error")
        return jsonify({"ok": False, "msg": str(call_id)})
    ip, port, key = details
    peer_username = target
    peer_ip = ip
    add_log(f"Dialing {target}...", "info")

    def wait_answer():
        global is_call_active, call_start_time, active_call_id
        for _ in range(30):
            st = user_mgr.check_call_status(call_id)
            if st == 'active':
                network.target_ip, network.target_port = ip, int(port)
                network.set_session_key(key)
                is_call_active = True
                call_start_time = time.time()
                active_call_id = call_id
                threading.Thread(target=call_monitor_loop, daemon=True).start()
                add_log(f"Call connected with {target}!", "success")
                return
            elif st in ('rejected', 'ended'):
                add_log(f"Call to {target} was {st}", "error")
                return
            time.sleep(1)
        add_log(f"Call to {target} timed out", "error")

    threading.Thread(target=wait_answer, daemon=True).start()
    return jsonify({"ok": True, "msg": "Dialing..."})


@app.route('/api/hangup', methods=['POST'])
def api_hangup():
    global is_call_active, peer_username, peer_ip, active_call_id
    is_call_active = False
    if active_call_id and user_mgr:
        user_mgr.hangup_call(active_call_id)
    result = {
        "duration": time.time() - call_start_time if call_start_time else 0,
        "pkts_sent": network.pkts_sent,
        "pkts_recv": network.pkts_recv,
        "pkts_lost": network.pkts_lost,
        "bytes_sent": network.bytes_sent,
        "bytes_recv": network.bytes_recv,
        "latency_history": network.latency_history[-60:],
        "throughput_history": network.throughput_history[-60:]
    }
    add_log(f"Call with {peer_username} ended", "info")
    peer_username = ""
    peer_ip = ""
    active_call_id = None
    return jsonify({"ok": True, "stats": result})


@app.route('/api/toggle-obfuscation', methods=['POST'])
def api_toggle_obf():
    network.sender_obfuscation = not network.sender_obfuscation
    state = "ON" if network.sender_obfuscation else "OFF"
    add_log(f"Obfuscation {state}", "success" if network.sender_obfuscation else "warn")
    return jsonify({"enabled": network.sender_obfuscation})


@app.route('/api/metrics')
def api_metrics():
    network.record_metrics_snapshot()
    elapsed = time.time() - call_start_time if call_start_time and is_call_active else 0
    tp_tx = tp_rx = 0
    if network.throughput_history:
        tp_tx = network.throughput_history[-1][1]
        tp_rx = network.throughput_history[-1][2]
    return jsonify({
        "active": is_call_active,
        "peer": peer_username,
        "elapsed": int(elapsed),
        "pkts_sent": network.pkts_sent,
        "pkts_recv": network.pkts_recv,
        "pkts_lost": network.pkts_lost,
        "bytes_sent": network.bytes_sent,
        "bytes_recv": network.bytes_recv,
        "latency": round(network.latency_ms, 1),
        "jitter": round(network.jitter_ms, 1),
        "tp_tx": round(tp_tx, 1),
        "tp_rx": round(tp_rx, 1),
        "obfuscation": network.sender_obfuscation,
        "pipeline": "Kyber-512 → XOR → AES-256-GCM"
    })


@app.route('/api/logs')
def api_logs():
    return jsonify({"logs": status_log})


@app.route('/api/status')
def api_status():
    return jsonify({
        "logged_in": user_mgr is not None and user_mgr.username is not None,
        "username": user_mgr.username if user_mgr else None,
        "call_active": is_call_active,
        "peer": peer_username,
        "my_ip": my_ip
    })


@app.route('/logout')
def logout():
    global user_mgr, is_call_active, active_call_id
    if is_call_active and active_call_id and user_mgr:
        user_mgr.hangup_call(active_call_id)
    is_call_active = False
    active_call_id = None
    if user_mgr:
        user_mgr.unregister()
        user_mgr = None
    network.stop()
    return redirect('/')


if __name__ == "__main__":
    print("=" * 50)
    print("  PQC Sender Panel — WebSocket Audio")
    print(f"  Open http://localhost:5002 in browser")
    print(f"  Phone: http://{my_ip}:5002")
    print(f"  UDP port: {my_listen_port}")
    print("=" * 50)
    socketio.run(app, host='0.0.0.0', port=5002, debug=False, allow_unsafe_werkzeug=True)
