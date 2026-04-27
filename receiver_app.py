"""
PQC Audio Receiver Panel — Flask + WebSocket
Receives encrypted UDP → decrypts → streams PCM to browser via WebSocket.
Works on any device with a browser (laptop, phone, tablet).

Case B fix: VAD on receiver side — de-obfuscate to check if original was speech,
play silence for quiet periods, garbled for speech when deobf OFF.
"""

import socket, threading, requests, json, time, queue, os, struct, math
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import crypto_utils
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify, redirect
from flask_socketio import SocketIO, emit

# ─── Audio Config ───────────────────────────────────
CHUNK = 1024
RATE = 16000
REGISTRY_URL_DEFAULT = "http://127.0.0.1:5001"
SILENCE_THRESHOLD = 300


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


def is_silent(audio_data, threshold=SILENCE_THRESHOLD):
    """Voice Activity Detection: returns True if audio chunk is silence."""
    count = len(audio_data) // 2
    if count == 0:
        return True
    samples = struct.unpack(f'<{count}h', audio_data[:count * 2])
    rms = math.sqrt(sum(s * s for s in samples) / count)
    return rms < threshold


# ═══════════════════════════════════════════════════
#  CORE: Network, User
# ═══════════════════════════════════════════════════

class NetworkHandler:
    def __init__(self):
        self.listen_sock = None
        self.target_ip = None
        self.target_port = None
        self.running = False
        self.session_key = None
        self.crypt = None
        self.pkts_sent = self.pkts_recv = self.pkts_lost = 0
        self.bytes_sent = self.bytes_recv = 0
        self.receiver_deobfuscation = True
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
        self.pkts_sent = self.pkts_recv = self.pkts_lost = 0
        self.bytes_sent = self.bytes_recv = 0
        self.latency_ms = self.jitter_ms = self._prev_latency = 0.0
        self.latency_history = []
        self.throughput_history = []
        self._call_start_time = time.time()
        self._last_throughput_check = time.time()
        self._last_bytes_sent = self._last_bytes_recv = 0

    def start_listening(self, port, on_recv):
        self.running = True
        if self.listen_sock:
            try: self.listen_sock.close()
            except: pass
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listen_sock.bind(('0.0.0.0', int(port)))
        self.listen_sock.settimeout(1.0)

        def listen():
            while self.running:
                try:
                    data, addr = self.listen_sock.recvfrom(CHUNK * 4)
                    on_recv(data, addr[0], addr[1])
                except socket.timeout:
                    continue
                except:
                    if self.running: pass
        threading.Thread(target=listen, daemon=True).start()

    def process_incoming_packet(self, data):
        """
        Decrypt packet. Returns (clear_audio, obfuscated_audio, obf_flag).
        """
        if not self.session_key: return None, None, 0
        try:
            if len(data) < 25: return None, None, 0
            nonce, index_bytes, ciphertext = data[:12], data[12:16], data[16:]
            idx = int.from_bytes(index_bytes, 'big')
            plaintext = self.crypt.decrypt(nonce, ciphertext, associated_data=index_bytes)
            send_ts = struct.unpack('!d', plaintext[:8])[0]
            obf_flag = plaintext[8]
            audio_payload = plaintext[9:]
            now = time.time()
            new_lat = (now - send_ts) * 1000
            if new_lat < 0: new_lat = 0
            if new_lat > 5000: new_lat = self.latency_ms
            self.jitter_ms = abs(new_lat - self._prev_latency) * 0.1 + self.jitter_ms * 0.9
            self._prev_latency = self.latency_ms
            self.latency_ms = new_lat * 0.3 + self.latency_ms * 0.7
            self.pkts_recv += 1
            self.bytes_recv += len(data)
            if obf_flag == 1:
                clear = crypto_utils.deobfuscate_audio(audio_payload, self.session_key, idx)
                return clear, audio_payload, 1
            else:
                return audio_payload, audio_payload, 0
        except Exception as e:
            self.pkts_lost += 1
            return None, None, 0

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
        if self.listen_sock:
            try: self.listen_sock.close()
            except: pass
        self.listen_sock = None


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

    def accept_call(self, call_id, ciphertext_hex):
        try:
            ciphertext = bytes.fromhex(ciphertext_hex)
            session_key = crypto_utils.kyber_decapsulate(ciphertext, self.secret_key)
            resp = requests.post(f"{self.registry_url}/call/accept", json={"call_id": call_id})
            if resp.status_code == 200:
                data = resp.json()
                return True, (data.get('caller_ip'), data.get('caller_port'), session_key)
            return False, None
        except Exception as e:
            print(f"Accept error: {e}")
            return False, None

    def poll_pending_calls(self):
        if not self.username: return []
        try:
            resp = requests.get(f"{self.registry_url}/call/pending/{self.username}", timeout=1)
            if resp.status_code == 200:
                return resp.json().get("pending_calls", [])
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
my_listen_port = 50008
is_call_active = False
peer_username = ""
peer_ip = ""
call_start_time = 0
active_call_id = None
audio_queue = queue.Queue()
incoming_calls = []
status_log = []


def add_log(msg, level="info"):
    global status_log
    status_log.insert(0, {"msg": msg, "level": level, "time": time.strftime("%H:%M:%S")})
    if len(status_log) > 30:
        status_log = status_log[:30]


def on_packet_received(data, sender_ip, sender_port):
    """
    Core obfuscation cases (receiver side):

    obf_flag=0 (sender obfuscation OFF) → play raw clear audio (Case C)
    obf_flag=1 (sender obfuscation ON):
      receiver_deobfuscation ON  → play de-obfuscated clear audio (Case A)
      receiver_deobfuscation OFF → VAD check on clear audio:
        speech → play garbled obfuscated audio (Case B: distorted)
        silence → play silence bytes (Case B: quiet)
    """
    global is_call_active
    if not is_call_active: return
    if peer_ip and sender_ip != peer_ip: return
    clear, obf, obf_flag = network.process_incoming_packet(data)
    if clear is None: return

    if obf_flag == 0:
        aud = clear
    elif network.receiver_deobfuscation:
        aud = clear
    else:
        # Case B: identity protection
        if is_silent(clear):
            aud = b'\x00' * len(obf)
        else:
            aud = obf

    audio_queue.put(aud)


def audio_stream_loop():
    """Stream audio to browser via WebSocket."""
    while is_call_active:
        try:
            chunk = audio_queue.get(timeout=0.1)
            # Send raw Int16 PCM bytes to browser for playback
            socketio.emit('audio_playback', chunk)
        except:
            pass


def poll_incoming():
    global incoming_calls
    while user_mgr and user_mgr.username:
        if not is_call_active:
            calls = user_mgr.poll_pending_calls()
            if calls:
                incoming_calls = calls
        time.sleep(2)


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
            template_folder=os.path.join(_DIR, 'receiver_templates'),
            static_folder=os.path.join(_DIR, 'receiver_static'),
            static_url_path='/static')
app.config['SECRET_KEY'] = 'pqc-receiver-secret'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')


@app.route('/')
def index():
    if user_mgr and user_mgr.username:
        return redirect('/dashboard')
    return render_template('receiver_login.html', my_ip=my_ip, default_url=REGISTRY_URL_DEFAULT)


@app.route('/login', methods=['POST'])
def do_login():
    global user_mgr, my_ip
    reg_url = request.form.get('registry_url', REGISTRY_URL_DEFAULT).strip()
    username = request.form.get('username', '').strip()
    if not username:
        return render_template('receiver_login.html', my_ip=my_ip, default_url=reg_url, error="Username required")
    if reg_url and not reg_url.startswith("http"):
        reg_url = f"http://{reg_url}"
    if ":" not in reg_url[7:]:
        reg_url = f"{reg_url}:5001"
    my_ip = get_local_ip(reg_url)
    user_mgr = UserManager(reg_url)
    ok, msg = user_mgr.register(username, my_listen_port)
    if ok:
        try:
            network.start_listening(my_listen_port, on_packet_received)
        except Exception as e:
            return render_template('receiver_login.html', my_ip=my_ip, default_url=reg_url, error=f"Port error: {e}")
        add_log(f"Registered as {username}", "success")
        threading.Thread(target=poll_incoming, daemon=True).start()
        return redirect('/dashboard')
    else:
        return render_template('receiver_login.html', my_ip=my_ip, default_url=reg_url, error=msg)


@app.route('/dashboard')
def dashboard():
    if not user_mgr or not user_mgr.username:
        return redirect('/')
    return render_template('receiver_dashboard.html',
        username=user_mgr.username, my_ip=my_ip,
        is_call_active=is_call_active, peer=peer_username)


@app.route('/api/online-users')
def api_online_users():
    if not user_mgr: return jsonify({"users": []})
    return jsonify({"users": user_mgr.fetch_online_users()})


@app.route('/api/incoming-calls')
def api_incoming_calls():
    return jsonify({"calls": incoming_calls})


@app.route('/api/accept', methods=['POST'])
def api_accept():
    global is_call_active, peer_username, peer_ip, call_start_time, incoming_calls, active_call_id
    call_data = request.json
    call_id = call_data.get('call_id')
    ct_hex = call_data.get('session_key_ciphertext')
    caller = call_data.get('caller', '')
    ok, details = user_mgr.accept_call(call_id, ct_hex)
    if ok:
        ip, port, key = details
        peer_username = caller
        peer_ip = ip
        network.target_ip, network.target_port = ip, int(port)
        network.set_session_key(key)
        is_call_active = True
        call_start_time = time.time()
        active_call_id = call_id
        while not audio_queue.empty():
            try: audio_queue.get_nowait()
            except: break
        threading.Thread(target=audio_stream_loop, daemon=True).start()
        threading.Thread(target=call_monitor_loop, daemon=True).start()
        incoming_calls = []
        add_log(f"Call accepted from {caller}", "success")
        return jsonify({"ok": True})
    add_log(f"Failed to accept call from {caller}", "error")
    return jsonify({"ok": False, "msg": "Failed to accept"})


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
    network.receiver_deobfuscation = not network.receiver_deobfuscation
    state = "ON" if network.receiver_deobfuscation else "OFF"
    add_log(f"De-obfuscation {state}", "success" if network.receiver_deobfuscation else "warn")
    return jsonify({"enabled": network.receiver_deobfuscation})


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
        "deobfuscation": network.receiver_deobfuscation,
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
    print("  PQC Receiver Panel — WebSocket Audio")
    print(f"  Open http://localhost:5003 in browser")
    print(f"  Phone: http://{my_ip}:5003")
    print(f"  UDP port: {my_listen_port}")
    print("=" * 50)
    socketio.run(app, host='0.0.0.0', port=5003, debug=False, allow_unsafe_werkzeug=True)
