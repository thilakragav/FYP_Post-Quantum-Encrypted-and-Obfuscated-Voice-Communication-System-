import pickle
import hashlib
import json
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqc.kem import kyber512 as kemalg
from pydub import AudioSegment

# Generate Kyber KEM keypair (receiver does this)
def kyber_generate_keypair():
    pk, sk = kemalg.keypair()
    return pk, sk

# Sender: Establish PQ session (needs receiver's public key)
def kyber_encapsulate(receiver_pk):
    session_key, ciphertext = kemalg.encap(receiver_pk)
    return session_key, ciphertext

# Receiver: Derive session from ciphertext + sk
def kyber_decapsulate(ciphertext, sk):
    session_key = kemalg.decap(ciphertext, sk)
    return session_key

# Derive obfuscation key stream from session key using SHAKE-256
def derive_obfuscation_key(session_key, chunk_index, length=2048):
    """Derive a full-length unique key stream for each chunk using SHAKE-256.
    
    Unlike SHA-256 (32 bytes repeating), SHAKE-256 produces a key stream
    as long as the audio data, ensuring every byte is XOR'd with a unique
    pseudo-random byte. This makes the obfuscated audio fully unintelligible.
    """
    h = hashlib.shake_256()
    h.update(session_key)
    h.update(chunk_index.to_bytes(4, "big"))
    return h.digest(length)

# Obfuscate audio data using the session key (identity obfuscation)
def obfuscate_audio(audio_data, session_key, chunk_index):
    """XOR obfuscate audio data using a full-length derived key stream."""
    obf_key = derive_obfuscation_key(session_key, chunk_index, len(audio_data))
    obfuscated = bytearray(audio_data)
    for i in range(len(obfuscated)):
        obfuscated[i] ^= obf_key[i]
    return bytes(obfuscated)

# De-obfuscate audio data using the session key
def deobfuscate_audio(obfuscated_data, session_key, chunk_index):
    """Reverse XOR obfuscation using the same key stream."""
    obf_key = derive_obfuscation_key(session_key, chunk_index, len(obfuscated_data))
    deobfuscated = bytearray(obfuscated_data)
    for i in range(len(deobfuscated)):
        deobfuscated[i] ^= obf_key[i]
    return bytes(deobfuscated)

# Encrypt .wav in chunks with AES-GCM using session key + identity obfuscation
def encrypt_audio_chunks(audio_file, session_key, chunk_ms=2000):
    audio = AudioSegment.from_file(audio_file, format="wav")
    chunks = [audio[i:i+chunk_ms] for i in range(0, len(audio), chunk_ms)]
    aesgcm = AESGCM(session_key)
    base_nonce = b"noncebase"
    encrypted_chunks = []
    obfuscated_chunks = []  # Store obfuscated chunks for preview
    for idx, chunk in enumerate(chunks):
        raw = chunk.raw_data
        # Step 1: Apply identity obfuscation using the session key
        obfuscated = obfuscate_audio(raw, session_key, idx)
        obfuscated_chunks.append((obfuscated, chunk.frame_rate, chunk.sample_width, chunk.channels))
        # Step 2: Encrypt the obfuscated data
        nonce = base_nonce + idx.to_bytes(4, "big")
        ct = aesgcm.encrypt(nonce, obfuscated, None)
        encrypted_chunks.append((nonce, ct, chunk.frame_rate, chunk.sample_width, chunk.channels))
    return encrypted_chunks, obfuscated_chunks

def save_obfuscated_audio(obfuscated_chunks, output_file="obfuscated_audio.wav"):
    """Save the obfuscated audio (before encryption) for preview on sender side."""
    obfuscated_audio_chunks = []
    for obfuscated_data, fr, sw, ch in obfuscated_chunks:
        chunk = AudioSegment(
            data=obfuscated_data, sample_width=sw, frame_rate=fr, channels=ch
        )
        obfuscated_audio_chunks.append(chunk)
    if obfuscated_audio_chunks:
        full_audio = sum(obfuscated_audio_chunks)
        full_audio.export(output_file, format="wav")
    return output_file

def decrypt_and_show_obfuscated(encrypted_chunks, session_key, output_file="obfuscated_received.wav"):
    """Decrypt but keep obfuscated (for receiver to see unrecognizable audio)."""
    aesgcm = AESGCM(session_key)
    obfuscated_chunks = []
    for idx, (nonce, ct, fr, sw, ch) in enumerate(encrypted_chunks):
        # Only decrypt, don't de-obfuscate
        obfuscated = aesgcm.decrypt(nonce, ct, None)
        chunk = AudioSegment(
            data=obfuscated, sample_width=sw, frame_rate=fr, channels=ch
        )
        obfuscated_chunks.append(chunk)
    full_audio = sum(obfuscated_chunks)
    full_audio.export(output_file, format="wav")
    return output_file

def decrypt_audio_chunks(encrypted_chunks, session_key, output_file="decrypted_audio.wav"):
    aesgcm = AESGCM(session_key)
    decrypted_chunks = []
    for idx, (nonce, ct, fr, sw, ch) in enumerate(encrypted_chunks):
        # Step 1: Decrypt the ciphertext
        obfuscated = aesgcm.decrypt(nonce, ct, None)
        # Step 2: Remove identity obfuscation using the same session key
        raw = deobfuscate_audio(obfuscated, session_key, idx)
        chunk = AudioSegment(
            data=raw, sample_width=sw, frame_rate=fr, channels=ch
        )
        decrypted_chunks.append(chunk)
    full_audio = sum(decrypted_chunks)
    full_audio.export(output_file, format="wav")
    return output_file

def serialize_chunks(arr):
    return pickle.dumps(arr)

def deserialize_chunks(payload):
    return pickle.loads(payload)

# ==================== METADATA ENCRYPTION ====================

def derive_metadata_key(session_key):
    """Derive a unique key for metadata encryption from session key."""
    h = hashlib.sha256()
    h.update(session_key)
    h.update(b"metadata_key")
    return h.digest()

def encrypt_metadata(metadata_dict, session_key):
    """Encrypt metadata using AES-GCM with a key derived from session key.
    
    Args:
        metadata_dict: Dictionary containing audio metadata
        session_key: 32-byte session key from Kyber KEM
    
    Returns:
        (nonce, ciphertext): Encrypted metadata
    """
    # Serialize metadata to JSON
    metadata_json = json.dumps(metadata_dict).encode('utf-8')
    
    # Derive metadata-specific key
    metadata_key = derive_metadata_key(session_key)
    
    # Generate random nonce for metadata
    metadata_nonce = os.urandom(12)
    
    # Encrypt metadata with AES-GCM
    aesgcm = AESGCM(metadata_key)
    ciphertext = aesgcm.encrypt(metadata_nonce, metadata_json, None)
    
    return metadata_nonce, ciphertext

def decrypt_metadata(metadata_nonce, ciphertext, session_key):
    """Decrypt metadata using AES-GCM.
    
    Args:
        metadata_nonce: Nonce used during encryption
        ciphertext: Encrypted metadata
        session_key: 32-byte session key from Kyber KEM
    
    Returns:
        metadata_dict: Decrypted metadata dictionary
    """
    # Derive same metadata key
    metadata_key = derive_metadata_key(session_key)
    
    # Decrypt with AES-GCM
    aesgcm = AESGCM(metadata_key)
    metadata_json = aesgcm.decrypt(metadata_nonce, ciphertext, None)
    
    # Deserialize from JSON
    metadata_dict = json.loads(metadata_json.decode('utf-8'))
    
    return metadata_dict

def extract_metadata_from_chunks(encrypted_chunks):
    """Extract metadata from encrypted chunks.
    
    Args:
        encrypted_chunks: List of (nonce, ciphertext, frame_rate, sample_width, channels)
    
    Returns:
        metadata_dict: Dictionary with audio parameters
    """
    if not encrypted_chunks:
        return {}
    
    # Get metadata from first chunk (all chunks have same parameters)
    first_chunk = encrypted_chunks[0]
    _, _, fr, sw, ch = first_chunk
    
    metadata = {
        'frame_rate': int(fr),
        'sample_width': int(sw),
        'channels': int(ch),
        'total_chunks': len(encrypted_chunks)
    }
    
    return metadata

