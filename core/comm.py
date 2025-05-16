# core/comm.py

import socket
import json
import threading
import time
import os # For salt generation and os.path in __main__

from .crypto import CryptoManager
from .auth import AuthManager
from .anomaly import AnomalyDetector # Import AnomalyDetector

MSG_LEN_HEADER_SIZE = 4

class SecurityException(Exception):
    """Custom exception for security-related errors during handshake or communication."""
    pass

class P2PCommunication:
    def __init__(self, host, port, local_auth_manager, \
                 anomaly_detector_instance=None, # Pass an instance or let it create one
                 on_message_received_callback=None, \
                 on_peer_connected_callback=None, \
                 on_peer_disconnected_callback=None,\
                 on_anomaly_detected_callback=None): # Callback for anomaly alerts
        self.host = host
        self.port = port
        self.local_auth_manager = local_auth_manager
        
        if anomaly_detector_instance:
            self.anomaly_detector = anomaly_detector_instance
        else:
            self.anomaly_detector = AnomalyDetector()
            # Attempt to load model, but don't block if not found initially
            if not self.anomaly_detector.load_model():
                print("COMM: Anomaly detector model not found or failed to load. Detection might be impaired until trained.")

        self.on_message_received_callback = on_message_received_callback
        self.on_peer_connected_callback = on_peer_connected_callback
        self.on_peer_disconnected_callback = on_peer_disconnected_callback
        self.on_anomaly_detected_callback = on_anomaly_detected_callback
        
        self.server_socket = None
        self.is_listening = False
        self.listener_thread = None
        
        self.peer_sessions = {} # Stores session_crypto, pks, seq_nums, etc.
        self.active_connections = []
        self.message_timestamps = {} # {conn: [timestamp1, timestamp2, ...]} for frequency analysis
        self.last_message_time = {} # {conn: timestamp} for inter-message interval

    def _initialize_session_data(self, conn, addr):
        """Initializes common data for a new peer session."""
        session_crypto = CryptoManager()
        self.peer_sessions[conn] = {
            "session_crypto": session_crypto,
            "peer_ecdh_pk_bytes": None,
            "peer_signing_pk_bytes": None,
            "session_active": False,
            "addr": addr,
            "send_sequence_number": 0, # For replay protection
            "receive_sequence_number": -1, # For replay protection, start at -1 to accept 0
            "handshake_transcript_hash": None # For mutual auth
        }
        return session_crypto

    def _send_raw(self, conn, data_bytes):
        try:
            # Basic input validation
            if not isinstance(data_bytes, bytes):
                raise TypeError("Data to send must be bytes.")
            message_len_bytes = len(data_bytes).to_bytes(MSG_LEN_HEADER_SIZE, "big")
            conn.sendall(message_len_bytes + data_bytes)
            return True
        except socket.error as e:
            print(f"Socket error during send to {self.peer_sessions.get(conn, {}).get('addr', 'unknown peer')}: {e}")
            self._handle_disconnection(conn)
            return False
        except TypeError as e:
            print(f"Type error during send: {e}") # Should not happen with check
            return False

    def _recv_raw(self, conn):
        try:
            len_bytes = conn.recv(MSG_LEN_HEADER_SIZE)
            if not len_bytes or len(len_bytes) < MSG_LEN_HEADER_SIZE:
                # Connection likely closed or data is malformed
                return None
            msg_len = int.from_bytes(len_bytes, "big")
            if msg_len == 0: return b"" # Empty message allowed by protocol
            if msg_len > 10 * 1024 * 1024: # Max message size 10MB (configurable)
                print(f"Message too large from {self.peer_sessions.get(conn, {}).get('addr', 'unknown peer')}: {msg_len} bytes. Discarding.")
                # Consume and discard to prevent blocking, then treat as error
                # This part is tricky as we don't want to hang reading a huge alleged message
                # For now, we'll rely on higher-level timeouts or treat as disconnection
                self._handle_disconnection(conn)
                return None
                
            data_bytes = b""
            conn.settimeout(5.0) # Timeout for receiving message body
            while len(data_bytes) < msg_len:
                packet = conn.recv(min(msg_len - len(data_bytes), 4096)) # Read in chunks
                if not packet: return None # Connection closed during read
                data_bytes += packet
            conn.settimeout(None) # Reset timeout
            return data_bytes
        except socket.timeout:
            print(f"Socket timeout during recv from {self.peer_sessions.get(conn, {}).get('addr', 'unknown peer')}")
            self._handle_disconnection(conn)
            return None
        except socket.error as e:
            print(f"Socket error during recv from {self.peer_sessions.get(conn, {}).get('addr', 'unknown peer')}: {e}")
            self._handle_disconnection(conn)
            return None
        except ValueError as e: # Catches int.from_bytes error for malformed length
            print(f"ValueError during recv (malformed length?) from {self.peer_sessions.get(conn, {}).get('addr', 'unknown peer')}: {e}")
            self._handle_disconnection(conn)
            return None

    def _perform_handshake_client(self, conn, peer_host, peer_port):
        session_crypto = self._initialize_session_data(conn, (peer_host, peer_port))
        handshake_transcript = b""
        try:
            client_ecdh_pk_bytes = session_crypto.get_public_key_bytes()
            client_signing_pk_bytes = self.local_auth_manager.get_signing_public_key_bytes()
            
            # Sign the ECDH public key
            ecdh_pk_to_sign = client_ecdh_pk_bytes # Could concatenate with other handshake context if needed
            client_ecdh_pk_signature = self.local_auth_manager.sign_message(ecdh_pk_to_sign)

            handshake_msg1_dict = {
                "type": "KEY_EXCHANGE_PUBLIC",
                "ecdh_pk": client_ecdh_pk_bytes.decode("latin-1"),
                "signing_pk": client_signing_pk_bytes.decode("latin-1"),
                "ecdh_pk_signature": client_ecdh_pk_signature.hex()
            }
            handshake_msg1_bytes = json.dumps(handshake_msg1_dict).encode("utf-8")
            handshake_transcript += handshake_msg1_bytes
            if not self._send_raw(conn, handshake_msg1_bytes): 
                raise ConnectionError("HS_CLIENT: Send PKs failed")
            
            server_keys_bytes = self._recv_raw(conn)
            if not server_keys_bytes: raise ConnectionError("HS_CLIENT: Recv PKs failed")
            handshake_transcript += server_keys_bytes
            server_keys_msg = json.loads(server_keys_bytes.decode("utf-8"))
            if server_keys_msg.get("type") != "KEY_EXCHANGE_PUBLIC": 
                raise ValueError("HS_CLIENT: Invalid PK msg type")
            
            peer_ecdh_pk_bytes = server_keys_msg["ecdh_pk"].encode("latin-1")
            peer_signing_pk_bytes = server_keys_msg["signing_pk"].encode("latin-1")
            peer_ecdh_pk_signature_hex = server_keys_msg.get("ecdh_pk_signature")
            if not peer_ecdh_pk_signature_hex: 
                raise SecurityException("HS_CLIENT: Peer ECDH PK signature missing")
            
            # Verify peer's ECDH public key signature
            ecdh_pk_to_verify = peer_ecdh_pk_bytes
            if not AuthManager.verify_signature(peer_signing_pk_bytes, ecdh_pk_to_verify, bytes.fromhex(peer_ecdh_pk_signature_hex)):
                raise SecurityException("HS_CLIENT: Invalid signature for peer ECDH public key")

            self.peer_sessions[conn]["peer_ecdh_pk_bytes"] = peer_ecdh_pk_bytes
            self.peer_sessions[conn]["peer_signing_pk_bytes"] = peer_signing_pk_bytes

            shared_secret = session_crypto.generate_shared_secret(peer_ecdh_pk_bytes)
            salt = os.urandom(16) # Client generates salt and sends it
            session_crypto.derive_session_key(shared_secret, salt)
            
            handshake_msg2_dict = {"type": "KEY_EXCHANGE_SALT", "salt": salt.hex()}
            handshake_msg2_bytes = json.dumps(handshake_msg2_dict).encode("utf-8")
            handshake_transcript += handshake_msg2_bytes
            if not self._send_raw(conn, handshake_msg2_bytes): 
                raise ConnectionError("HS_CLIENT: Send salt failed")
            
            # Mutual Authentication (Step 1: Client sends proof)
            # Hash the transcript so far
            from cryptography.hazmat.primitives import hashes
            digest = hashes.Hash(hashes.SHA256())
            digest.update(handshake_transcript)
            transcript_hash = digest.finalize()
            self.peer_sessions[conn]["handshake_transcript_hash"] = transcript_hash

            auth_proof_payload = {"proof_data": transcript_hash.hex()}
            # This proof needs to be encrypted with the new session key
            auth_proof_msg_bytes = json.dumps(auth_proof_payload).encode("utf-8")
            encrypted_auth_proof = session_crypto.encrypt_message(auth_proof_msg_bytes)
            if not encrypted_auth_proof: raise SecurityException("HS_CLIENT: Failed to encrypt auth proof")
            
            auth_msg_dict = {"type": "MUTUAL_AUTH_CLIENT_PROOF", "encrypted_proof": encrypted_auth_proof.hex()}
            if not self._send_raw(conn, json.dumps(auth_msg_dict).encode("utf-8")): 
                raise ConnectionError("HS_CLIENT: Send auth proof failed")

            # Mutual Authentication (Step 2: Client receives and verifies server's proof)
            server_auth_proof_bytes_raw = self._recv_raw(conn)
            if not server_auth_proof_bytes_raw: raise ConnectionError("HS_CLIENT: Recv server auth proof failed")
            server_auth_proof_msg = json.loads(server_auth_proof_bytes_raw.decode("utf-8"))
            if server_auth_proof_msg.get("type") != "MUTUAL_AUTH_SERVER_PROOF":
                raise SecurityException("HS_CLIENT: Invalid server auth proof message type")
            
            encrypted_server_proof_hex = server_auth_proof_msg.get("encrypted_proof")
            if not encrypted_server_proof_hex: raise SecurityException("HS_CLIENT: Server auth proof missing")
            decrypted_server_proof_payload_bytes = session_crypto.decrypt_message(bytes.fromhex(encrypted_server_proof_hex))
            if not decrypted_server_proof_payload_bytes: raise SecurityException("HS_CLIENT: Failed to decrypt server auth proof")
            
            server_proof_payload = json.loads(decrypted_server_proof_payload_bytes.decode("utf-8"))
            server_transcript_hash_hex = server_proof_payload.get("proof_data")
            if not server_transcript_hash_hex or bytes.fromhex(server_transcript_hash_hex) != transcript_hash:
                raise SecurityException("HS_CLIENT: Server auth proof mismatch")

            self.peer_sessions[conn]["session_active"] = True
            self.active_connections.append(conn)
            self.message_timestamps[conn] = []
            self.last_message_time[conn] = time.time()
            if self.on_peer_connected_callback: self.on_peer_connected_callback(conn, (peer_host, peer_port))
            return True
        except (json.JSONDecodeError, ValueError, ConnectionError, SecurityException) as e:
            print(f"CLIENT: Handshake failed with {peer_host}:{peer_port}: {type(e).__name__} - {e}")
            self._handle_disconnection(conn)
            return False
        except Exception as e: # Catch any other unexpected errors
            print(f"CLIENT: Unexpected handshake error with {peer_host}:{peer_port}: {type(e).__name__} - {e}")
            self._handle_disconnection(conn)
            return False

    def _perform_handshake_server(self, conn, addr):
        session_crypto = self._initialize_session_data(conn, addr)
        handshake_transcript = b""
        try:
            client_keys_bytes = self._recv_raw(conn)
            if not client_keys_bytes: raise ConnectionError("HS_SERVER: Recv PKs failed")
            handshake_transcript += client_keys_bytes
            client_keys_msg = json.loads(client_keys_bytes.decode("utf-8"))
            if client_keys_msg.get("type") != "KEY_EXCHANGE_PUBLIC": 
                raise ValueError("HS_SERVER: Invalid PK msg type")

            peer_ecdh_pk_bytes = client_keys_msg["ecdh_pk"].encode("latin-1")
            peer_signing_pk_bytes = client_keys_msg["signing_pk"].encode("latin-1")
            peer_ecdh_pk_signature_hex = client_keys_msg.get("ecdh_pk_signature")
            if not peer_ecdh_pk_signature_hex: 
                raise SecurityException("HS_SERVER: Peer ECDH PK signature missing")

            ecdh_pk_to_verify = peer_ecdh_pk_bytes
            if not AuthManager.verify_signature(peer_signing_pk_bytes, ecdh_pk_to_verify, bytes.fromhex(peer_ecdh_pk_signature_hex)):
                raise SecurityException("HS_SERVER: Invalid signature for peer ECDH public key")

            self.peer_sessions[conn]["peer_ecdh_pk_bytes"] = peer_ecdh_pk_bytes
            self.peer_sessions[conn]["peer_signing_pk_bytes"] = peer_signing_pk_bytes

            server_ecdh_pk_bytes = session_crypto.get_public_key_bytes()
            server_signing_pk_bytes = self.local_auth_manager.get_signing_public_key_bytes()
            ecdh_pk_to_sign = server_ecdh_pk_bytes
            server_ecdh_pk_signature = self.local_auth_manager.sign_message(ecdh_pk_to_sign)

            handshake_msg1_dict = {
                "type": "KEY_EXCHANGE_PUBLIC",
                "ecdh_pk": server_ecdh_pk_bytes.decode("latin-1"),
                "signing_pk": server_signing_pk_bytes.decode("latin-1"),
                "ecdh_pk_signature": server_ecdh_pk_signature.hex()
            }
            handshake_msg1_bytes = json.dumps(handshake_msg1_dict).encode("utf-8")
            handshake_transcript += handshake_msg1_bytes # Server adds its own message to transcript AFTER receiving client's first
            if not self._send_raw(conn, handshake_msg1_bytes): 
                raise ConnectionError("HS_SERVER: Send PKs failed")

            salt_msg_bytes = self._recv_raw(conn)
            if not salt_msg_bytes: raise ConnectionError("HS_SERVER: Recv salt failed")
            handshake_transcript += salt_msg_bytes
            salt_msg = json.loads(salt_msg_bytes.decode("utf-8"))
            if salt_msg.get("type") != "KEY_EXCHANGE_SALT": 
                raise ValueError("HS_SERVER: Invalid salt msg type")
            salt = bytes.fromhex(salt_msg["salt"])
            
            shared_secret = session_crypto.generate_shared_secret(peer_ecdh_pk_bytes)
            session_crypto.derive_session_key(shared_secret, salt)

            # Mutual Authentication (Step 1: Server receives and verifies client's proof)
            client_auth_proof_bytes_raw = self._recv_raw(conn)
            if not client_auth_proof_bytes_raw: raise ConnectionError("HS_SERVER: Recv client auth proof failed")
            # Note: Client's auth proof is NOT added to server's transcript for its own proof generation
            # The transcript should be identical for both sides up to the point of proof generation.
            client_auth_proof_msg = json.loads(client_auth_proof_bytes_raw.decode("utf-8"))
            if client_auth_proof_msg.get("type") != "MUTUAL_AUTH_CLIENT_PROOF":
                raise SecurityException("HS_SERVER: Invalid client auth proof message type")

            from cryptography.hazmat.primitives import hashes # Ensure imported
            digest = hashes.Hash(hashes.SHA256())
            digest.update(handshake_transcript) # Server uses the same transcript as client did
            expected_transcript_hash = digest.finalize()
            self.peer_sessions[conn]["handshake_transcript_hash"] = expected_transcript_hash

            encrypted_client_proof_hex = client_auth_proof_msg.get("encrypted_proof")
            if not encrypted_client_proof_hex: raise SecurityException("HS_SERVER: Client auth proof missing")
            decrypted_client_proof_payload_bytes = session_crypto.decrypt_message(bytes.fromhex(encrypted_client_proof_hex))
            if not decrypted_client_proof_payload_bytes: raise SecurityException("HS_SERVER: Failed to decrypt client auth proof")
            
            client_proof_payload = json.loads(decrypted_client_proof_payload_bytes.decode("utf-8"))
            client_transcript_hash_hex = client_proof_payload.get("proof_data")
            if not client_transcript_hash_hex or bytes.fromhex(client_transcript_hash_hex) != expected_transcript_hash:
                raise SecurityException("HS_SERVER: Client auth proof mismatch")

            # Mutual Authentication (Step 2: Server sends its proof)
            auth_proof_payload = {"proof_data": expected_transcript_hash.hex()}
            auth_proof_msg_bytes = json.dumps(auth_proof_payload).encode("utf-8")
            encrypted_auth_proof = session_crypto.encrypt_message(auth_proof_msg_bytes)
            if not encrypted_auth_proof: raise SecurityException("HS_SERVER: Failed to encrypt auth proof")
            
            auth_msg_dict = {"type": "MUTUAL_AUTH_SERVER_PROOF", "encrypted_proof": encrypted_auth_proof.hex()}
            if not self._send_raw(conn, json.dumps(auth_msg_dict).encode("utf-8")): 
                raise ConnectionError("HS_SERVER: Send auth proof failed")

            self.peer_sessions[conn]["session_active"] = True
            self.active_connections.append(conn)
            self.message_timestamps[conn] = []
            self.last_message_time[conn] = time.time()
            if self.on_peer_connected_callback: self.on_peer_connected_callback(conn, addr)
            return True
        except (json.JSONDecodeError, ValueError, ConnectionError, SecurityException) as e:
            print(f"SERVER: Handshake failed with {addr}: {type(e).__name__} - {e}")
            self._handle_disconnection(conn)
            return False
        except Exception as e: # Catch any other unexpected errors
            print(f"SERVER: Unexpected handshake error with {addr}: {type(e).__name__} - {e}")
            self._handle_disconnection(conn)
            return False

    def start_listening(self):
        if self.is_listening: return True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.is_listening = True
            print(f"Listening for secure connections on {self.host}:{self.port}")
            self.listener_thread = threading.Thread(target=self._accept_connections, daemon=True); self.listener_thread.start()
        except OSError as e: 
            print(f"Error starting listener: {e}"); self.is_listening = False; return False
        return True

    def _accept_connections(self):
        while self.is_listening:
            try:
                conn, addr = self.server_socket.accept()
                conn.settimeout(10.0) # Set a timeout for handshake operations
                threading.Thread(target=self._handle_new_server_connection, args=(conn, addr), daemon=True).start()
            except OSError as e: 
                if self.is_listening: print(f"Error accepting connection: {e}")
                break # Exit loop if server_socket is closed or error occurs
            except Exception as e:
                if self.is_listening: print(f"Unexpected error in accept_connections: {e}")

    def _handle_new_server_connection(self, conn, addr):
        print(f"New connection attempt from {addr}")
        try:
            if self._perform_handshake_server(conn, addr):
                print(f"Handshake successful with {addr}. Starting message loop.")
                conn.settimeout(None) # Clear handshake timeout for message loop
                self._message_loop(conn, addr)
            else: 
                print(f"Handshake failed with {addr}. Closing connection.")
                conn.close()
        except Exception as e:
            print(f"Error handling new server connection for {addr}: {e}")
            self._handle_disconnection(conn) # Ensure cleanup

    def connect_to_peer(self, peer_host, peer_port):
        conn = None
        try:
            print(f"Attempting to connect to {peer_host}:{peer_port}")
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(10.0) # Timeout for connection and handshake
            conn.connect((peer_host, peer_port))
            if self._perform_handshake_client(conn, peer_host, peer_port):
                print(f"Handshake successful with {peer_host}:{peer_port}. Starting message loop.")
                conn.settimeout(None) # Clear handshake timeout
                threading.Thread(target=self._message_loop, args=(conn, (peer_host, peer_port)), daemon=True).start()
                return conn
            else: 
                print(f"Handshake failed with {peer_host}:{peer_port}. Connection not established.")
                if conn: conn.close()
                return None
        except socket.error as e: 
            print(f"Failed to connect to {peer_host}:{peer_port}: {e}")
            if conn: conn.close()
            return None
        except Exception as e: # Catch other handshake related errors from _perform_handshake_client
            print(f"Error during connect_to_peer for {peer_host}:{peer_port}: {e}")
            if conn: conn.close()
            return None

    def _check_anomaly(self, conn, event_type, details=None):
        if not self.anomaly_detector or not self.anomaly_detector.is_trained:
            # print("Anomaly detector not trained or available, skipping check.") # Too verbose
            return

        addr = self.peer_sessions.get(conn, {}).get("addr", "unknown")
        current_time = time.time()
        
        details = details or {}
        message_length = details.get("message_length", 0)
        time_interval = current_time - self.last_message_time.get(conn, current_time)
        self.last_message_time[conn] = current_time

        # Ensure message_timestamps[conn] exists before list comprehension
        if conn not in self.message_timestamps: self.message_timestamps[conn] = []
        self.message_timestamps[conn] = [ts for ts in self.message_timestamps[conn] if current_time - ts < 60]
        self.message_timestamps[conn].append(current_time)
        message_count_window = len(self.message_timestamps[conn])

        # Armazenar contadores de erros para este peer
        session_data = self.peer_sessions.get(conn, {})
        if "error_counters" not in session_data:
            session_data["error_counters"] = {
                "decrypt_errors": 0,
                "signature_errors": 0,
                "replay_attempts": 0,
                "handshake_failures": 0,
                "sequential_errors": 0  # Erros sequenciais
            }
        
        # Incrementar contadores baseados no tipo de evento
        error_counters = session_data["error_counters"]
        if event_type == "failed_decrypt":
            error_counters["decrypt_errors"] += 1
            error_counters["sequential_errors"] += 1
        elif event_type == "failed_sig_verify":
            error_counters["signature_errors"] += 1
            error_counters["sequential_errors"] += 1
        elif event_type == "replay_attempt":
            error_counters["replay_attempts"] += 1
            error_counters["sequential_errors"] += 1
        elif event_type == "valid_message":
            # Resetar contador de erros sequenciais ao receber uma mensagem válida
            error_counters["sequential_errors"] = 0
        
        # Estimar variância do tipo de mensagem (por simplicidade, usamos um valor derivado)
        # Em uma implementação mais completa, rastreariam-se os diferentes tipos
        message_type_variance = details.get("message_type_variance", 0.7)  # Valor padrão
        if "message_type" in details:
            # Aqui seria implementado um cálculo real da variância
            # baseado no histórico de tipos de mensagens deste peer
            pass

        # Calcular entropia do payload (simplificado)
        payload_entropy = 4.5  # Valor padrão, assumindo texto normal
        if message_length > 0:
            if message_length > 5000:
                # Mensagens muito grandes têm maior chance de ser dados comprimidos/cifrados
                payload_entropy = 6.8 + (message_length / 50000)  # Mais entropia para mensagens maiores
            elif message_length < 50:
                # Mensagens muito pequenas geralmente têm menor entropia
                payload_entropy = 3.5
        
        # Resposta do sistema em função da carga
        response_time = 0.3  # Resposta padrão normal
        if message_count_window > 30:
            # Sistema sob carga, resposta mais lenta
            response_time = 0.3 + (message_count_window * 0.05)
        
        # Duração da sessão
        session_start_time = session_data.get("session_start_time", current_time)
        if "session_start_time" not in session_data:
            session_data["session_start_time"] = current_time
        
        session_duration = current_time - session_start_time

        # Flag de replay (1 se for uma tentativa de replay, 0 caso contrário)
        replay_flag = 1 if event_type == "replay_attempt" else 0
        
        # Validade do número de sequência
        seq_num_validity = details.get("seq_num_validity", 0)

        # Criar o dicionário completo de features para a detecção de anomalias
        event_features_dict = {
            # Features básicas originais
            "message_length": message_length,
            "time_interval": time_interval,
            "message_count_window": message_count_window,
            
            # Features avançadas
            "payload_entropy": payload_entropy,
            "response_time": response_time,
            "decryption_errors": error_counters["decrypt_errors"],
            "signature_errors": error_counters["signature_errors"],
            "replay_flags": replay_flag,
            "handshake_failures": error_counters["handshake_failures"],
            "message_type_variance": message_type_variance,
            "session_duration": session_duration,
            "sequential_errors": error_counters["sequential_errors"]
        }
        
        try:
            # Usar o dicionário completo de features para a detecção
            prediction = self.anomaly_detector.predict(event_features_dict)
            score = self.anomaly_detector.get_anomaly_score(event_features_dict)
        except Exception as e:
            print(f"Error during anomaly prediction: {e}")
            return # Avoid further processing if prediction fails

        # Tratar os resultados da detecção
        is_anomaly = prediction == -1 or event_type == "replay_attempt"
        
        if is_anomaly:
            alert_details = details.copy()
            alert_details.update(event_features_dict)  # Incluir todas as features no alerta
            alert_details["original_event_type"] = event_type
            
            print(f"ANOMALY DETECTED from {addr}! Type: {event_type}, Score: {score:.4f}")
            if self.on_anomaly_detected_callback:
                self.on_anomaly_detected_callback(addr, event_type if event_type == "replay_attempt" else "anomaly_ml", score, alert_details)

    def _message_loop(self, conn, addr):
        try:
            while self.is_listening or conn in self.active_connections:
                session_data = self.peer_sessions.get(conn)
                if not session_data or not session_data.get("session_active"):
                    # print(f"Session not active or not found for {addr}. Exiting message loop.") # Debug
                    break
                
                encrypted_data = self._recv_raw(conn)
                if encrypted_data is None: 
                    # print(f"No data received from {addr} or connection closed. Exiting message loop.") # Debug
                    break 
                
                session_crypto = session_data["session_crypto"]
                peer_signing_pk_bytes = session_data["peer_signing_pk_bytes"]

                decrypted_bytes = session_crypto.decrypt_message(encrypted_data)
                if not decrypted_bytes:
                    self._check_anomaly(conn, "failed_decrypt", {"data_len": len(encrypted_data)})
                    continue
                
                try:
                    msg_dict = json.loads(decrypted_bytes.decode("utf-8"))
                    # Validate required fields
                    required_fields = ["type", "timestamp", "payload", "signature", "seq"]
                    if not all(k in msg_dict for k in required_fields):
                        missing_fields = [k for k in required_fields if k not in msg_dict]
                        self._check_anomaly(conn, "malformed_decrypted_message", {
                            "error": "Missing fields", 
                            "missing": missing_fields,
                            "message_content": decrypted_bytes.decode("utf-8", errors="ignore")})
                        continue
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    self._check_anomaly(conn, "decoding_error_decrypted_message", {"error": str(e), "raw_decrypted": decrypted_bytes.decode("utf-8", errors="ignore")})
                    continue
                
                received_seq = msg_dict.get("seq")
                if not isinstance(received_seq, int):
                    self._check_anomaly(conn, "malformed_sequence_number", {"received_seq": str(received_seq)})
                    continue

                expected_seq_num_min = session_data["receive_sequence_number"] + 1
                if received_seq < expected_seq_num_min:
                    self._check_anomaly(conn, "replay_attempt", {
                        "message_type": msg_dict.get("type"), 
                        "received_seq": received_seq, 
                        "expected_seq_min": expected_seq_num_min
                    })
                    print(f"Replay/Out-of-order message from {addr}. Received Seq: {received_seq}, Expected >= {expected_seq_num_min}. Discarding.")
                    continue 
                session_data["receive_sequence_number"] = received_seq 

                # Validate payload structure before creating payload_str for signature verification
                payload_data = msg_dict.get("payload")
                if not isinstance(payload_data, dict): # Assuming payload is always a dict
                    self._check_anomaly(conn, "malformed_payload", {"payload_type": type(payload_data).__name__})
                    continue
                payload_str = json.dumps(payload_data) # Use original payload for signature
                signature_bytes = bytes.fromhex(msg_dict["signature"])

                if not AuthManager.verify_signature(peer_signing_pk_bytes, payload_str.encode("utf-8"), signature_bytes):
                    self._check_anomaly(conn, "failed_sig_verify", {"message_type": msg_dict.get("type"), "seq_num_validity": 1})
                    continue
                
                self._check_anomaly(conn, "valid_message", {"message_type": msg_dict.get("type"), "message_length": len(payload_str), "seq_num_validity": 1})

                if self.on_message_received_callback:
                    message_type = msg_dict.get("type", "UNKNOWN")
                    # Pass the full msg_dict to callback if it needs seq or timestamp
                    self.on_message_received_callback(conn, addr, message_type, payload_data, msg_dict)
        except ConnectionResetError:
            print(f"Connection reset by peer {addr}.")
        except socket.timeout:
            print(f"Socket timeout in message loop for {addr}.")
        except Exception as e:
            if self.is_listening or conn in self.active_connections: 
                print(f"Error in message loop for {addr}: {type(e).__name__} - {e}")
        finally:
            self._handle_disconnection(conn)

    def send_message(self, conn, msg_type, payload_dict):
        session_data = self.peer_sessions.get(conn)
        if not session_data or not session_data.get("session_active"):
            print(f"Cannot send message: Session not active or not found for connection.")
            return False
        
        # Validate payload type
        if not isinstance(payload_dict, dict):
            print("Payload must be a dictionary.")
            return False
            
        session_crypto = session_data["session_crypto"]
        current_seq_num = session_data["send_sequence_number"]
        
        payload_str = json.dumps(payload_dict)
        signature = self.local_auth_manager.sign_message(payload_str.encode("utf-8"))
        
        full_msg_dict = {
            "type": msg_type, 
            "timestamp": time.time(), 
            "payload": payload_dict, 
            "signature": signature.hex(),
            "seq": current_seq_num
        }
        full_msg_bytes = json.dumps(full_msg_dict).encode("utf-8")
        encrypted_msg = session_crypto.encrypt_message(full_msg_bytes)
        if not encrypted_msg: 
            print("Failed to encrypt message.")
            return False
        
        if self._send_raw(conn, encrypted_msg):
            session_data["send_sequence_number"] += 1 # Increment sequence number only after successful send
            return True
        return False

    def broadcast_message(self, msg_type, payload_dict):
        success_all = True
        for conn in list(self.active_connections): 
            if not self.send_message(conn, msg_type, payload_dict):
                success_all = False
        return success_all

    def _handle_disconnection(self, conn):
        addr = self.peer_sessions.get(conn, {}).get("addr", "unknown_peer_disconnecting")
        if conn in self.active_connections: self.active_connections.remove(conn)
        if conn in self.peer_sessions: del self.peer_sessions[conn]
        if conn in self.message_timestamps: del self.message_timestamps[conn]
        if conn in self.last_message_time: del self.last_message_time[conn]
        try: 
            if conn.fileno() != -1: # Check if socket is still valid
                conn.shutdown(socket.SHUT_RDWR) # Gracefully shutdown
                conn.close()
        except (socket.error, OSError): pass # Ignore errors during close, already disconnected
        
        print(f"Connection with {addr} closed/lost.")
        if self.on_peer_disconnected_callback: 
            if isinstance(addr, tuple) and len(addr) == 2:
                self.on_peer_disconnected_callback(conn, addr)
            else:
                self.on_peer_disconnected_callback(conn, ("unknown", 0)) 

    def stop_listening(self):
        print("Stopping P2P Communication...")
        self.is_listening = False # Signal listener thread to stop
        if self.server_socket:
            try:
                # This is a common trick to unblock accept() call
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.1)
                    s.connect((self.host, self.port if self.port != 0 else self.server_socket.getsockname()[1]))
            except (socket.timeout, ConnectionRefusedError, OSError): 
                pass 
            finally:
                try:
                    if self.server_socket.fileno() != -1:
                        self.server_socket.close()
                except (socket.error, OSError): pass
                self.server_socket = None
        
        if self.listener_thread and self.listener_thread.is_alive(): 
            self.listener_thread.join(timeout=2) # Increased timeout for join
            if self.listener_thread.is_alive():
                 print("Listener thread did not terminate cleanly.")

        # Close all active client connections initiated by this instance
        # Connections accepted by the server part are handled by their respective threads terminating
        for conn in list(self.active_connections): 
            self._handle_disconnection(conn)
            
        self.peer_sessions.clear(); self.active_connections.clear()
        print("P2P Communication stopped.")

# Example usage for testing (needs to be adapted for a full client/server application)
if __name__ == '__main__':
    import pandas as pd 
    import numpy as np  
    # AuthManager, AnomalyDetector, time, os are imported at the top level of the file.

    print("Simplified __main__ for comm.py. Full testing requires trained anomaly model and client/server setup.")

    auth_peer1 = AuthManager()
    auth_peer2 = AuthManager()

    ad = AnomalyDetector()
    # Ensure data directory exists for dummy model saving/loading
    data_dir_path = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(data_dir_path, exist_ok=True)
    
    if not ad.load_model(): # Tries to load from default path in data_dir
        print("MAIN: No pre-trained model found. Creating a dummy one for comms test.")
        dummy_features = pd.DataFrame(np.random.rand(100, 3), columns=["message_length", "time_interval", "message_count_window"])
        ad.train(dummy_features)
        ad.save_model() # Save to default path

    def basic_msg_handler(conn, addr, msg_type, payload, full_msg=None):
        # Added full_msg to access seq if needed by handler
        print(f"HANDLER from {addr} (Conn Fileno: {conn.fileno() if conn.fileno() != -1 else 'N/A'}): Type={msg_type}, Seq={full_msg.get('seq') if full_msg else 'N/A'}, Payload={payload}")

    def peer_conn_handler(conn, addr):
        print(f"PEER_CONN from {addr} (Conn Fileno: {conn.fileno() if conn.fileno() != -1 else 'N/A'})")

    def peer_disconn_handler(conn, addr):
        # conn might be already closed, so fileno() could fail
        print(f"PEER_DISCONN from {addr}")

    def anomaly_alert_handler(peer_addr, event_type, score, details):
        print(f"ALERT_HANDLER: Anomaly from {peer_addr}, Event: {event_type}, Score: {score:.4f}, Details: {details}")

    comm1_host = '127.0.0.1'
    comm1_port = 12345
    comm2_host = '127.0.0.1'
    # comm2_port = 12346 # Client doesn't bind to a fixed port unless it also acts as a server

    comm1 = P2PCommunication(comm1_host, comm1_port, auth_peer1, 
                             anomaly_detector_instance=ad, 
                             on_message_received_callback=basic_msg_handler, 
                             on_peer_connected_callback=peer_conn_handler,
                             on_peer_disconnected_callback=peer_disconn_handler,
                             on_anomaly_detected_callback=anomaly_alert_handler)
    if not comm1.start_listening():
        print("Failed to start comm1 listener. Exiting test.")
        exit()
    time.sleep(0.5) # Give server time to start

    comm2 = P2PCommunication(comm2_host, 0, auth_peer2, # Port 0 for client to get ephemeral port 
                             anomaly_detector_instance=ad, 
                             on_message_received_callback=basic_msg_handler,
                             on_peer_connected_callback=peer_conn_handler,
                             on_peer_disconnected_callback=peer_disconn_handler,
                             on_anomaly_detected_callback=anomaly_alert_handler)
    # comm2 doesn't need to listen if it's only acting as a client in this test

    conn_c2_s1 = comm2.connect_to_peer(comm1_host, comm1_port)
    if conn_c2_s1:
        print("\n--- Sending first message from Comm2 to Comm1 ---")
        comm2.send_message(conn_c2_s1, "HELLO", {"data": "world 1 from C2"})
        time.sleep(0.5) 
        
        print("\n--- Sending second message from Comm2 to Comm1 ---")
        comm2.send_message(conn_c2_s1, "INFO", {"info": "test data 2 from C2"})
        time.sleep(0.5)

        # Find the connection object on comm1's side to send back
        comm1_conn_to_c2 = None
        # This logic to find the peer connection is simplified for the test
        # In a real scenario, you'd map connections or have a way to identify peers
        if comm1.active_connections:
            # Assuming the first connection is the one from comm2
            # A more robust way would be to check peer_sessions[c]["addr"]
            # against conn_c2_s1.getsockname() (the client's ephemeral port and host)
            for c_obj in comm1.active_connections:
                # print(f"Comm1 active conn: {comm1.peer_sessions[c_obj]['addr']}")
                # print(f"Comm2 conn_c2_s1 sockname: {conn_c2_s1.getsockname()}")
                if comm1.peer_sessions[c_obj]['addr'] == conn_c2_s1.getsockname():
                    comm1_conn_to_c2 = c_obj
                    break
        
        if comm1_conn_to_c2:
            print(f"\n--- Sending first message from Comm1 back to Comm2 (Conn Fileno: {comm1_conn_to_c2.fileno()}) ---")
            comm1.send_message(comm1_conn_to_c2, "REPLY", {"response": "got it 1 from C1"})
            time.sleep(0.5)
            print(f"\n--- Sending second message from Comm1 back to Comm2 (Conn Fileno: {comm1_conn_to_c2.fileno()}) ---")
            comm1.send_message(comm1_conn_to_c2, "ACK", {"status": "ok 2 from C1"})
            time.sleep(0.5)
        else:
            print("Could not find active connection on Comm1 corresponding to Comm2's client connection for this test setup.")

    else:
        print("Comm2 failed to connect to Comm1.")
    
    print("\n--- Test: Attempting to connect with a new client (Comm3) ---")
    auth_peer3 = AuthManager()
    comm3 = P2PCommunication(comm2_host, 0, auth_peer3, anomaly_detector_instance=ad, on_message_received_callback=basic_msg_handler)
    conn_c3_s1 = comm3.connect_to_peer(comm1_host, comm1_port)
    if conn_c3_s1:
        comm3.send_message(conn_c3_s1, "PING", {"data": "from Comm3"})
        time.sleep(0.5)
    else:
        print("Comm3 failed to connect to Comm1")

    print("\n--- Stopping communication ---")
    # Client side connections should be closed by their owners or when server closes
    if conn_c2_s1: comm2._handle_disconnection(conn_c2_s1) # Explicitly close client connection
    if conn_c3_s1: comm3._handle_disconnection(conn_c3_s1)

    comm1.stop_listening()
    # comm2.stop_listening() # Not started for comm2
    # comm3.stop_listening() # Not started for comm3

    time.sleep(1) # Allow threads to close and print final messages
    print("\nBasic comms test with sequence numbers and signed ECDH keys (simulated) finished.")
    print("Note: Full ECDH key signing and mutual auth proof implemented.")

