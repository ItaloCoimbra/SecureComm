# utils/logger.py

import logging
import os
import time
import hashlib
import json
import threading
from logging.handlers import RotatingFileHandler
from cryptography.fernet import Fernet

# Define the default log directory and file
LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs") # Logs directory at project root
LOG_FILE = os.path.join(LOG_DIR, "secure_comm.log.enc") # Encrypted log file
KEY_FILE = os.path.join(LOG_DIR, "log_encryption.key")
HASH_CHAIN_FILE = os.path.join(LOG_DIR, "log_hash_chain.json") # Para armazenar os hashes em cadeia

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# --- Log Encryption Key Management ---
def load_or_generate_key(key_path):
    """Loads a Fernet key from key_path or generates a new one if not found."""
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(key_path, "wb") as f:
            f.write(key)
        print(f"LOGGER: New encryption key generated and saved to {key_path}. "
              f"IMPORTANT: Secure this key file appropriately in a production environment!")
    return key

LOG_ENCRYPTION_KEY = load_or_generate_key(KEY_FILE)
FERNET_CIPHER = Fernet(LOG_ENCRYPTION_KEY)

# --- Hash Chain Management ---
class HashChain:
    """
    Implementa uma cadeia de hashes (blockchain simples) para garantir a 
    integridade dos logs. Cada entrada é vinculada à anterior através de hashes.
    """
    def __init__(self, chain_file=HASH_CHAIN_FILE):
        self.chain_file = chain_file
        self.chain = []
        self.lock = threading.Lock()  # Para acesso thread-safe
        self._load_chain()
    
    def _load_chain(self):
        """Carrega a cadeia de hashes existente do arquivo."""
        if os.path.exists(self.chain_file):
            try:
                with open(self.chain_file, 'r') as f:
                    self.chain = json.load(f)
                print(f"LOGGER: Hash chain loaded with {len(self.chain)} blocks")
            except (json.JSONDecodeError, IOError) as e:
                print(f"LOGGER: Error loading hash chain: {e}. Starting a new chain.")
                self.chain = []
        else:
            self.chain = []
            # Criar bloco genesis se a cadeia estiver vazia
            if not self.chain:
                genesis_block = {
                    "index": 0,
                    "timestamp": time.time(),
                    "log_hash": hashlib.sha256("Genesis Block".encode()).hexdigest(),
                    "previous_hash": "0" * 64,  # Hash vazio para o bloco genesis
                    "nonce": 0
                }
                self.chain.append(genesis_block)
                self._save_chain()
    
    def _save_chain(self):
        """Salva a cadeia de hashes atual no arquivo."""
        try:
            with open(self.chain_file, 'w') as f:
                json.dump(self.chain, f, indent=2)
        except IOError as e:
            print(f"LOGGER: Error saving hash chain: {e}")
    
    def append_log_entry(self, log_entry):
        """
        Adiciona uma nova entrada de log à cadeia de hashes.
        
        Args:
            log_entry (bytes): Mensagem de log criptografada
        
        Returns:
            int: Índice do bloco na cadeia
        """
        with self.lock:
            # Criar hash para a entrada de log
            log_hash = hashlib.sha256(log_entry).hexdigest()
            
            # Obter o hash do bloco anterior
            previous_block = self.chain[-1]
            previous_hash = previous_block["log_hash"]
            
            # Criar novo bloco
            block = {
                "index": len(self.chain),
                "timestamp": time.time(),
                "log_hash": log_hash,
                "previous_hash": previous_hash,
                "nonce": self._simple_pow(log_hash, previous_hash)
            }
            
            # Adicionar à cadeia e salvar
            self.chain.append(block)
            self._save_chain()
            
            return block["index"]
    
    def _simple_pow(self, log_hash, previous_hash, difficulty=2):
        """
        Implementa uma função simples de prova de trabalho.
        O nonce é incrementado até que o hash do bloco comece com
        um número 'difficulty' de zeros.
        """
        nonce = 0
        check_str = "0" * difficulty
        
        while True:
            # Combinar log_hash, previous_hash e nonce
            combined = f"{log_hash}{previous_hash}{nonce}".encode()
            block_hash = hashlib.sha256(combined).hexdigest()
            
            # Verificar se o hash começa com o número necessário de zeros
            if block_hash.startswith(check_str):
                return nonce
            
            nonce += 1
    
    def verify_chain(self):
        """
        Verifica a integridade da cadeia de hashes.
        
        Returns:
            bool: True se a cadeia estiver intacta, False caso contrário
            list: Lista de índices de blocos comprometidos (se houver)
        """
        compromised_blocks = []
        
        with self.lock:
            for i in range(1, len(self.chain)):
                current_block = self.chain[i]
                previous_block = self.chain[i-1]
                
                # Verificar se o hash anterior está correto
                if current_block["previous_hash"] != previous_block["log_hash"]:
                    compromised_blocks.append(i)
                
                # Verificar PoW
                combined = f"{current_block['log_hash']}{current_block['previous_hash']}{current_block['nonce']}".encode()
                block_hash = hashlib.sha256(combined).hexdigest()
                if not block_hash.startswith("0" * 2):  # Mesmo nível de difficulty usado no _simple_pow
                    compromised_blocks.append(i)
        
        return len(compromised_blocks) == 0, compromised_blocks

# Inicializa a cadeia de hashes
hash_chain = HashChain()

# --- Custom Encrypted File Handler with Hash Chain ---
class SecureRotatingFileHandler(RotatingFileHandler):
    def __init__(self, filename, cipher, hash_chain, mode='a', maxBytes=0, backupCount=0, encoding=None, delay=False):
        self.cipher = cipher
        self.hash_chain = hash_chain
        # The actual file will store bytes, so encoding is handled before encryption
        super().__init__(filename, mode, maxBytes, backupCount, encoding, delay)
        self.encoding = encoding if encoding else "utf-8" # Ensure encoding for pre-encryption
    
    def _open(self):
        """
        Sobrescreve o método _open para abrir o arquivo em modo binário,
        já que estamos escrevendo bytes (mensagens criptografadas).
        """
        # mode 'ab' = anexar em modo binário
        return open(self.baseFilename, 'ab')

    def emit(self, record):
        """Emit a record, encrypting it and adding to hash chain before writing."""
        try:
            msg = self.format(record)
            # Ensure message is bytes before encryption
            if isinstance(msg, str):
                msg_bytes = msg.encode(self.encoding)
            else: # Should not happen if formatter produces str
                msg_bytes = str(msg).encode(self.encoding)
            
            # Adiciona timestamp e id aos detalhes do log para auditoria
            timestamp = time.time()
            log_id = f"{timestamp:.6f}-{record.levelname}-{record.name}"
            augmented_msg = f"[ID:{log_id}] {msg_bytes.decode(self.encoding)}"
            augmented_msg_bytes = augmented_msg.encode(self.encoding)
            
            # Encrypt the message
            encrypted_msg = self.cipher.encrypt(augmented_msg_bytes)
            
            # Add to hash chain for integrity verification
            block_index = self.hash_chain.append_log_entry(encrypted_msg)
            
            # Check if rollover is needed before writing
            if self.shouldRollover(record): # `record` is not used by default shouldRollover
                self.doRollover()
            
            # Write the encrypted message (as bytes) followed by a newline
            with self._open() as f: # Use the parent class\_open method
                # Formato: [BLOCK:index]encrypted_message\n
                f.write(f"[BLOCK:{block_index}]".encode() + encrypted_msg + b"\n")

        except Exception as e:
            print(f"Error in SecureRotatingFileHandler.emit: {e}")
            self.handleError(record)

def setup_logger(name="SecureCommApp", log_level=logging.INFO, log_file=LOG_FILE, cipher_suite=FERNET_CIPHER, chain=hash_chain):
    """
    Sets up a rotating, encrypted file logger with hash chain integrity.
    """
    logger = logging.getLogger(name)
    
    if logger.hasHandlers():
        logger.handlers.clear()

    logger.setLevel(log_level)

    formatter = logging.Formatter(
        fmt="%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Encrypted & Hash-Chained File Handler
    secure_file_handler = SecureRotatingFileHandler(
        log_file, cipher=cipher_suite, hash_chain=chain, maxBytes=5*1024*1024, backupCount=5, encoding='utf-8'
    )
    secure_file_handler.setLevel(log_level)
    secure_file_handler.setFormatter(formatter)

    # Console Handler (remains unencrypted for direct viewing)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level) 
    console_handler.setFormatter(formatter)

    logger.addHandler(secure_file_handler)
    logger.addHandler(console_handler)

    return logger

app_logger = setup_logger()

# --- Utility to decrypt, verify and view logs (for testing/admin) ---
def view_encrypted_logs(log_file_path=LOG_FILE, key_path=KEY_FILE, verify_integrity=True):
    if not os.path.exists(key_path):
        print(f"Key file not found at {key_path}. Cannot decrypt logs.")
        return
    if not os.path.exists(log_file_path):
        print(f"Log file not found at {log_file_path}.")
        return

    # Carregar chave
    with open(key_path, "rb") as f:
        key = f.read()
    cipher = Fernet(key)
    
    # Verificar a integridade da cadeia de hash, se solicitado
    if verify_integrity:
        chain = HashChain()
        is_intact, compromised_blocks = chain.verify_chain()
        if is_intact:
            print("✅ Hash chain integrity check passed - logs are intact")
        else:
            print(f"⚠️ Hash chain integrity check FAILED - {len(compromised_blocks)} compromised blocks detected!")
            print(f"Compromised block indices: {compromised_blocks}")
    
    print(f"--- Decrypted Logs from {log_file_path} ---")
    try:
        with open(log_file_path, "rb") as f:
            for line_num, encrypted_line_with_newline in enumerate(f, 1):
                encrypted_line = encrypted_line_with_newline.rstrip(b"\n") # Remove the trailing newline
                if not encrypted_line: continue # Skip empty lines if any
                
                try:
                    # Extract block index if present
                    block_index = None
                    if encrypted_line.startswith(b"[BLOCK:"):
                        block_end = encrypted_line.find(b"]")
                        if block_end > 0:
                            try:
                                block_index = int(encrypted_line[7:block_end])
                                encrypted_line = encrypted_line[block_end+1:]
                            except ValueError:
                                pass  # Cannot parse block index, continue with original line
                    
                    # Decrypt the log entry
                    decrypted_message = cipher.decrypt(encrypted_line)
                    
                    # Check if the log is in a potentially compromised block
                    integrity_warning = ""
                    if verify_integrity and block_index is not None and block_index in compromised_blocks:
                        integrity_warning = " ⚠️ INTEGRITY COMPROMISED"
                    
                    print(f"Line {line_num}{integrity_warning}: {decrypted_message.decode('utf-8')}")
                except Exception as e:
                    print(f"Line {line_num}: Error decrypting line - {e} (Data: {encrypted_line[:50]}...)")
    except FileNotFoundError:
        print(f"Log file {log_file_path} not found.")
    except Exception as e:
        print(f"An error occurred while reading or decrypting logs: {e}")
    print("--- End of Decrypted Logs ---")

def verify_log_integrity():
    """
    Verifica apenas a integridade dos logs sem descriptografá-los.
    Útil para auditorias regulares automatizadas.
    
    Returns:
        bool: True se os logs estiverem intactos, False caso contrário
    """
    chain = HashChain()
    is_intact, compromised_blocks = chain.verify_chain()
    if is_intact:
        print("✅ Log integrity verification passed - all logs are intact")
    else:
        print(f"⚠️ Log integrity verification FAILED - {len(compromised_blocks)} compromised blocks detected!")
        print(f"Compromised block indices: {compromised_blocks}")
    
    return is_intact

if __name__ == '__main__':
    # Testa o logger seguro com criptografia e cadeia de hash
    test_logger = setup_logger(name="SecureLoggerTest", log_level=logging.DEBUG)
    
    # Registrar mensagens de diferentes níveis
    test_logger.debug("Mensagem de debug para teste do logger seguro")
    test_logger.info("Mensagem informativa para teste de logs criptografados e encadeados")
    test_logger.warning("Uma mensagem de aviso aqui")
    test_logger.error("Ocorreu um erro! Registrando de forma segura")
    test_logger.critical("Evento crítico, registrado com criptografia e proteção de integridade")
    
    # Verificar a integridade da cadeia logo após o registro
    verify_log_integrity()
    
    print(f"\nMensagens de log criptografadas gravadas em: {LOG_FILE}")
    print(f"Chave de criptografia armazenada em: {KEY_FILE}")
    print(f"Cadeia de hash armazenada em: {HASH_CHAIN_FILE}")
    print("A saída do console permanece em texto simples.")
    
    print("\nPara visualizar os logs descriptografados, você pode executar:")
    print("  from utils.logger import view_encrypted_logs")
    print("  view_encrypted_logs()")
    
    print("\nTentando exibir os logs descriptografados agora para verificação:")
    view_encrypted_logs()

