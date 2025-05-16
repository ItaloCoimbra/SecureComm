# core/crypto.py

from cryptography.hazmat.primitives import hashes, serialization # Updated import
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Curva elíptica recomendada para ECDH
CURVE = ec.SECP384R1()

class CryptoManager:
    def __init__(self):
        self.private_key = ec.generate_private_key(CURVE)
        self.public_key = self.private_key.public_key()
        self.shared_key = None
        self.aes_gcm = None

    def get_public_key_bytes(self):
        """Retorna a chave pública em formato de bytes para transmissão."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM, # Corrected usage
            format=serialization.PublicFormat.SubjectPublicKeyInfo # Corrected usage
        )

    def generate_shared_secret(self, peer_public_key_bytes):
        """Gera o segredo compartilhado usando a chave pública do peer."""
        peer_public_key = serialization.load_pem_public_key( # Corrected usage
            peer_public_key_bytes
        )
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
        return shared_secret

    def derive_session_key(self, shared_secret, salt=None):
        """Deriva uma chave de sessão simétrica do segredo compartilhado usando HKDF."""
        if salt is None:
            salt = os.urandom(16)
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256 requer chave de 32 bytes
            salt=salt,
            info=b'session_key_derivation',
        )
        self.shared_key = hkdf.derive(shared_secret)
        self.aes_gcm = AESGCM(self.shared_key)
        return self.shared_key, salt # Retorna a chave e o salt usado

    def encrypt_message(self, plaintext_bytes):
        """Criptografa uma mensagem usando AES-GCM."""
        if not self.aes_gcm:
            raise ValueError("Chave de sessão não derivada. Chame derive_session_key primeiro.")
        nonce = os.urandom(12)  # Nonce de 96 bits (12 bytes) é recomendado para GCM
        ciphertext_bytes = self.aes_gcm.encrypt(nonce, plaintext_bytes, None) # Sem dados adicionais autenticados (AAD)
        return nonce + ciphertext_bytes # Prepend nonce ao ciphertext

    def decrypt_message(self, ciphertext_with_nonce_bytes):
        """Descriptografa uma mensagem usando AES-GCM."""
        if not self.aes_gcm:
            raise ValueError("Chave de sessão não derivada. Chame derive_session_key primeiro.")
        nonce = ciphertext_with_nonce_bytes[:12]
        ciphertext_bytes = ciphertext_with_nonce_bytes[12:]
        try:
            plaintext_bytes = self.aes_gcm.decrypt(nonce, ciphertext_bytes, None)
            return plaintext_bytes
        except Exception as e: # cryptography.exceptions.InvalidTag
            print(f"Erro na descriptografia: {e}")
            return None

    def reset_session(self):
        """Reinicia as chaves para uma nova sessão (para forward secrecy)."""
        self.private_key = ec.generate_private_key(CURVE)
        self.public_key = self.private_key.public_key()
        self.shared_key = None
        self.aes_gcm = None

# Exemplo de uso (para teste inicial)
if __name__ == '__main__':
    # Peer A
    peer_A = CryptoManager()
    peer_A_public_key_bytes = peer_A.get_public_key_bytes()

    # Peer B
    peer_B = CryptoManager()
    peer_B_public_key_bytes = peer_B.get_public_key_bytes()

    # Troca de chaves e derivação (simulando a troca pela rede)
    # Peer A calcula o segredo compartilhado com a chave pública de B
    shared_secret_A = peer_A.generate_shared_secret(peer_B_public_key_bytes)
    session_key_A, salt_A = peer_A.derive_session_key(shared_secret_A)
    print(f"Peer A - Chave de Sessão: {session_key_A.hex()}")

    # Peer B calcula o segredo compartilhado com a chave pública de A
    shared_secret_B = peer_B.generate_shared_secret(peer_A_public_key_bytes)
    # Peer B DEVE usar o mesmo salt que A para derivar a mesma chave de sessão
    # Em um cenário real, o salt seria enviado por A para B junto com a chave pública ou em uma etapa separada.
    # Para este exemplo, vamos assumir que B recebeu o salt_A.
    session_key_B, _ = peer_B.derive_session_key(shared_secret_B, salt=salt_A)
    print(f"Peer B - Chave de Sessão: {session_key_B.hex()}")

    assert session_key_A == session_key_B, "As chaves de sessão não coincidem!"
    print("Chaves de sessão coincidem. ECDH e derivação de chave OK.")

    # Teste de Criptografia e Descriptografia
    mensagem_original = b"Esta eh uma mensagem secreta para teste!"

    # Peer A criptografa
    ciphertext_A = peer_A.encrypt_message(mensagem_original)
    print(f"Peer A - Ciphertext: {ciphertext_A.hex()}")

    # Peer B descriptografa
    plaintext_B = peer_B.decrypt_message(ciphertext_A)
    print(f"Peer B - Plaintext: {plaintext_B.decode() if plaintext_B else 'Falha na descriptografia'}")

    assert mensagem_original == plaintext_B, "A mensagem descriptografada não coincide com a original!"
    print("Criptografia e descriptografia AES-GCM OK.")

    # Teste de Forward Secrecy (simples)
    peer_A.reset_session()
    peer_A_new_public_key_bytes = peer_A.get_public_key_bytes()
    assert peer_A_public_key_bytes != peer_A_new_public_key_bytes, "A chave pública não mudou após o reset."
    print("Reset de sessão para forward secrecy OK (nova chave pública gerada).")

    print("\nTestes básicos do CryptoManager concluídos.")

