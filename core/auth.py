# core/auth.py

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# Curva elíptica para assinaturas digitais (a mesma do ECDH para consistência, ou outra se preferir)
SIGNATURE_CURVE = ec.SECP384R1()

class AuthManager:
    def __init__(self):
        self.signing_private_key = ec.generate_private_key(SIGNATURE_CURVE)
        self.signing_public_key = self.signing_private_key.public_key()

    def get_signing_public_key_bytes(self):
        """Retorna a chave pública de assinatura em formato PEM para transmissão."""
        return self.signing_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign_message(self, message_bytes):
        """Assina uma mensagem usando a chave privada de assinatura (ECDSA)."""
        if not isinstance(message_bytes, bytes):
            message_bytes = message_bytes.encode("utf-8")
            
        signature = self.signing_private_key.sign(
            message_bytes,
            ec.ECDSA(hashes.SHA256()) # Algoritmo de assinatura ECDSA com SHA256
        )
        return signature

    @staticmethod
    def verify_signature(peer_signing_public_key_bytes, message_bytes, signature_bytes):
        """Verifica a assinatura de uma mensagem usando a chave pública de assinatura do peer."""
        if not isinstance(message_bytes, bytes):
            message_bytes = message_bytes.encode("utf-8")

        try:
            signing_public_key = serialization.load_pem_public_key(
                peer_signing_public_key_bytes
            )
            signing_public_key.verify(
                signature_bytes,
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            print("Verificação de assinatura falhou: Assinatura inválida.")
            return False
        except Exception as e:
            print(f"Erro durante a verificação da assinatura: {e}")
            return False

# Exemplo de uso (para teste inicial)
if __name__ == '__main__':
    # Peer A (remetente)
    peer_A_auth = AuthManager()
    peer_A_signing_public_key_bytes = peer_A_auth.get_signing_public_key_bytes()

    # Peer B (destinatário)
    # Em um cenário real, Peer B receberia peer_A_signing_public_key_bytes pela rede.

    mensagem_original = "Esta eh uma mensagem para ser assinada e verificada."
    mensagem_bytes = mensagem_original.encode("utf-8")

    # Peer A assina a mensagem
    assinatura_A = peer_A_auth.sign_message(mensagem_bytes)
    print(f"Peer A - Assinatura: {assinatura_A.hex()}")

    # Peer B verifica a assinatura
    # Para este teste, usamos diretamente a chave pública de A.
    verificacao_B = AuthManager.verify_signature(
        peer_signing_public_key_bytes,
        mensagem_bytes,
        assinatura_A
    )

    if verificacao_B:
        print("Peer B - Verificação da assinatura: SUCESSO!")
    else:
        print("Peer B - Verificação da assinatura: FALHA!")
    
    assert verificacao_B, "A verificação da assinatura falhou!"

    # Teste de falha na verificação (mensagem adulterada)
    mensagem_adulterada_bytes = b"Esta eh uma mensagem ADULTERADA."
    verificacao_adulterada = AuthManager.verify_signature(
        peer_signing_public_key_bytes,
        mensagem_adulterada_bytes,
        assinatura_A
    )
    assert not verificacao_adulterada, "A verificação da assinatura deveria falhar para mensagem adulterada."
    print("Teste de falha com mensagem adulterada: SUCESSO (assinatura não verificou como esperado).")

    # Teste de falha na verificação (assinatura errada)
    outra_assinatura = AuthManager().sign_message(b"outra mensagem")
    verificacao_assinatura_errada = AuthManager.verify_signature(
        peer_signing_public_key_bytes,
        mensagem_bytes,
        outra_assinatura
    )
    assert not verificacao_assinatura_errada, "A verificação da assinatura deveria falhar para assinatura errada."
    print("Teste de falha com assinatura errada: SUCESSO (assinatura não verificou como esperado).")

    print("\nTestes básicos do AuthManager concluídos.")

