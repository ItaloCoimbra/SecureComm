#!/usr/bin/env python3
# server/session_manager.py

import time
import threading
import json
import socket
from datetime import datetime
import os
import sys

# Adicionar o diretório raiz ao path para importar módulos corretamente
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import setup_logger
from core.crypto import CryptoManager

# Configurar logger
logger = setup_logger(name="SessionManager", log_level=20)  # INFO = 20

class SessionManager:
    """
    Gerencia as sessões de comunicação entre peers, incluindo:
    - Rastreamento de sessões ativas
    - Manutenção do estado da criptografia para cada sessão
    - Estatísticas de tráfego e métricas para detecção de anomalias
    """
    
    def __init__(self, session_timeout=1800):  # 30 minutos de timeout padrão
        self.sessions = {}  # {session_id: session_data}
        self.session_timeout = session_timeout
        self.last_cleanup = time.time()
        self.cleanup_interval = 300  # Limpar sessões expiradas a cada 5 minutos
        self.lock = threading.RLock()  # Lock para thread-safety
        
        # Iniciar thread de limpeza de sessão
        self.is_running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired_sessions, daemon=True)
        self.cleanup_thread.start()
        
        logger.info("SessionManager inicializado")
    
    def create_session(self, conn, addr, session_crypto=None, peer_info=None):
        """
        Cria uma nova sessão para um peer conectado.
        
        Args:
            conn: Objeto de conexão do socket
            addr: Tupla (host, port) do peer
            session_crypto: Instância do CryptoManager para esta sessão
            peer_info: Dicionário com informações adicionais sobre o peer
            
        Returns:
            session_id: ID da sessão criada
        """
        with self.lock:
            session_id = f"{addr[0]}:{addr[1]}_{int(time.time())}"
            
            if not session_crypto:
                session_crypto = CryptoManager()
            
            self.sessions[session_id] = {
                "conn": conn,
                "addr": addr,
                "crypto": session_crypto,
                "created_at": time.time(),
                "last_activity": time.time(),
                "peer_info": peer_info or {},
                "traffic_stats": {
                    "messages_sent": 0,
                    "messages_received": 0,
                    "bytes_sent": 0,
                    "bytes_received": 0,
                    "message_timestamps": [],  # Lista de timestamps para análise de frequência
                    "message_sizes": []  # Lista de tamanhos de mensagem para análise
                }
            }
            
            logger.info(f"Nova sessão criada: {session_id} para {addr}")
            return session_id
    
    def get_session(self, session_id):
        """
        Obtém os dados de uma sessão pelo ID.
        
        Args:
            session_id: ID da sessão
            
        Returns:
            dict: Dados da sessão ou None se não for encontrada
        """
        with self.lock:
            session = self.sessions.get(session_id)
            if session:
                # Atualizar timestamp de última atividade
                session["last_activity"] = time.time()
            return session
    
    def get_session_by_conn(self, conn):
        """
        Obtém uma sessão pelo objeto de conexão.
        
        Args:
            conn: Objeto de conexão do socket
            
        Returns:
            (session_id, session_data): Tupla com ID da sessão e dados, ou (None, None)
        """
        with self.lock:
            for session_id, session_data in self.sessions.items():
                if session_data["conn"] == conn:
                    # Atualizar timestamp de última atividade
                    session_data["last_activity"] = time.time()
                    return session_id, session_data
            return None, None
    
    def update_session_activity(self, session_id, bytes_sent=0, bytes_received=0, 
                               message_sent=False, message_received=False, message_size=0):
        """
        Atualiza as estatísticas de atividade de uma sessão.
        
        Args:
            session_id: ID da sessão
            bytes_sent: Número de bytes enviados
            bytes_received: Número de bytes recebidos
            message_sent: Se uma mensagem completa foi enviada
            message_received: Se uma mensagem completa foi recebida
            message_size: Tamanho da mensagem em bytes
        """
        with self.lock:
            session = self.sessions.get(session_id)
            if not session:
                return False
            
            # Atualizar timestamp de última atividade
            session["last_activity"] = current_time = time.time()
            
            # Atualizar estatísticas
            if bytes_sent > 0:
                session["traffic_stats"]["bytes_sent"] += bytes_sent
            if bytes_received > 0:
                session["traffic_stats"]["bytes_received"] += bytes_received
            if message_sent:
                session["traffic_stats"]["messages_sent"] += 1
            if message_received:
                session["traffic_stats"]["messages_received"] += 1
                session["traffic_stats"]["message_timestamps"].append(current_time)
                session["traffic_stats"]["message_sizes"].append(message_size)
                
                # Manter apenas os últimos 100 timestamps/tamanhos para economizar memória
                max_history = 100
                if len(session["traffic_stats"]["message_timestamps"]) > max_history:
                    session["traffic_stats"]["message_timestamps"] = session["traffic_stats"]["message_timestamps"][-max_history:]
                    session["traffic_stats"]["message_sizes"] = session["traffic_stats"]["message_sizes"][-max_history:]
            
            return True
    
    def close_session(self, session_id, reason="Normal disconnect"):
        """
        Fecha e remove uma sessão.
        
        Args:
            session_id: ID da sessão
            reason: Motivo do fechamento
        """
        with self.lock:
            session = self.sessions.pop(session_id, None)
            if not session:
                return False
            
            try:
                conn = session["conn"]
                addr = session["addr"]
                conn.close()
                logger.info(f"Sessão fechada: {session_id} ({addr}) - Motivo: {reason}")
                return True
            except Exception as e:
                logger.error(f"Erro ao fechar sessão {session_id}: {e}")
                return False
    
    def get_session_stats(self, session_id):
        """
        Obtém estatísticas detalhadas de uma sessão.
        
        Args:
            session_id: ID da sessão
            
        Returns:
            dict: Estatísticas da sessão ou None se não for encontrada
        """
        with self.lock:
            session = self.sessions.get(session_id)
            if not session:
                return None
            
            current_time = time.time()
            session_age = current_time - session["created_at"]
            last_activity_ago = current_time - session["last_activity"]
            
            # Calcular métricas para detecção de anomalias
            message_count = session["traffic_stats"]["messages_received"]
            timestamps = session["traffic_stats"]["message_timestamps"]
            
            # Calcular frequência de mensagens nas últimas janelas de tempo
            msgs_last_minute = sum(1 for ts in timestamps if current_time - ts <= 60)
            msgs_last_5min = sum(1 for ts in timestamps if current_time - ts <= 300)
            
            # Calcular intervalo médio entre mensagens se houver pelo menos 2 mensagens
            avg_interval = 0
            if len(timestamps) >= 2:
                intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                avg_interval = sum(intervals) / len(intervals) if intervals else 0
            
            # Calcular tamanho médio de mensagem
            message_sizes = session["traffic_stats"]["message_sizes"]
            avg_message_size = sum(message_sizes) / len(message_sizes) if message_sizes else 0
            
            return {
                "session_id": session_id,
                "peer_address": session["addr"],
                "peer_info": session["peer_info"],
                "session_age_seconds": session_age,
                "last_activity_seconds_ago": last_activity_ago,
                "messages_sent": session["traffic_stats"]["messages_sent"],
                "messages_received": session["traffic_stats"]["messages_received"],
                "bytes_sent": session["traffic_stats"]["bytes_sent"],
                "bytes_received": session["traffic_stats"]["bytes_received"],
                "msgs_last_minute": msgs_last_minute,
                "msgs_last_5min": msgs_last_5min,
                "avg_interval_seconds": avg_interval,
                "avg_message_size_bytes": avg_message_size,
                "is_active": last_activity_ago < self.session_timeout
            }
    
    def list_sessions(self, active_only=True):
        """
        Lista todas as sessões ativas ou todas as sessões.
        
        Args:
            active_only: Se True, retorna apenas sessões ativas
            
        Returns:
            list: Lista de IDs de sessão
        """
        with self.lock:
            current_time = time.time()
            if active_only:
                return [sid for sid, data in self.sessions.items() 
                       if current_time - data["last_activity"] < self.session_timeout]
            else:
                return list(self.sessions.keys())
    
    def _cleanup_expired_sessions(self):
        """Thread de limpeza de sessões expiradas."""
        while self.is_running:
            time.sleep(10)  # Verificar a cada 10 segundos
            
            current_time = time.time()
            if current_time - self.last_cleanup >= self.cleanup_interval:
                with self.lock:
                    expired_sessions = []
                    for session_id, session in self.sessions.items():
                        if current_time - session["last_activity"] >= self.session_timeout:
                            expired_sessions.append(session_id)
                    
                    for session_id in expired_sessions:
                        self.close_session(session_id, reason="Session timeout")
                    
                    if expired_sessions:
                        logger.info(f"Limpeza de sessões: {len(expired_sessions)} sessões expiradas removidas")
                    
                    self.last_cleanup = current_time
    
    def shutdown(self):
        """Desliga o gerenciador de sessões e fecha todas as sessões."""
        logger.info("Desligando SessionManager...")
        self.is_running = False
        
        with self.lock:
            for session_id in list(self.sessions.keys()):
                self.close_session(session_id, reason="Server shutdown")
            
            logger.info("Todas as sessões foram fechadas")


# Exemplo de uso para teste
if __name__ == "__main__":
    print("Testando SessionManager...")
    
    # Criar um gerenciador de sessões com timeout menor para teste
    session_mgr = SessionManager(session_timeout=60)  # 60 segundos de timeout
    
    # Criar sessões de teste simuladas
    mock_conn1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mock_conn2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    session1 = session_mgr.create_session(mock_conn1, ('127.0.0.1', 12345), 
                                         peer_info={"username": "usuario_teste1"})
    session2 = session_mgr.create_session(mock_conn2, ('192.168.1.100', 54321), 
                                         peer_info={"username": "usuario_teste2"})
    
    print(f"Sessões criadas: {session1}, {session2}")
    
    # Simular algumas atividades
    session_mgr.update_session_activity(session1, bytes_received=1024, message_received=True, message_size=1024)
    session_mgr.update_session_activity(session1, bytes_sent=512, message_sent=True)
    session_mgr.update_session_activity(session2, bytes_received=2048, message_received=True, message_size=2048)
    
    # Listar sessões
    print(f"Sessões ativas: {session_mgr.list_sessions()}")
    
    # Obter estatísticas
    stats1 = session_mgr.get_session_stats(session1)
    print(f"Estatísticas da sessão 1: {json.dumps(stats1, indent=2)}")
    
    # Fechar uma sessão manualmente
    session_mgr.close_session(session2, reason="Teste de fechamento")
    print(f"Sessões ativas após fechar a sessão 2: {session_mgr.list_sessions()}")
    
    # Limpar recursos
    print("Desligando SessionManager...")
    session_mgr.shutdown()
    
    # Fechar os sockets mock (não são reais, mas é boa prática)
    try:
        mock_conn1.close()
        mock_conn2.close()
    except:
        pass
    
    print("Teste concluído.") 