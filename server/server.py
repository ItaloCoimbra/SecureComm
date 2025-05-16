#!/usr/bin/env python3
# server/server.py

import os
import sys
import argparse
import threading
import json
import time
from datetime import datetime
import socket

# Adicionar o diretório raiz ao path para importar módulos corretamente
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.crypto import CryptoManager
from core.auth import AuthManager
from core.comm import P2PCommunication
from core.anomaly import AnomalyDetector
from utils.logger import setup_logger
from server.session_manager import SessionManager

# Configurar logger
logger = setup_logger(name="SecureCommServer", log_level=20)  # INFO = 20

class SecureCommServer:
    """
    Servidor para comunicação segura P2P.
    Gerencia conexões de múltiplos clientes, autenticação, e detecção de anomalias.
    """
    
    def __init__(self, host='0.0.0.0', port=12345, server_name="SecureCommServer"):
        self.host = host
        self.port = port
        self.server_name = server_name
        self.is_running = False
        self.stats = {
            "start_time": time.time(),
            "connections_total": 0,
            "connections_active": 0,
            "messages_processed": 0,
            "anomalies_detected": 0,
            "last_anomaly_time": None
        }
        
        # Inicializar o gerenciador de autenticação
        self.auth_manager = AuthManager()
        logger.info(f"Auth Manager inicializado para o servidor '{server_name}'")
        
        # Inicializar o detector de anomalias
        self.anomaly_detector = AnomalyDetector()
        if not self.anomaly_detector.load_model():
            logger.warning("Modelo de detecção de anomalias não encontrado. Detecção pode não funcionar corretamente.")
        
        # Inicializar o gerenciador de sessões
        self.session_manager = SessionManager()
        logger.info("Session Manager inicializado")
        
        # Inicializar o gerenciador de comunicação P2P
        self.communication = P2PCommunication(
            host=self.host,
            port=self.port,
            local_auth_manager=self.auth_manager,
            anomaly_detector_instance=self.anomaly_detector,
            on_message_received_callback=self.handle_message,
            on_peer_connected_callback=self.handle_peer_connected,
            on_peer_disconnected_callback=self.handle_peer_disconnected,
            on_anomaly_detected_callback=self.handle_anomaly_detected
        )
        
        # Dicionário de callbacks de handlers para diferentes tipos de mensagens
        self.message_handlers = {
            "CHAT": self.handle_chat_message,
            "USERNAME": self.handle_username_message,
            "PING": self.handle_ping_message,
            "STATS": self.handle_stats_message,
            "LIST_PEERS": self.handle_list_peers_message,
            "BENCHMARK_ECHO": self.handle_benchmark_echo_message,
            "LIST_ANOMALIES": self.handle_list_anomalies_message
        }
        
        logger.info(f"Servidor inicializado em {self.host}:{self.port}")
    
    def start(self):
        """Inicia o servidor para aceitar conexões"""
        if self.is_running:
            logger.warning("O servidor já está em execução")
            return False
        
        # Iniciar o servidor para escutar conexões
        if not self.communication.start_listening():
            logger.error(f"Falha ao iniciar servidor em {self.host}:{self.port}")
            return False
        
        self.is_running = True
        logger.info(f"Servidor iniciado e escutando em {self.host}:{self.port}")
        print(f"Servidor iniciado em {self.host}:{self.port}")
        return True
    
    def stop(self):
        """Para o servidor e fecha todas as conexões"""
        if not self.is_running:
            logger.warning("O servidor já está parado")
            return False
        
        logger.info("Parando servidor...")
        self.communication.stop_listening()
        self.session_manager.shutdown()
        self.is_running = False
        logger.info("Servidor parado")
        print("Servidor parado")
        return True
    
    def handle_peer_connected(self, conn, addr):
        """Callback quando um novo peer se conecta"""
        logger.info(f"Novo peer conectado: {addr}")
        print(f"Novo peer conectado: {addr}")
        
        # Criar uma sessão para este peer
        session_crypto = self.communication.peer_sessions.get(conn, {}).get("session_crypto")
        session_id = self.session_manager.create_session(conn, addr, session_crypto=session_crypto)
        
        # Atualizar estatísticas
        self.stats["connections_total"] += 1
        self.stats["connections_active"] += 1
        
        # Verificar número de conexões ativas
        active_sessions = len(self.session_manager.list_sessions(active_only=True))
        logger.info(f"Sessões ativas atuais: {active_sessions}")
        print(f"Sessões ativas atuais: {active_sessions}")
        print(f"Conexões ativas do P2P: {len(self.communication.active_connections)}")
        
        # Enviar mensagem de boas-vindas
        welcome_payload = {
            "message": f"Bem-vindo ao {self.server_name}!",
            "server_time": time.time(),
            "server_id": self.server_name
        }
        self.communication.send_message(conn, "WELCOME", welcome_payload)
    
    def handle_peer_disconnected(self, conn, addr):
        """Callback quando um peer desconecta"""
        logger.info(f"Peer desconectado: {addr}")
        print(f"Peer desconectado: {addr}")
        
        # Obter e fechar a sessão
        session_id, session = self.session_manager.get_session_by_conn(conn)
        if session_id:
            logger.info(f"Fechando sessão: {session_id}")
            self.session_manager.close_session(session_id, reason="Peer disconnected")
        else:
            logger.warning(f"Não foi encontrada sessão para a conexão do peer: {addr}")
        
        # Atualizar estatísticas
        self.stats["connections_active"] = max(0, self.stats["connections_active"] - 1)
        
        # Verificar número de conexões ativas
        active_sessions = len(self.session_manager.list_sessions(active_only=True))
        logger.info(f"Sessões ativas atuais: {active_sessions}")
        print(f"Sessões ativas atuais: {active_sessions}")
        print(f"Conexões ativas do P2P: {len(self.communication.active_connections)}")
    
    def handle_message(self, conn, addr, message_type, message_payload, full_msg=None):
        """Callback para processar mensagens recebidas"""
        # Obter a sessão do peer
        session_id, session = self.session_manager.get_session_by_conn(conn)
        if not session_id:
            logger.warning(f"Mensagem recebida de peer sem sessão: {addr}, tipo: {message_type}")
            return
        
        # Atualizar estatísticas da sessão
        message_size = sys.getsizeof(json.dumps(message_payload))
        self.session_manager.update_session_activity(
            session_id, bytes_received=message_size, message_received=True, message_size=message_size
        )
        
        # Atualizar estatísticas do servidor
        self.stats["messages_processed"] += 1
        
        # Direcionar para o handler específico
        handler = self.message_handlers.get(message_type)
        if handler:
            handler(conn, addr, message_payload, session_id, session)
        else:
            logger.info(f"Mensagem de tipo não tratado: {message_type} de {addr}")
    
    def handle_anomaly_detected(self, peer_addr, event_type, score, details):
        """Callback quando uma anomalia é detectada"""
        logger.warning(f"ANOMALIA DETECTADA de {peer_addr}! Tipo: {event_type}, Score: {score:.4f}")
        
        # Atualizar estatísticas
        self.stats["anomalies_detected"] += 1
        self.stats["last_anomaly_time"] = time.time()
        
        # Registrar detalhes da anomalia
        anomaly_details = {
            "peer_addr": peer_addr,
            "event_type": event_type,
            "score": score,
            "timestamp": time.time(),
            "details": details or {}
        }
        
        # Salvar anomalia no arquivo de anomalias
        anomaly_file = os.path.join(os.path.dirname(__file__), "..", "data", "detected_anomalies.json")
        try:
            # Carregar anomalias existentes, se houver
            if os.path.exists(anomaly_file):
                with open(anomaly_file, 'r') as f:
                    anomalies = json.load(f)
            else:
                anomalies = []
            
            # Adicionar nova anomalia
            anomalies.append({
                "id": len(anomalies) + 1,
                "timestamp": anomaly_details["timestamp"],
                "datetime": datetime.fromtimestamp(anomaly_details["timestamp"]).strftime('%Y-%m-%d %H:%M:%S'),
                "peer_addr": str(anomaly_details["peer_addr"]),
                "event_type": anomaly_details["event_type"],
                "score": anomaly_details["score"],
                "details": anomaly_details["details"],
                "reviewed": False,
                "confirmed": None
            })
            
            # Salvar arquivo atualizado
            os.makedirs(os.path.dirname(anomaly_file), exist_ok=True)
            with open(anomaly_file, 'w') as f:
                json.dump(anomalies, f, indent=2)
            
            logger.info(f"Anomalia #{len(anomalies)} salva em {anomaly_file}")
        except Exception as e:
            logger.error(f"Erro ao salvar anomalia: {e}")
        
        # Log usual
        logger.warning(f"Detalhes da anomalia: {json.dumps(anomaly_details)}")
        
        # Opcional: Notificar outros peers sobre a anomalia
        alert_payload = {
            "alert_type": "anomaly",
            "peer_addr": str(peer_addr),
            "event_type": event_type,
            "score": score,
            "timestamp": time.time()
        }
        # self.broadcast_to_admins("SECURITY_ALERT", alert_payload)
    
    def view_anomalies(self, limit=10, include_reviewed=False):
        """Retorna as últimas anomalias detectadas"""
        anomaly_file = os.path.join(os.path.dirname(__file__), "..", "data", "detected_anomalies.json")
        
        if not os.path.exists(anomaly_file):
            return {"anomalies": [], "count": 0}
        
        try:
            with open(anomaly_file, 'r') as f:
                all_anomalies = json.load(f)
            
            # Filtrar se necessário
            if not include_reviewed:
                filtered_anomalies = [a for a in all_anomalies if not a.get("reviewed", False)]
            else:
                filtered_anomalies = all_anomalies
            
            # Ordenar por timestamp (mais recente primeiro) e limitar
            sorted_anomalies = sorted(filtered_anomalies, key=lambda x: x.get("timestamp", 0), reverse=True)
            limited_anomalies = sorted_anomalies[:limit]
            
            return {
                "anomalies": limited_anomalies,
                "count": len(limited_anomalies),
                "total": len(all_anomalies)
            }
        except Exception as e:
            logger.error(f"Erro ao ler anomalias: {e}")
            return {"anomalies": [], "count": 0, "error": str(e)}
    
    # Handlers específicos para tipos de mensagem
    
    def handle_chat_message(self, conn, addr, payload, session_id, session):
        """Processa mensagens de chat e as retransmite para outros clientes"""
        content = payload.get("content", "")
        username = session.get("peer_info", {}).get("username", f"{addr[0]}:{addr[1]}")
        
        logger.info(f"Mensagem de chat de {username}: {content}")
        
        # Enriquecer a mensagem com informações do remetente
        broadcast_payload = {
            "content": content,
            "sender": username,
            "timestamp": time.time(),
            "original_timestamp": payload.get("timestamp", time.time())
        }
        
        # Retransmitir para todos os outros clientes
        for peer_conn in self.communication.active_connections:
            if peer_conn != conn:  # Não enviar de volta para o remetente
                self.communication.send_message(peer_conn, "CHAT", broadcast_payload)
    
    def handle_username_message(self, conn, addr, payload, session_id, session):
        """Processa mensagens de atualização de nome de usuário"""
        old_username = session.get("peer_info", {}).get("username", "")
        new_username = payload.get("username", "")
        
        if not new_username:
            logger.warning(f"Tentativa de definir nome de usuário vazio de {addr}")
            return
        
        # Atualizar o nome de usuário na sessão
        if "peer_info" not in session:
            session["peer_info"] = {}
        session["peer_info"]["username"] = new_username
        
        logger.info(f"Nome de usuário alterado: {addr} de '{old_username}' para '{new_username}'")
        
        # Notificar outros usuários sobre a mudança de nome
        if old_username:  # Se não é a primeira definição
            notification_payload = {
                "old_username": old_username,
                "new_username": new_username,
                "timestamp": time.time()
            }
            for peer_conn in self.communication.active_connections:
                if peer_conn != conn:  # Não enviar de volta para o remetente
                    self.communication.send_message(peer_conn, "USERNAME_CHANGE", notification_payload)
    
    def handle_ping_message(self, conn, addr, payload, session_id, session):
        """Processa mensagens de ping e responde com pong"""
        client_timestamp = payload.get("timestamp", time.time())
        
        # Calcular RTT (Round Trip Time)
        current_time = time.time()
        rtt = current_time - client_timestamp
        
        # Responder com pong
        pong_payload = {
            "client_timestamp": client_timestamp,
            "server_timestamp": current_time,
            "rtt": rtt
        }
        self.communication.send_message(conn, "PONG", pong_payload)
    
    def handle_stats_message(self, conn, addr, payload, session_id, session):
        """Processa solicitações de estatísticas e responde com informações do servidor"""
        # Verificar se o cliente tem permissão para receber estatísticas
        # Aqui você poderia implementar verificações de autorização
        
        # Calcular métricas adicionais
        uptime = time.time() - self.stats["start_time"]
        active_sessions = len(self.session_manager.list_sessions(active_only=True))
        
        # Estatísticas básicas do servidor
        stats_payload = {
            "server_name": self.server_name,
            "uptime_seconds": uptime,
            "connections_total": self.stats["connections_total"],
            "connections_active": active_sessions,
            "messages_processed": self.stats["messages_processed"],
            "anomalies_detected": self.stats["anomalies_detected"],
            "timestamp": time.time()
        }
        
        # Enviar estatísticas
        self.communication.send_message(conn, "STATS_RESPONSE", stats_payload)
    
    def handle_list_peers_message(self, conn, addr, payload, session_id, session):
        """Processa solicitações de lista de peers conectados"""
        # Verificar se o cliente tem permissão para listar peers
        # Aqui você poderia implementar verificações de autorização
        
        logger.info(f"Solicitação de lista de peers de {addr}")
        print(f"Solicitação de lista de peers de {addr}")
        
        # Lista todas as sessões ativas
        active_sessions = self.session_manager.list_sessions(active_only=True)
        logger.info(f"Sessões ativas encontradas: {len(active_sessions)}")
        
        peers_list = []
        for sid in active_sessions:
            peer_session = self.session_manager.get_session(sid)
            if peer_session and peer_session["conn"] != conn:  # Não incluir o solicitante
                peers_list.append({
                    "addr": f"{peer_session['addr'][0]}:{peer_session['addr'][1]}",
                    "username": peer_session.get("peer_info", {}).get("username", "Anônimo"),
                    "connected_since": int(peer_session["created_at"])
                })
        
        peers_payload = {
            "peers": peers_list,
            "count": len(peers_list),
            "timestamp": time.time()
        }
        
        logger.info(f"Enviando lista de {len(peers_list)} peers para {addr}")
        print(f"Enviando lista de {len(peers_list)} peers para {addr}")
        self.communication.send_message(conn, "PEERS_LIST", peers_payload)
    
    def handle_benchmark_echo_message(self, conn, addr, payload, session_id, session):
        """
        Processa mensagens de benchmark echo - simplesmente retorna a mesma mensagem
        para testes de desempenho
        """
        logger.debug(f"Recebida mensagem de benchmark de {addr}")
        
        # Apenas devolver a mesma mensagem como resposta
        self.communication.send_message(conn, "BENCHMARK_ECHO", payload)
    
    def handle_list_anomalies_message(self, conn, addr, payload, session_id, session):
        """Processa solicitações de lista de anomalias detectadas"""
        logger.info(f"Solicitação de lista de anomalias de {addr}")
        print(f"Solicitação de lista de anomalias de {addr}")
        
        # Obter parâmetros da solicitação
        limit = payload.get("limit", 10)
        include_reviewed = payload.get("include_reviewed", False)
        
        # Obter anomalias
        anomalies_data = self.view_anomalies(limit=limit, include_reviewed=include_reviewed)
        
        # Adicionar timestamp
        anomalies_data["timestamp"] = time.time()
        
        logger.info(f"Enviando lista de {anomalies_data['count']} anomalias para {addr} (de {anomalies_data['total']} total)")
        print(f"Enviando lista de {anomalies_data['count']} anomalias para {addr} (de {anomalies_data['total']} total)")
        
        # Enviar resposta
        self.communication.send_message(conn, "ANOMALIES_LIST", anomalies_data)
    
    # Métodos auxiliares
    
    def broadcast_message(self, message_type, payload):
        """Envia uma mensagem para todos os peers conectados"""
        self.communication.broadcast_message(message_type, payload)
    
    def broadcast_to_admins(self, message_type, payload):
        """Envia uma mensagem apenas para peers com status de administrador"""
        admin_conns = []
        for sid in self.session_manager.list_sessions(active_only=True):
            session = self.session_manager.get_session(sid)
            if session and session.get("peer_info", {}).get("is_admin", False):
                admin_conns.append(session["conn"])
        
        for conn in admin_conns:
            self.communication.send_message(conn, message_type, payload)
    
    def get_server_stats(self):
        """Retorna estatísticas atuais do servidor"""
        uptime = time.time() - self.stats["start_time"]
        active_sessions = len(self.session_manager.list_sessions(active_only=True))
        
        return {
            "server_name": self.server_name,
            "host": self.host,
            "port": self.port,
            "uptime_seconds": uptime,
            "uptime_formatted": str(datetime.utcfromtimestamp(uptime).strftime('%H:%M:%S')),
            "connections_total": self.stats["connections_total"],
            "connections_active": active_sessions,
            "messages_processed": self.stats["messages_processed"],
            "anomalies_detected": self.stats["anomalies_detected"],
            "last_anomaly_time": self.stats["last_anomaly_time"],
            "timestamp": time.time()
        }


def main():
    """Função principal para executar o servidor"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Servidor de comunicação segura P2P')
    parser.add_argument('-p', '--port', type=int, default=12345, help='Porta para escutar (padrão: 12345)')
    parser.add_argument('-H', '--host', default='0.0.0.0', help='Host para escutar (padrão: 0.0.0.0)')
    parser.add_argument('-n', '--name', default="SecureCommServer", help='Nome do servidor')
    args = parser.parse_args()
    
    try:
        server = SecureCommServer(host=args.host, port=args.port, server_name=args.name)
        if not server.start():
            logger.critical("Falha ao iniciar o servidor. Encerrando.")
            sys.exit(1)
        
        print(f"Servidor '{args.name}' iniciado em {args.host}:{args.port}")
        print("Pressione Ctrl+C para encerrar")
        
        # Loop principal - mantém o programa rodando até Ctrl+C
        try:
            while server.is_running:
                time.sleep(1)
                
                # A cada 60 segundos, exibir estatísticas no console
                if int(time.time()) % 60 == 0:
                    stats = server.get_server_stats()
                    print(f"\nEstatísticas do servidor ({datetime.now().strftime('%H:%M:%S')}):")
                    print(f"Uptime: {stats['uptime_formatted']}")
                    print(f"Conexões: {stats['connections_active']} ativas / {stats['connections_total']} total")
                    print(f"Mensagens processadas: {stats['messages_processed']}")
                    print(f"Anomalias detectadas: {stats['anomalies_detected']}")
                    
                    # Evitar exibição repetida na mesma iteração
                    time.sleep(1)
        
        except KeyboardInterrupt:
            print("\nEncerrando servidor...")
        finally:
            server.stop()
            print("Servidor encerrado com sucesso.")
    
    except Exception as e:
        logger.critical(f"Erro fatal: {e}")
        print(f"Erro fatal: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 