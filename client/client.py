#!/usr/bin/env python3
# client/client.py

import os
import sys
import argparse
import threading
import json
import time
from datetime import datetime

# Adicionar manipulação condicional para readline (que não está disponível nativamente no Windows)
try:
    import readline  # Para histórico de comandos e edição de linha no Linux/macOS
except ImportError:
    # No Windows, readline não está disponível
    # Podemos usar pyreadline3 se estiver instalado, ou simplesmente ignorar a funcionalidade
    try:
        import pyreadline3 as readline
    except ImportError:
        # Se pyreadline3 não estiver instalado, continue sem a funcionalidade de readline
        pass

# Adicionar o diretório raiz ao path para importar módulos corretamente
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.crypto import CryptoManager
from core.auth import AuthManager
from core.comm import P2PCommunication
from core.anomaly import AnomalyDetector
from utils.logger import setup_logger

# Configurar logger
logger = setup_logger(name="SecureCommClient", log_level=20)  # INFO = 20

class SecureCommClient:
    def __init__(self, host='0.0.0.0', port=12345, username=None):
        self.host = host
        self.port = port
        self.username = username or f"user_{os.getpid()}"
        self.is_running = False
        self.authenticated_peers = set()
        self.peer_usernames = {}  # Mapeamento de conexões para nomes de usuário
        self.current_peers = []  # Lista de pares conectados
        
        # Inicializar o gerenciador de autenticação
        self.auth_manager = AuthManager()
        logger.info(f"Auth Manager inicializado para o usuário {self.username}")
        
        # Inicializar o detector de anomalias
        self.anomaly_detector = AnomalyDetector()
        if not self.anomaly_detector.load_model():
            logger.warning("Modelo de detecção de anomalias não encontrado. Detecção pode não funcionar corretamente.")
        
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
        
        # Iniciar o servidor para escutar conexões
        if not self.communication.start_listening():
            logger.error(f"Falha ao iniciar serviço de escuta em {self.host}:{self.port}")
            raise RuntimeError(f"Não foi possível iniciar o servidor na porta {self.port}")
        
        logger.info(f"Cliente inicializado e escutando em {self.host}:{self.port}")
    
    def handle_message(self, conn, addr, message_type, message_payload, full_msg=None):
        """Callback para processar mensagens recebidas"""
        username = self.peer_usernames.get(conn, str(addr))
        
        # Processar diferentes tipos de mensagens
        if message_type == "CHAT":
            content = message_payload.get("content", "")
            timestamp = message_payload.get("timestamp", time.time())
            time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
            print(f"\r[{time_str}] {username}: {content}")
            logger.info(f"Mensagem recebida de {username}: {content}")
            # Força o prompt a reaparecer após exibir a mensagem
            print(f"{self.username}> ", end="", flush=True)
        
        elif message_type == "USERNAME":
            username = message_payload.get("username", "Anônimo")
            self.peer_usernames[conn] = username
            logger.info(f"Peer {addr} identificado como '{username}'")
            print(f"\r[Sistema] {addr} se identificou como '{username}'")
            print(f"{self.username}> ", end="", flush=True)
            
        elif message_type == "PEERS_LIST":
            peers = message_payload.get("peers", [])
            logger.info(f"Lista de peers recebida: {len(peers)} peers conectados")
            
            if not peers:
                print("\r[Sistema] Não há outros peers conectados.")
            else:
                print("\r[Sistema] Peers conectados:")
                for i, peer in enumerate(peers):
                    peer_addr = peer.get("addr", "desconhecido")
                    peer_username = peer.get("username", "Anônimo")
                    print(f"  [{i}] {peer_username} ({peer_addr})")
            
            print(f"{self.username}> ", end="", flush=True)
            
        elif message_type == "ANOMALIES_LIST":
            anomalies = message_payload.get("anomalies", [])
            count = message_payload.get("count", 0)
            total = message_payload.get("total", 0)
            
            logger.info(f"Lista de anomalias recebida: {count} anomalias (de {total} total)")
            
            if not anomalies:
                print("\r[Sistema] Não há anomalias registradas.")
            else:
                print(f"\r[Sistema] Anomalias detectadas ({count} de {total} total):")
                for anomaly in anomalies:
                    anomaly_id = anomaly.get("id", "?")
                    datetime_str = anomaly.get("datetime", "?")
                    peer_addr = anomaly.get("peer_addr", "desconhecido")
                    event_type = anomaly.get("event_type", "desconhecido")
                    score = anomaly.get("score", 0)
                    reviewed = "Revisada" if anomaly.get("reviewed", False) else "Não revisada"
                    
                    print(f"  [#{anomaly_id}] {datetime_str} - {peer_addr}")
                    print(f"     Tipo: {event_type}, Score: {score:.4f}")
                    print(f"     Status: {reviewed}")
                    
                    # Detalhes adicionais se houver
                    details = anomaly.get("details", {})
                    if details:
                        print(f"     Detalhes: {json.dumps(details, indent=6)}")
                    
                    print()  # Linha em branco entre anomalias
            
            print(f"{self.username}> ", end="", flush=True)
            
        elif message_type == "WELCOME":
            server_id = message_payload.get("server_id", "servidor")
            welcome_msg = message_payload.get("message", f"Bem-vindo ao {server_id}!")
            print(f"\r[Sistema] {welcome_msg}")
            print(f"{self.username}> ", end="", flush=True)
            
            # Ao receber boas-vindas, solicitar lista de peers
            self.communication.send_message(conn, "LIST_PEERS", {})
    
    def handle_peer_connected(self, conn, addr):
        """Callback quando um novo peer se conecta"""
        logger.info(f"Novo peer conectado: {addr}")
        self.current_peers.append(conn)
        print(f"\r[Sistema] Novo peer conectado: {addr}")
        print(f"{self.username}> ", end="", flush=True)
        
        # Enviar nome de usuário para o peer conectado
        self.communication.send_message(conn, "USERNAME", {"username": self.username})
    
    def handle_peer_disconnected(self, conn, addr):
        """Callback quando um peer desconecta"""
        if conn in self.current_peers:
            self.current_peers.remove(conn)
        
        username = self.peer_usernames.pop(conn, str(addr))
        logger.info(f"Peer desconectado: {username} ({addr})")
        print(f"\r[Sistema] Peer desconectado: {username} ({addr})")
        print(f"{self.username}> ", end="", flush=True)
    
    def handle_anomaly_detected(self, peer_addr, event_type, score, details):
        """Callback quando uma anomalia é detectada"""
        logger.warning(f"ANOMALIA DETECTADA de {peer_addr}! Tipo: {event_type}, Score: {score:.4f}")
        print(f"\r[ALERTA!] Possível atividade suspeita detectada de {peer_addr}!")
        print(f"Tipo: {event_type}, Score de anomalia: {score:.4f}")
        print(f"Detalhes: {json.dumps(details, indent=2) if details else 'Nenhum'}")
        print(f"{self.username}> ", end="", flush=True)
    
    def connect_to_peer(self, peer_host, peer_port):
        """Conectar a um peer remoto"""
        try:
            peer_port = int(peer_port)
            logger.info(f"Tentando conectar a {peer_host}:{peer_port}...")
            print(f"Conectando a {peer_host}:{peer_port}...")
            
            conn = self.communication.connect_to_peer(peer_host, peer_port)
            if conn:
                # Enviar nome de usuário para o peer
                self.communication.send_message(conn, "USERNAME", {"username": self.username})
                print(f"Conectado com sucesso a {peer_host}:{peer_port}")
                return True
            else:
                print(f"Falha ao conectar a {peer_host}:{peer_port}")
                return False
        except ValueError:
            print(f"Porta inválida: {peer_port}")
            return False
        except Exception as e:
            logger.error(f"Erro ao conectar: {e}")
            print(f"Erro ao conectar: {e}")
            return False
    
    def broadcast_message(self, message):
        """Envia uma mensagem para todos os peers conectados"""
        if not self.current_peers:
            print("Nenhum peer conectado para enviar mensagem.")
            return
        
        payload = {
            "content": message,
            "timestamp": time.time()
        }
        
        self.communication.broadcast_message("CHAT", payload)
        logger.info(f"Mensagem broadcast enviada para {len(self.current_peers)} peers")
    
    def send_direct_message(self, peer_index, message):
        """Envia uma mensagem para um peer específico"""
        if not self.current_peers:
            print("Nenhum peer conectado para enviar mensagem.")
            return False
        
        try:
            peer_index = int(peer_index)
            if peer_index < 0 or peer_index >= len(self.current_peers):
                print(f"Índice de peer inválido: {peer_index}")
                return False
            
            conn = self.current_peers[peer_index]
            username = self.peer_usernames.get(conn, "Desconhecido")
            
            payload = {
                "content": message,
                "timestamp": time.time()
            }
            
            self.communication.send_message(conn, "CHAT", payload)
            logger.info(f"Mensagem direta enviada para {username}")
            return True
        except ValueError:
            print(f"Índice de peer inválido: {peer_index}")
            return False
    
    def list_peers(self):
        """Lista todos os peers conectados"""
        if not self.current_peers:
            print("Nenhum peer conectado.")
            return
        
        print("\nPeers conectados:")
        for i, conn in enumerate(self.current_peers):
            addr = self.communication.peer_sessions.get(conn, {}).get("addr", "desconhecido")
            username = self.peer_usernames.get(conn, str(addr))
            print(f"  [{i}] {username} ({addr})")
    
    def start_cli(self):
        """Inicia a interface de linha de comando"""
        self.is_running = True
        print(f"Cliente seguro iniciado. Digite /ajuda para ver os comandos disponíveis.")
        print(f"Escutando em {self.host}:{self.port}")
        
        while self.is_running:
            try:
                command = input(f"{self.username}> ")
                self.process_command(command)
            except KeyboardInterrupt:
                print("\nSaindo...")
                self.stop()
                break
            except Exception as e:
                logger.error(f"Erro ao processar comando: {e}")
                print(f"Erro: {e}")
    
    def process_command(self, command):
        """Processa comandos inseridos pelo usuário"""
        if not command:
            return
        
        # Comandos com / no início
        if command.startswith('/'):
            cmd_parts = command.split(' ', 1)
            cmd = cmd_parts[0].lower()
            args = cmd_parts[1] if len(cmd_parts) > 1 else ""
            
            if cmd == '/ajuda':
                self.show_help()
            elif cmd == '/conectar':
                if not args or ':' not in args:
                    print("Uso: /conectar host:porta")
                    return
                host, port = args.split(':', 1)
                self.connect_to_peer(host, port)
            elif cmd == '/sair' or cmd == '/quit':
                print("Saindo...")
                self.stop()
                self.is_running = False
            elif cmd == '/peers':
                self.list_peers()
            elif cmd == '/listar':
                # Solicitar lista de peers ao servidor
                for conn in self.current_peers:
                    self.communication.send_message(conn, "LIST_PEERS", {})
                    print("Solicitando lista de peers conectados...")
            elif cmd == '/anomalias':
                # Solicitar lista de anomalias ao servidor
                limit = 10  # Padrão
                include_reviewed = False  # Padrão
                
                # Processar argumentos se houver
                if args:
                    params = args.split()
                    for param in params:
                        if param.isdigit():
                            limit = int(param)
                        elif param.lower() == "todas":
                            include_reviewed = True
                
                for conn in self.current_peers:
                    self.communication.send_message(conn, "LIST_ANOMALIES", {
                        "limit": limit,
                        "include_reviewed": include_reviewed
                    })
                    print(f"Solicitando lista de anomalias (limite: {limit}, incluir revisadas: {include_reviewed})...")
            elif cmd == '/dm':
                # Formato: /dm índice mensagem
                parts = args.split(' ', 1)
                if len(parts) < 2:
                    print("Uso: /dm índice_do_peer mensagem")
                    return
                peer_index, message = parts
                self.send_direct_message(peer_index, message)
            elif cmd == '/nome':
                if not args:
                    print(f"Seu nome de usuário atual é: {self.username}")
                else:
                    old_username = self.username
                    self.username = args
                    logger.info(f"Nome de usuário alterado de '{old_username}' para '{self.username}'")
                    print(f"Nome de usuário alterado para: {self.username}")
                    # Avisar os peers sobre a mudança
                    for conn in self.current_peers:
                        self.communication.send_message(conn, "USERNAME", {"username": self.username})
            else:
                print(f"Comando desconhecido: {cmd}. Digite /ajuda para ver os comandos disponíveis.")
        else:
            # Tratar como mensagem broadcast
            self.broadcast_message(command)
    
    def show_help(self):
        """Exibe a ajuda dos comandos disponíveis"""
        help_text = """
Comandos disponíveis:
  /ajuda              - Exibe esta ajuda
  /conectar host:porta - Conecta a um peer específico
  /peers              - Lista todos os peers conectados localmente
  /listar             - Solicita lista de peers conectados ao servidor
  /anomalias [N] [todas] - Solicita lista de anomalias (N: limite, 'todas': incluir revisadas)
  /dm índice mensagem - Envia uma mensagem direta para um peer específico
  /nome [novo_nome]   - Exibe ou altera seu nome de usuário
  /sair ou /quit      - Sai do cliente
  
Qualquer texto sem comando será enviado como mensagem para todos os peers conectados.
"""
        print(help_text)
    
    def stop(self):
        """Para o cliente e fecha todas as conexões"""
        logger.info("Parando cliente...")
        self.communication.stop_listening()
        logger.info("Cliente parado")

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Cliente de comunicação segura P2P')
    parser.add_argument('-p', '--port', type=int, default=12345, help='Porta para escutar (padrão: 12345)')
    parser.add_argument('-H', '--host', default='0.0.0.0', help='Host para escutar (padrão: 0.0.0.0)')
    parser.add_argument('-u', '--username', default=None, help='Nome de usuário para identificação')
    args = parser.parse_args()
    
    try:
        client = SecureCommClient(host=args.host, port=args.port, username=args.username)
        client.start_cli()
    except Exception as e:
        logger.critical(f"Erro fatal: {e}")
        print(f"Erro fatal: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 