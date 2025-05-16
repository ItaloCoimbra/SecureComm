#!/usr/bin/env python3
# benchmark/performance_test.py

import os
import sys
import time
import threading
import argparse
import json
import statistics
from datetime import datetime

# Adicionar o diretório raiz ao path para importar módulos corretamente
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.crypto import CryptoManager
from core.auth import AuthManager
from core.comm import P2PCommunication
from utils.logger import setup_logger

# Configurar logger
logger = setup_logger(name="Benchmark", log_level=20)  # INFO = 20

class BenchmarkClient:
    """
    Cliente para testes de benchmark do sistema de comunicação segura.
    """
    
    def __init__(self, host='127.0.0.1', port=12345, client_id=None):
        self.host = host
        self.port = port
        self.client_id = client_id or f"benchmark_{time.time()}"
        self.auth_manager = AuthManager()
        self.communication = None
        self.connected = False
        self.message_counter = 0
        
        # Métricas
        self.metrics = {
            "connection_time": None,
            "message_latencies": [],
            "message_sizes": [],
            "messages_sent": 0,
            "messages_received": 0,
            "errors": 0,
            "test_start_time": None,
            "test_end_time": None
        }
        
        # Event para sincronização
        self.received_message_event = threading.Event()
        self.last_received_msg = None
        
        logger.info(f"Cliente de benchmark {self.client_id} inicializado")
    
    def handle_message(self, conn, addr, message_type, message_payload):
        """Callback para processar mensagens recebidas"""
        if message_type == "BENCHMARK_ECHO":
            # Calcular latência
            sent_timestamp = message_payload.get("timestamp", 0)
            current_time = time.time()
            latency = (current_time - sent_timestamp) * 1000  # ms
            
            self.metrics["message_latencies"].append(latency)
            self.metrics["messages_received"] += 1
            
            logger.debug(f"Recebida resposta de echo: {message_payload.get('content', '')[:30]}... " +
                       f"Latência: {latency:.2f}ms")
            
            self.last_received_msg = {
                "type": message_type,
                "payload": message_payload,
                "latency": latency
            }
            self.received_message_event.set()
    
    def handle_peer_connected(self, conn, addr):
        """Callback quando um peer se conecta"""
        logger.info(f"Conectado ao servidor: {addr}")
        self.connected = True
    
    def handle_peer_disconnected(self, conn, addr):
        """Callback quando um peer desconecta"""
        logger.info(f"Desconectado do servidor: {addr}")
        self.connected = False
    
    def connect(self):
        """Conectar ao servidor para benchmark"""
        logger.info(f"Conectando ao servidor {self.host}:{self.port}...")
        
        # Medir tempo de conexão
        start_time = time.time()
        
        self.communication = P2PCommunication(
            host='0.0.0.0',  # Bind to any interface for outgoing connection
            port=0,          # Use any available port
            local_auth_manager=self.auth_manager,
            on_message_received_callback=self.handle_message,
            on_peer_connected_callback=self.handle_peer_connected,
            on_peer_disconnected_callback=self.handle_peer_disconnected
        )
        
        # Conectar ao servidor
        conn = self.communication.connect_to_peer(self.host, self.port)
        
        if conn:
            connection_time = time.time() - start_time
            self.metrics["connection_time"] = connection_time * 1000  # ms
            logger.info(f"Conectado em {connection_time*1000:.2f}ms")
            return True
        else:
            logger.error(f"Falha ao conectar ao servidor {self.host}:{self.port}")
            return False
    
    def disconnect(self):
        """Desconectar do servidor"""
        if self.communication:
            self.communication.stop_listening()
            logger.info("Desconectado do servidor")
    
    def send_echo_message(self, size, wait_for_response=True, timeout=30):
        """
        Envia uma mensagem de echo de tamanho específico e, opcionalmente,
        espera pela resposta.
        
        Args:
            size (int): Tamanho aproximado da mensagem em bytes
            wait_for_response (bool): Se deve esperar pela resposta
            timeout (float): Timeout em segundos para esperar resposta
            
        Returns:
            dict: Informações sobre a mensagem enviada e a resposta, ou None se falhar
        """
        if not self.connected or not self.communication:
            logger.error("Não conectado ao servidor")
            return None
        
        # Resetar evento de recebimento
        self.received_message_event.clear()
        
        # Gerar conteúdo do tamanho desejado
        content = "X" * max(1, size - 100)  # Descontar overhead aproximado de JSON
        
        # Preparar payload
        payload = {
            "content": content,
            "timestamp": time.time(),
            "message_id": self.message_counter,
            "client_id": self.client_id
        }
        
        # Medir tamanho exato da mensagem serializada
        serialized = json.dumps(payload)
        actual_size = len(serialized.encode('utf-8'))
        self.metrics["message_sizes"].append(actual_size)
        
        # Enviar mensagem
        send_time = time.time()
        
        # Encontrar o primeiro conn ativo na lista de conexões
        if self.communication.active_connections:
            conn = self.communication.active_connections[0]
            self.communication.send_message(conn, "BENCHMARK_ECHO", payload)
            self.metrics["messages_sent"] += 1
            self.message_counter += 1
            
            result = {
                "sent_time": send_time,
                "message_id": payload["message_id"],
                "size_bytes": actual_size
            }
            
            # Esperar pela resposta
            if wait_for_response:
                if self.received_message_event.wait(timeout):
                    result["response"] = self.last_received_msg
                    result["round_trip_ms"] = self.last_received_msg["latency"]
                    return result
                else:
                    logger.warning(f"Timeout esperando resposta para mensagem {payload['message_id']}")
                    self.metrics["errors"] += 1
                    return None
            
            return result
        else:
            logger.error("Sem conexões ativas")
            self.metrics["errors"] += 1
            return None
    
    def run_echo_test(self, num_messages=100, message_size=1024, interval=0.1):
        """
        Executa um teste de echo enviando múltiplas mensagens.
        
        Args:
            num_messages (int): Número de mensagens a enviar
            message_size (int): Tamanho de cada mensagem em bytes
            interval (float): Intervalo entre mensagens em segundos
            
        Returns:
            dict: Métricas do teste
        """
        if not self.connect():
            return {"error": "Falha ao conectar"}
        
        logger.info(f"Iniciando teste de echo com {num_messages} mensagens de {message_size} bytes cada")
        
        self.metrics["test_start_time"] = time.time()
        results = []
        
        for i in range(num_messages):
            result = self.send_echo_message(message_size)
            if result:
                results.append(result)
            time.sleep(interval)
        
        self.metrics["test_end_time"] = time.time()
        
        # Calcular métricas
        test_duration = self.metrics["test_end_time"] - self.metrics["test_start_time"]
        
        if self.metrics["message_latencies"]:
            avg_latency = statistics.mean(self.metrics["message_latencies"])
            min_latency = min(self.metrics["message_latencies"])
            max_latency = max(self.metrics["message_latencies"])
            p95_latency = sorted(self.metrics["message_latencies"])[int(len(self.metrics["message_latencies"]) * 0.95)]
            p99_latency = sorted(self.metrics["message_latencies"])[int(len(self.metrics["message_latencies"]) * 0.99)]
        else:
            avg_latency = min_latency = max_latency = p95_latency = p99_latency = 0
        
        self.metrics["summary"] = {
            "total_messages": num_messages,
            "successful_messages": len(results),
            "error_rate": (num_messages - len(results)) / num_messages if num_messages > 0 else 0,
            "avg_latency_ms": avg_latency,
            "min_latency_ms": min_latency,
            "max_latency_ms": max_latency,
            "p95_latency_ms": p95_latency,
            "p99_latency_ms": p99_latency,
            "connection_time_ms": self.metrics["connection_time"],
            "test_duration_seconds": test_duration,
            "throughput_msgs_per_sec": len(results) / test_duration if test_duration > 0 else 0
        }
        
        logger.info(f"Teste concluído. Métricas: " + 
                  f"Latência média: {avg_latency:.2f}ms, " +
                  f"Taxa de erro: {self.metrics['summary']['error_rate']*100:.2f}%, " +
                  f"Throughput: {self.metrics['summary']['throughput_msgs_per_sec']:.2f} msgs/sec")
        
        self.disconnect()
        return self.metrics


def run_benchmark_suite(host, port, output_file=None):
    """
    Executa uma suíte completa de testes de benchmark.
    
    Args:
        host (str): Host do servidor para teste
        port (int): Porta do servidor
        output_file (str): Arquivo para salvar resultados (opcional)
    
    Returns:
        dict: Resultados completos do benchmark
    """
    results = {
        "timestamp": time.time(),
        "datetime": datetime.now().isoformat(),
        "server": f"{host}:{port}",
        "tests": {}
    }
    
    # Teste 1: Tempo de conexão e handshake (5 repetições)
    connection_times = []
    for i in range(5):
        client = BenchmarkClient(host=host, port=port, client_id=f"conn_test_{i}")
        if client.connect():
            connection_times.append(client.metrics["connection_time"])
        client.disconnect()
        time.sleep(1)  # Pequena pausa entre testes
    
    if connection_times:
        results["tests"]["connection"] = {
            "avg_time_ms": statistics.mean(connection_times),
            "min_time_ms": min(connection_times),
            "max_time_ms": max(connection_times),
            "std_dev_ms": statistics.stdev(connection_times) if len(connection_times) > 1 else 0,
            "samples": connection_times
        }
    
    # Teste 2: Latência com mensagens pequenas (100 bytes, 100 mensagens)
    small_client = BenchmarkClient(host=host, port=port, client_id="small_msg_test")
    small_results = small_client.run_echo_test(num_messages=100, message_size=100, interval=0.05)
    results["tests"]["small_messages"] = small_results
    
    # Teste 3: Latência com mensagens médias (1KB, 50 mensagens)
    medium_client = BenchmarkClient(host=host, port=port, client_id="medium_msg_test")
    medium_results = medium_client.run_echo_test(num_messages=50, message_size=1024, interval=0.1)
    results["tests"]["medium_messages"] = medium_results
    
    # Teste 4: Latência com mensagens grandes (50KB, 20 mensagens)
    large_client = BenchmarkClient(host=host, port=port, client_id="large_msg_test")
    large_results = large_client.run_echo_test(num_messages=20, message_size=50*1024, interval=0.2)
    results["tests"]["large_messages"] = large_results
    
    # Teste 5: Throughput (muitas mensagens pequenas rapidamente)
    throughput_client = BenchmarkClient(host=host, port=port, client_id="throughput_test")
    throughput_results = throughput_client.run_echo_test(num_messages=200, message_size=100, interval=0.01)
    results["tests"]["throughput"] = throughput_results
    
    # Salvar resultados
    if output_file:
        try:
            output_dir = os.path.dirname(output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Resultados do benchmark salvos em {output_file}")
        except Exception as e:
            logger.error(f"Erro ao salvar resultados: {e}")
    
    # Resumo
    summary = {
        "avg_connection_time_ms": results["tests"]["connection"]["avg_time_ms"] if "connection" in results["tests"] else 0,
        "small_msg_latency_ms": small_results["summary"]["avg_latency_ms"] if "summary" in small_results else 0,
        "medium_msg_latency_ms": medium_results["summary"]["avg_latency_ms"] if "summary" in medium_results else 0,
        "large_msg_latency_ms": large_results["summary"]["avg_latency_ms"] if "summary" in large_results else 0,
        "max_throughput_msgs_per_sec": throughput_results["summary"]["throughput_msgs_per_sec"] if "summary" in throughput_results else 0
    }
    
    results["summary"] = summary
    
    print("\n" + "="*50)
    print("RESULTADOS DO BENCHMARK")
    print("="*50)
    print(f"Servidor: {host}:{port}")
    print(f"Data/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\nResumo:")
    print(f"- Tempo médio de conexão: {summary['avg_connection_time_ms']:.2f}ms")
    print(f"- Latência média (mensagens pequenas): {summary['small_msg_latency_ms']:.2f}ms")
    print(f"- Latência média (mensagens médias): {summary['medium_msg_latency_ms']:.2f}ms")
    print(f"- Latência média (mensagens grandes): {summary['large_msg_latency_ms']:.2f}ms")
    print(f"- Throughput máximo: {summary['max_throughput_msgs_per_sec']:.2f} msgs/seg")
    print("="*50 + "\n")
    
    return results


def main():
    parser = argparse.ArgumentParser(description='Benchmark para o sistema de comunicação segura')
    parser.add_argument('-H', '--host', default='127.0.0.1', help='Host do servidor para teste')
    parser.add_argument('-p', '--port', type=int, default=12345, help='Porta do servidor')
    parser.add_argument('-o', '--output', help='Arquivo para salvar os resultados em formato JSON')
    parser.add_argument('-s', '--single', choices=['connection', 'small', 'medium', 'large', 'throughput'],
                       help='Executar apenas um teste específico')
    parser.add_argument('-c', '--count', type=int, default=100, help='Número de mensagens para testes individuais')
    args = parser.parse_args()
    
    # Determinar nome do arquivo de saída padrão, se não fornecido
    if not args.output:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        args.output = f"benchmark/results/benchmark_{timestamp}.json"
    
    # Executar teste específico ou suíte completa
    if args.single:
        client = BenchmarkClient(host=args.host, port=args.port)
        
        if args.single == 'connection':
            connection_times = []
            for i in range(5):
                if client.connect():
                    connection_times.append(client.metrics["connection_time"])
                client.disconnect()
                time.sleep(1)
            
            if connection_times:
                avg_time = statistics.mean(connection_times)
                print(f"Tempo médio de conexão: {avg_time:.2f}ms")
        
        elif args.single == 'small':
            results = client.run_echo_test(num_messages=args.count, message_size=100, interval=0.05)
            if "summary" in results:
                print(f"Latência média (mensagens pequenas): {results['summary']['avg_latency_ms']:.2f}ms")
        
        elif args.single == 'medium':
            results = client.run_echo_test(num_messages=args.count, message_size=1024, interval=0.1)
            if "summary" in results:
                print(f"Latência média (mensagens médias): {results['summary']['avg_latency_ms']:.2f}ms")
        
        elif args.single == 'large':
            results = client.run_echo_test(num_messages=args.count, message_size=50*1024, interval=0.2)
            if "summary" in results:
                print(f"Latência média (mensagens grandes): {results['summary']['avg_latency_ms']:.2f}ms")
        
        elif args.single == 'throughput':
            results = client.run_echo_test(num_messages=args.count, message_size=100, interval=0.01)
            if "summary" in results:
                print(f"Throughput: {results['summary']['throughput_msgs_per_sec']:.2f} msgs/seg")
    
    else:
        # Executar suíte completa
        run_benchmark_suite(args.host, args.port, args.output)


if __name__ == "__main__":
    # Criar diretório de resultados se não existir
    os.makedirs(os.path.join(os.path.dirname(__file__), "results"), exist_ok=True)
    
    main() 