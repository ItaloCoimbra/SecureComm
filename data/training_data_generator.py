#!/usr/bin/env python3
# data/training_data_generator.py

import os
import sys
import pandas as pd
import numpy as np
import random
import time
from datetime import datetime, timedelta
import json
import argparse
import scipy.stats as stats  # Para cálculo de entropia

# Adicionar o diretório raiz ao path para importar módulos corretamente
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.anomaly import AnomalyDetector
from utils.logger import setup_logger

# Configurar logger
logger = setup_logger(name="DataGenerator", log_level=20)  # INFO = 20

class TrainingDataGenerator:
    """
    Gera dados para treinar o modelo de detecção de anomalias.
    Simula padrões de tráfego normais e anômalos com features avançadas.
    """
    
    def __init__(self, output_file="training_data.csv"):
        """
        Inicializa o gerador de dados.
        
        Args:
            output_file (str): Caminho para o arquivo de saída
        """
        self.output_file = output_file
        self.data = []
        
        # Diretório onde este script está para salvar dados
        self.data_dir = os.path.dirname(os.path.abspath(__file__))
        if not os.path.isabs(output_file):
            self.output_file = os.path.join(self.data_dir, output_file)
        
        logger.info(f"Gerador de dados inicializado. Arquivo de saída: {self.output_file}")
    
    def calculate_payload_entropy(self, payload_size):
        """
        Calcula uma entropia simulada para um payload de tamanho específico.
        Payloads normais tendem a ter entropia média (texto comum),
        payloads cifrados têm alta entropia, e payloads maliciosos podem ter
        entropia muito baixa (repetições) ou muito alta (dados cifrados).
        
        Args:
            payload_size (int): Tamanho do payload
        
        Returns:
            float: Valor de entropia entre 0 e 8 (bits por byte)
        """
        # Valores normais de entropia para texto comum: ~4-5 bits/byte
        # Valores para dados cifrados: ~7-8 bits/byte
        # Valores para dados comprimidos: ~6-7 bits/byte
        # Valores para repetições: ~0-3 bits/byte
        return random.uniform(3.8, 5.2)  # Entropia normal por padrão
    
    def generate_normal_traffic(self, num_samples=1000):
        """
        Gera padrões de tráfego normal com features avançadas.
        
        Args:
            num_samples (int): Número de amostras a serem geradas
        """
        logger.info(f"Gerando {num_samples} amostras de tráfego normal...")
        
        for _ in range(num_samples):
            # Tamanho de mensagem moderado (100-2000 bytes)
            message_length = random.randint(100, 2000)
            
            # Features avançadas para tráfego normal
            sample = {
                # Features básicas
                "message_length": message_length,
                "time_interval": random.uniform(0.5, 5.0),
                "message_count_window": random.randint(1, 20),
                
                # Features avançadas
                "payload_entropy": self.calculate_payload_entropy(message_length),
                "response_time": random.uniform(0.1, 0.8),  # Tempo de resposta normal (100-800ms)
                "decryption_errors": 0,  # Normalmente zero erros
                "signature_errors": 0,  # Normalmente zero erros
                "replay_flags": 0,  # Normalmente zero flags de replay
                "handshake_failures": 0,  # Normalmente zero falhas de handshake
                "message_type_variance": random.uniform(0.6, 1.0),  # Alta variância (muitos tipos diferentes)
                "session_duration": random.uniform(30, 1800),  # 30s a 30min é normal
                "sequential_errors": 0,  # Sequência de erros (0 é normal)
                
                # Rótulo
                "is_anomaly": 0  # 0 = normal
            }
            
            self.data.append(sample)
        
        logger.info(f"Geradas {num_samples} amostras de tráfego normal")
    
    def generate_dos_attack(self, num_samples=100):
        """
        Gera padrões de ataque de negação de serviço (DoS) com features avançadas.
        
        Args:
            num_samples (int): Número de amostras a serem geradas
        """
        logger.info(f"Gerando {num_samples} amostras de ataque DoS...")
        
        for _ in range(num_samples):
            # Tamanho de mensagem pode variar no DoS
            message_length = random.randint(50, 3000)
            
            sample = {
                # Features básicas - característico de DoS
                "message_length": message_length,
                "time_interval": random.uniform(0.001, 0.2),  # Intervalo muito curto
                "message_count_window": random.randint(50, 200),  # Muitas mensagens
                
                # Features avançadas
                "payload_entropy": self.calculate_payload_entropy(message_length),
                "response_time": random.uniform(1.5, 10.0),  # Tempo de resposta lento devido à sobrecarga
                "decryption_errors": random.randint(0, 3),  # Pode haver alguns erros
                "signature_errors": random.randint(0, 2),  # Pode haver alguns erros
                "replay_flags": 0,  # DoS geralmente não usa replay
                "handshake_failures": random.randint(0, 5),  # Pode haver falhas devido à carga
                "message_type_variance": random.uniform(0.0, 0.3),  # Baixa variância (repetição de tipos)
                "session_duration": random.uniform(10, 300),  # Sessões mais curtas
                "sequential_errors": random.randint(0, 3),  # Alguns erros sequenciais
                
                # Rótulo
                "is_anomaly": 1  # 1 = anomalia
            }
            
            self.data.append(sample)
        
        logger.info(f"Geradas {num_samples} amostras de ataque DoS")
    
    def generate_data_exfiltration(self, num_samples=50):
        """
        Gera padrões de exfiltração de dados com features avançadas.
        
        Args:
            num_samples (int): Número de amostras a serem geradas
        """
        logger.info(f"Gerando {num_samples} amostras de exfiltração de dados...")
        
        for _ in range(num_samples):
            # Tamanho de mensagem muito grande para exfiltração
            message_length = random.randint(5000, 50000)
            
            sample = {
                # Features básicas - característico de exfiltração
                "message_length": message_length,
                "time_interval": random.uniform(1, 10),
                "message_count_window": random.randint(5, 15),
                
                # Features avançadas
                "payload_entropy": random.uniform(6.8, 8.0),  # Alta entropia (dados cifrados/comprimidos)
                "response_time": random.uniform(0.3, 1.2),  # Resposta normal a ligeiramente mais lenta
                "decryption_errors": 0,  # Normalmente sem erros
                "signature_errors": 0,  # Normalmente sem erros
                "replay_flags": 0,  # Sem replay
                "handshake_failures": 0,  # Sem falhas de handshake
                "message_type_variance": random.uniform(0.0, 0.4),  # Baixa variância (poucos tipos de mensagem)
                "session_duration": random.uniform(60, 600),  # Sessões médias
                "sequential_errors": 0,  # Sem erros sequenciais
                
                # Rótulo
                "is_anomaly": 1  # 1 = anomalia
            }
            
            self.data.append(sample)
        
        logger.info(f"Geradas {num_samples} amostras de exfiltração de dados")
    
    def generate_replay_attack(self, num_samples=75):
        """
        Gera padrões de ataque de replay com features avançadas.
        
        Args:
            num_samples (int): Número de amostras a serem geradas
        """
        logger.info(f"Gerando {num_samples} amostras de ataque de replay...")
        
        # Criar blocos de mensagens similares para simular replay
        num_message_blocks = max(1, int(num_samples / 15))
        
        for block in range(num_message_blocks):
            # Base para este bloco de mensagens repetidas
            base_length = random.randint(100, 1000)
            base_interval = random.uniform(0.2, 1.0)
            base_entropy = self.calculate_payload_entropy(base_length)
            
            # Quantas mensagens similares neste bloco
            block_size = random.randint(5, 15)
            
            for _ in range(block_size):
                sample = {
                    # Features básicas - característico de replay
                    "message_length": base_length + random.randint(-10, 10),  # Pouca variação
                    "time_interval": base_interval + random.uniform(-0.05, 0.05),  # Pouca variação
                    "message_count_window": random.randint(15, 40),  # Moderado a alto
                    
                    # Features avançadas
                    "payload_entropy": base_entropy + random.uniform(-0.1, 0.1),  # Pouca variação
                    "response_time": random.uniform(0.2, 0.6),  # Normal
                    "decryption_errors": 0,  # Sem erros de decriptografia
                    "signature_errors": 0,  # Sem erros de assinatura
                    "replay_flags": random.randint(0, 1),  # Possível detecção de replay
                    "handshake_failures": 0,  # Sem falhas de handshake
                    "message_type_variance": random.uniform(0.0, 0.2),  # Muito baixa variância (repetição)
                    "session_duration": random.uniform(30, 300),  # Sessões médias
                    "sequential_errors": 0,  # Sem erros sequenciais
                    
                    # Rótulo
                    "is_anomaly": 1  # 1 = anomalia
                }
                
                self.data.append(sample)
        
        logger.info(f"Geradas {len(self.data) - (len(self.data) - num_samples)} amostras de ataque de replay")
    
    def generate_mitm_attack(self, num_samples=75):
        """
        Gera padrões de ataque Man-in-the-Middle com features avançadas.
        
        Args:
            num_samples (int): Número de amostras a serem geradas
        """
        logger.info(f"Gerando {num_samples} amostras de ataque MITM...")
        
        for _ in range(num_samples):
            # Tamanho de mensagem para MITM
            message_length = random.randint(150, 2500)  # Ligeiramente maior
            
            sample = {
                # Features básicas - característico de MITM
                "message_length": message_length,
                "time_interval": random.uniform(0.8, 6.0),  # Ligeiramente maior
                "message_count_window": random.randint(1, 25),  # Normal
                
                # Features avançadas
                "payload_entropy": self.calculate_payload_entropy(message_length) + random.uniform(0.2, 0.8),  # Entropia alterada
                "response_time": random.uniform(0.5, 1.5),  # Ligeiramente mais lento
                "decryption_errors": random.randint(0, 2),  # Possíveis erros
                "signature_errors": random.randint(0, 3),  # Possíveis erros de assinatura
                "replay_flags": 0,  # Sem replay
                "handshake_failures": random.randint(0, 2),  # Possíveis falhas de handshake
                "message_type_variance": random.uniform(0.3, 0.7),  # Média variância
                "session_duration": random.uniform(20, 400),  # Duração variada
                "sequential_errors": random.randint(0, 2),  # Possíveis erros sequenciais
                
                # Rótulo
                "is_anomaly": 1  # 1 = anomalia
            }
            
            self.data.append(sample)
        
        logger.info(f"Geradas {num_samples} amostras de ataque MITM")
        
    def generate_invalid_signature_attack(self, num_samples=50):
        """
        Gera padrões de ataques com assinaturas inválidas.
        
        Args:
            num_samples (int): Número de amostras a serem geradas
        """
        logger.info(f"Gerando {num_samples} amostras de ataques com assinaturas inválidas...")
        
        for _ in range(num_samples):
            # Tamanho de mensagem normal
            message_length = random.randint(100, 2000)
            
            sample = {
                # Features básicas - aparentemente normal
                "message_length": message_length,
                "time_interval": random.uniform(0.5, 5.0),  # Normal
                "message_count_window": random.randint(1, 20),  # Normal
                
                # Features avançadas
                "payload_entropy": self.calculate_payload_entropy(message_length),  # Normal
                "response_time": random.uniform(0.1, 0.8),  # Normal
                "decryption_errors": 0,  # Sem erros de decriptografia
                "signature_errors": random.randint(2, 5),  # Muitos erros de assinatura
                "replay_flags": 0,  # Sem replay
                "handshake_failures": 0,  # Sem falhas de handshake
                "message_type_variance": random.uniform(0.4, 1.0),  # Normal
                "session_duration": random.uniform(30, 1800),  # Normal
                "sequential_errors": random.randint(1, 3),  # Alguns erros sequenciais
                
                # Rótulo
                "is_anomaly": 1  # 1 = anomalia
            }
            
            self.data.append(sample)
        
        logger.info(f"Geradas {num_samples} amostras de ataques com assinaturas inválidas")
    
    def save_data(self):
        """
        Salva os dados gerados em um arquivo CSV.
        """
        if not self.data:
            logger.warning("Nenhum dado para salvar!")
            return False
        
        # Converter para DataFrame
        df = pd.DataFrame(self.data)
        
        # Embaralhar os dados
        df = df.sample(frac=1).reset_index(drop=True)
        
        try:
            # Criar diretório se não existir
            os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
            
            # Salvar no formato CSV
            df.to_csv(self.output_file, index=False)
            logger.info(f"Dados salvos com sucesso em {self.output_file}")
            
            # Resumo dos dados
            normal = df[df['is_anomaly'] == 0].shape[0]
            anomaly = df[df['is_anomaly'] == 1].shape[0]
            total = df.shape[0]
            logger.info(f"Resumo: {total} amostras totais, {normal} normais ({normal/total*100:.1f}%), {anomaly} anômalas ({anomaly/total*100:.1f}%)")
            
            return True
        except Exception as e:
            logger.error(f"Erro ao salvar dados: {e}")
            return False
    
    def load_and_train_model(self):
        """
        Carrega os dados gerados e treina um modelo de detecção de anomalias.
        """
        if not os.path.exists(self.output_file):
            logger.error(f"Arquivo de dados {self.output_file} não encontrado!")
            return False
        
        try:
            # Carregar dados
            df = pd.read_csv(self.output_file)
            logger.info(f"Dados carregados de {self.output_file}: {df.shape[0]} amostras")
            
            # Separar features e target
            X = df.drop('is_anomaly', axis=1)
            
            # Treinar detector de anomalias
            detector = AnomalyDetector(contamination=0.05)  # Assume ~5% de anomalias
            detector.train(X)
            logger.info("Modelo treinado e salvo com sucesso!")
            
            # Verificar anomalias (teste rápido)
            # Exemplo normal:
            normal_example = {
                "message_length": 500, 
                "time_interval": 2.0, 
                "message_count_window": 10,
                "payload_entropy": 4.5,
                "response_time": 0.3,
                "decryption_errors": 0,
                "signature_errors": 0,
                "replay_flags": 0,
                "handshake_failures": 0,
                "message_type_variance": 0.8,
                "session_duration": 300,
                "sequential_errors": 0
            }
            
            # Exemplo anômalo:
            anomaly_example = {
                "message_length": 20000, 
                "time_interval": 0.05, 
                "message_count_window": 150,
                "payload_entropy": 7.9,
                "response_time": 2.5,
                "decryption_errors": 2,
                "signature_errors": 3,
                "replay_flags": 1,
                "handshake_failures": 2,
                "message_type_variance": 0.1,
                "session_duration": 15,
                "sequential_errors": 2
            }
            
            normal_pred = detector.predict(normal_example)
            anomaly_pred = detector.predict(anomaly_example)
            
            logger.info(f"Teste com exemplo normal -> Predição: {normal_pred}")
            logger.info(f"Teste com exemplo anômalo -> Predição: {anomaly_pred}")
            
            return True
        except Exception as e:
            logger.error(f"Erro ao treinar modelo: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description='Gerador de dados para treinamento do detector de anomalias')
    parser.add_argument('-o', '--output', default='training_data.csv', 
                        help='Arquivo de saída para os dados de treinamento')
    parser.add_argument('-n', '--normal', type=int, default=2000, 
                        help='Número de amostras de tráfego normal a gerar')
    parser.add_argument('-d', '--dos', type=int, default=200, 
                        help='Número de amostras de ataque DoS a gerar')
    parser.add_argument('-e', '--exfil', type=int, default=100, 
                        help='Número de amostras de exfiltração de dados a gerar')
    parser.add_argument('-r', '--replay', type=int, default=150, 
                        help='Número de amostras de ataque de replay a gerar')
    parser.add_argument('-m', '--mitm', type=int, default=150, 
                        help='Número de amostras de ataque MITM a gerar')
    parser.add_argument('-s', '--signature', type=int, default=100, 
                        help='Número de amostras de ataques com assinaturas inválidas a gerar')
    parser.add_argument('-t', '--train', action='store_true', 
                        help='Treinar modelo após gerar dados')
    
    args = parser.parse_args()
    
    # Inicializar gerador
    generator = TrainingDataGenerator(output_file=args.output)
    
    # Gerar dados
    generator.generate_normal_traffic(num_samples=args.normal)
    generator.generate_dos_attack(num_samples=args.dos)
    generator.generate_data_exfiltration(num_samples=args.exfil)
    generator.generate_replay_attack(num_samples=args.replay)
    generator.generate_mitm_attack(num_samples=args.mitm)
    generator.generate_invalid_signature_attack(num_samples=args.signature)
    
    # Salvar dados
    if generator.save_data():
        print(f"Dados de treinamento gerados e salvos em {args.output}")
        
        # Treinar modelo se solicitado
        if args.train:
            if generator.load_and_train_model():
                print("Modelo treinado e salvo com sucesso!")
            else:
                print("Falha ao treinar modelo.")
    else:
        print("Falha ao salvar dados.")


if __name__ == "__main__":
    main() 