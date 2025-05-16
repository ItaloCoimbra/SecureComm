#!/usr/bin/env python3
# train_model.py - Script para treinar o modelo de detecção de anomalias

import os
import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, auc, precision_recall_curve, average_precision_score
from sklearn.model_selection import train_test_split

# Adicionar o diretório raiz ao path para importar módulos corretamente
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.anomaly import AnomalyDetector
from utils.logger import setup_logger

# Configurar logger
logger = setup_logger(name="ModelTrainer", log_level=20)  # INFO = 20

def plot_model_performance(y_true, scores, output_dir="data"):
    """
    Gera gráficos de desempenho do modelo (ROC, Precision-Recall).
    
    Args:
        y_true (array): Rótulos verdadeiros (0 para normal, 1 para anomalia)
        scores (array): Scores de anomalia (-1 * scores para converter de isolation forest)
        output_dir (str): Diretório para salvar os gráficos
    """
    try:
        os.makedirs(output_dir, exist_ok=True)
        
        # Para o IsolationForest, scores negativos indicam anomalias
        # Invertemos para que valores maiores sejam mais anômalos para fins de plotting
        scores_inverted = -1 * scores
        
        # Curva ROC
        fpr, tpr, _ = roc_curve(y_true, scores_inverted)
        roc_auc = auc(fpr, tpr)
        
        plt.figure(figsize=(10, 6))
        plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('Receiver Operating Characteristic (ROC) Curve')
        plt.legend(loc="lower right")
        plt.savefig(os.path.join(output_dir, 'roc_curve.png'))
        
        # Curva Precision-Recall
        precision, recall, _ = precision_recall_curve(y_true, scores_inverted)
        avg_precision = average_precision_score(y_true, scores_inverted)
        
        plt.figure(figsize=(10, 6))
        plt.plot(recall, precision, color='blue', lw=2, label=f'Precision-Recall curve (AP = {avg_precision:.2f})')
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.ylim([0.0, 1.05])
        plt.xlim([0.0, 1.0])
        plt.title('Precision-Recall Curve')
        plt.legend(loc="lower left")
        plt.savefig(os.path.join(output_dir, 'precision_recall_curve.png'))
        
        logger.info(f"Gráficos de desempenho salvos em {output_dir}")
        
    except Exception as e:
        logger.error(f"Erro ao gerar gráficos de desempenho: {e}")

def train_model_from_csv(csv_path="data/training_data.csv", contamination=0.05, test_size=0.2, plot_performance=True):
    """
    Carrega dados do CSV e treina o modelo de detecção de anomalias.
    
    Args:
        csv_path (str): Caminho para o arquivo CSV com os dados de treinamento
        contamination (float): Porcentagem de contaminação para o IsolationForest
        test_size (float): Proporção dos dados para teste (0-1)
        plot_performance (bool): Se deve gerar gráficos de desempenho
    
    Returns:
        bool: True se treinado com sucesso, False caso contrário
    """
    logger.info(f"Iniciando treinamento do modelo com dados de: {csv_path}")
    
    try:
        # Verificar se o arquivo existe
        if not os.path.exists(csv_path):
            logger.error(f"Arquivo {csv_path} não encontrado!")
            return False
        
        # Carregar dados
        df = pd.read_csv(csv_path)
        logger.info(f"Dados carregados: {df.shape[0]} amostras, colunas: {list(df.columns)}")
        
        # Verificar se há dados suficientes
        if len(df) < 10:
            logger.error(f"Poucos dados para treinamento: {len(df)} amostras")
            return False
            
        # Verificar se há a coluna 'is_anomaly'
        if "is_anomaly" not in df.columns:
            logger.warning("Coluna 'is_anomaly' não encontrada. Assumindo que todos os dados são normais.")
            y = np.zeros(len(df))
        else:
            y = df["is_anomaly"].values
            logger.info(f"Distribuição de dados: {len(df[df['is_anomaly']==0])} normais, {len(df[df['is_anomaly']==1])} anômalos")
            
        # Separar features (remover a coluna is_anomaly se existir)
        X = df.drop("is_anomaly", axis=1) if "is_anomaly" in df.columns else df
        
        # Dividir em conjuntos de treino e teste
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42)
        logger.info(f"Dados divididos: {len(X_train)} amostras para treino, {len(X_test)} para teste")
        
        # Criar e treinar o detector
        detector = AnomalyDetector(contamination=contamination)
        detector.train(X_train)
        
        # Avaliar o modelo com os dados de teste
        predictions = []
        scores = []
        
        for idx, row in X_test.iterrows():
            # Converter Series para dicionário
            sample = row.to_dict()
            pred = detector.predict(sample)
            score = detector.get_anomaly_score(sample)
            predictions.append(pred)
            scores.append(score)
        
        # Converter para arrays numpy
        predictions = np.array(predictions)
        scores = np.array(scores)
        
        # Calcular métricas básicas (adaptadas para detecção de anomalias)
        true_anomalies = (y_test == 1)
        predicted_anomalies = (predictions == -1)
        
        true_positives = np.sum(true_anomalies & predicted_anomalies)
        false_positives = np.sum((~true_anomalies) & predicted_anomalies)
        true_negatives = np.sum((~true_anomalies) & (~predicted_anomalies))
        false_negatives = np.sum(true_anomalies & (~predicted_anomalies))
        
        # Calcular métricas
        accuracy = (true_positives + true_negatives) / len(y_test)
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        logger.info(f"Desempenho do modelo:")
        logger.info(f"  Accuracy: {accuracy:.4f}")
        logger.info(f"  Precision: {precision:.4f}")
        logger.info(f"  Recall: {recall:.4f}")
        logger.info(f"  F1-Score: {f1_score:.4f}")
        
        # Gerar gráficos de desempenho
        if plot_performance:
            plot_model_performance(y_test, scores, os.path.dirname(csv_path))
        
        # Testar com exemplos avançados
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
        normal_score = detector.get_anomaly_score(normal_example)
        
        anomaly_pred = detector.predict(anomaly_example)
        anomaly_score = detector.get_anomaly_score(anomaly_example)
        
        logger.info(f"Teste com exemplo normal -> Predição: {normal_pred} (Score: {normal_score:.4f})")
        logger.info(f"Teste com exemplo anômalo -> Predição: {anomaly_pred} (Score: {anomaly_score:.4f})")
        
        logger.info("Modelo treinado e salvo com sucesso!")
        return True
    
    except Exception as e:
        logger.error(f"Erro durante o treinamento: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Treina o modelo de detecção de anomalias")
    parser.add_argument("--csv", default="data/training_data.csv", help="Caminho para o arquivo CSV de treinamento")
    parser.add_argument("--contamination", type=float, default=0.05, help="Valor de contaminação para o modelo (0-1)")
    parser.add_argument("--test-size", type=float, default=0.2, help="Proporção dos dados para teste")
    parser.add_argument("--no-plots", action="store_true", help="Não gerar gráficos de desempenho")
    
    args = parser.parse_args()
    
    success = train_model_from_csv(
        args.csv, 
        args.contamination, 
        args.test_size, 
        not args.no_plots
    )
    
    if success:
        print(f"Modelo treinado com sucesso usando dados de {args.csv}")
        sys.exit(0)
    else:
        print("Falha ao treinar o modelo. Verifique os logs para mais detalhes.")
        sys.exit(1) 