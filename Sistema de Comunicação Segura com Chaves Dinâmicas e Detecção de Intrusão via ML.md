# Sistema de Comunicação Segura com Chaves Dinâmicas e Detecção de Intrusão via ML

> Documento histórico do projeto de 2025. Consulte `README.md`,
> `docs/architecture.md` e `todo.md` para o estado atual. As expectativas abaixo
> não são garantias de segurança validadas.

## 🎯 Objetivo Geral

Desenvolver um sistema de comunicação peer-to-peer criptografado em tempo real, que:

*   Gere chaves dinâmicas para cada sessão com troca baseada em ECDH (Elliptic Curve Diffie-Hellman).
*   Use Python para implementar tanto o protocolo de comunicação quanto a criptografia.
*   Tenha uma camada de detecção de intrusão/anomalias com Machine Learning, identificando padrões suspeitos como man-in-the-middle ou replay attack.

## 🧠 Tecnologias e Conceitos Envolvidos

*   **Python:** `sockets` para comunicação, `cryptography` para operações criptográficas, `scikit-learn` e `pandas` para Machine Learning.
*   **Criptografia:**
    *   Troca de Chaves: Elliptic Curve Diffie-Hellman (ECDH) com curva SECP384R1.
    *   Criptografia de Sessão: AES-GCM com chaves de 256 bits derivadas via HKDF (SHA256) a partir do segredo ECDH.
    *   Forward Secrecy: Chaves ECDH efêmeras geradas para cada sessão.
    *   Integridade e Autenticidade de Mensagens: Assinaturas digitais usando ECDSA com curva SECP384R1 e hash SHA256.
*   **Comunicação:** Protocolo P2P sobre TCP/IP, com mensagens serializadas em JSON.
*   **Detecção de Anomalias:** Modelo `IsolationForest` do Scikit-learn para detectar padrões anômalos no tráfego de comunicação. As features iniciais incluem tamanho da mensagem, intervalo entre mensagens e contagem de mensagens em uma janela de tempo.
*   **Logging:** Logging de eventos importantes com rotação de arquivos, utilizando o módulo `logging` do Python.

## 📂 Estrutura do Projeto

```
/securecomm/
├── core/                     # Módulos centrais da aplicação
│   ├── crypto.py             # Implementação de ECDH + AES-GCM
│   ├── auth.py               # Implementação de Assinatura Digital (ECDSA)
│   ├── comm.py               # Lógica de comunicação socket P2P segura
│   └── anomaly.py            # Modelo ML para detecção de anomalias e suas funções
├── server/                   # Lógica específica do servidor (se necessário, atualmente integrado no comm.py e client.py)
│   ├── server.py             # (Previsto, mas funcionalidade pode estar no client.py/comm.py para P2P puro)
│   └── session_manager.py    # (Previsto, gerenciamento de sessão integrado no comm.py)
├── client/                   # Lógica específica do cliente
│   └── client.py             # Implementação do cliente CLI (A SER DESENVOLVIDO)
├── data/                     # Dados para treinamento e modelos de ML
│   ├── training_data.csv     # (Previsto para dados de treinamento gerados)
│   └── anomaly_detector_model.joblib # Modelo de detecção de anomalias treinado
│   └── anomaly_scaler.joblib   # Scaler para os dados do modelo
├── utils/                    # Utilitários
│   └── logger.py             # Módulo de logging
├── logs/                     # Diretório para arquivos de log
│   └── secure_comm.log       # Arquivo de log principal
├── venv/                     # Ambiente virtual Python
└── README.md                 # Este arquivo
```

## ⚙️ Configuração e Instalação

1.  **Clone o repositório (se aplicável) ou crie a estrutura de diretórios manualmente.**

2.  **Crie e ative um ambiente virtual Python:**
    ```bash
    cd securecomm
    python3.11 -m venv venv
    source venv/bin/activate
    ```

3.  **Instale as dependências:**
    ```bash
    pip install cryptography scikit-learn pandas joblib
    ```

## 🚀 Como Executar

Atualmente, os módulos `core/crypto.py`, `core/auth.py`, `core/comm.py` e `core/anomaly.py` contêm seções `if __name__ == '__main__':` com exemplos de uso e testes básicos. Para executar esses testes individuais:

```bash
python -m core.crypto
python -m core.auth
python -m core.comm # Este tentará uma comunicação P2P básica com detecção de anomalia
python -m core.anomaly # Este testará o treinamento/carregamento do modelo de anomalia
python -m utils.logger # Este testará o logger
```

Uma aplicação cliente-servidor completa (`client/client.py` e `server/server.py` ou um peer executável unificado) ainda precisa ser desenvolvida para demonstrar o sistema de forma interativa.

### Executando o Teste de Comunicação (`core/comm.py`)

O `core/comm.py` quando executado diretamente (`python -m core.comm`) tentará:
1.  Iniciar um "Peer 1" (servidor) na `localhost:12345`.
2.  Iniciar um "Peer 2" (cliente) que se conectará ao Peer 1.
3.  Realizar um handshake criptográfico.
4.  Trocar algumas mensagens de teste.
5.  Utilizar o `AnomalyDetector` (carregando um modelo de `data/anomaly_detector_model.joblib` ou treinando um dummy se não existir) para verificar as mensagens.

Certifique-se de que o diretório `data/` existe dentro de `securecomm/` para que o modelo de anomalia possa ser salvo/carregado.

## 🧠 Treinamento do Modelo de Machine Learning (Detecção de Anomalias)

O módulo `core/anomaly.py` implementa a classe `AnomalyDetector` que usa `IsolationForest`.

1.  **Geração de Dados:**
    *   Atualmente, `core/anomaly.py` inclui uma geração de *dados dummy* para fins de teste dentro de seu bloco `if __name__ == '__main__':`. 
    *   Para um treinamento real, seria necessário um script separado (e.g., `data/training_data_generator.py`) para simular tráfego normal e de ataque, extraindo features como:
        *   `message_length`: Tamanho da mensagem.
        *   `time_interval`: Tempo desde a última mensagem do mesmo peer.
        *   `message_count_window`: Número de mensagens do peer em uma janela de tempo (e.g., últimos 60s).
        *   Outras features relevantes (e.g., tipo de mensagem, falhas de decriptografia/assinatura).
    *   Este script geraria um `training_data.csv` no diretório `data/`.

2.  **Treinamento do Modelo:**
    *   Após gerar `training_data.csv`, o modelo pode ser treinado executando uma função de treinamento que utilize `AnomalyDetector.train(dataframe)`.
    *   O `AnomalyDetector` salvará o modelo treinado como `data/anomaly_detector_model.joblib` e o scaler como `data/anomaly_scaler.joblib`.
    *   O `core/comm.py` tentará carregar este modelo salvo. Se não encontrar, o `AnomalyDetector` dentro de `comm.py` (no seu `__main__` de teste) treinará um modelo dummy para permitir a execução dos testes de comunicação.

## 📝 Resultados Esperados (Conforme TCC)

*   **Alta segurança:** Mesmo se a chave de uma sessão for descoberta, o conteúdo de sessões passadas não é comprometido (Forward Secrecy).
*   **Capacidade de detectar e alertar sobre padrões estranhos de uso** (ex: tentativas de MITM, tráfego anômalo) através do módulo de Machine Learning.
*   **Aplicação com potencial** para ser usada em ambientes corporativos ou mensageiros descentralizados.

## 🛣️ Próximos Passos (Desenvolvimento)

*   Desenvolvimento completo do `client/client.py` com interface CLI.
*   Desenvolvimento de um `server/server.py` robusto ou um script de peer executável unificado.
*   Criação de um script dedicado para geração de dados de treinamento (`data/training_data_generator.py`).
*   Implementação de um mecanismo de alerta mais explícito no cliente para anomalias detectadas.
*   Testes de integração completos e benchmarking de desempenho.
*   Refinamentos e otimizações.
*   (Opcional) Implementação de logging criptografado (atualmente usa logging padrão para arquivo).
*   (Opcional) Interface WebSocket e troca de chave pública com QR code.

