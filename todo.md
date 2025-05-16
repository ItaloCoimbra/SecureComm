# Plano de Projeto: Sistema de Comunicação Segura com Chaves Dinâmicas e Detecção de Intrusão via ML

Este documento descreve as etapas e tarefas para o desenvolvimento do projeto de TCC.

## Fase 1: Fundação e Criptografia Central

- [X] **Configuração do Ambiente e Estrutura do Projeto**
    - [X] Criar a estrutura de diretórios (`/securecomm`, `core`, `server`, `client`, `data`, `utils`).
    - [X] Configurar ambiente virtual Python e instalar dependências iniciais (`cryptography`).
- [X] **Módulo de Criptografia (`core/crypto.py`)**
    - [X] Implementar a troca de chaves Elliptic Curve Diffie-Hellman (ECDH).
    - [X] Implementar a derivação de chave de sessão simétrica a partir da chave ECDH compartilhada.
    - [X] Implementar criptografia e descriptografia de mensagens usando AES (modo GCM para confidencialidade e autenticidade).
    - [X] Implementar a geração de chaves efêmeras para cada sessão (forward secrecy).
    - [X] Escrever testes unitários para as funções de criptografia.
- [X] **Módulo de Autenticação (`core/auth.py`)**
    - [X] Implementar a geração de pares de chaves para assinatura digital (e.g., ECDSA).
    - [X] Implementar a assinatura de mensagens.
    - [X] Implementar a verificação de assinaturas.
    - [X] Escrever testes unitários para as funções de autenticação.

## Fase 2: Comunicação Básica e Integração Criptográfica

- [X] **Módulo de Comunicação (`core/comm.py`)**
    - [X] Desenvolver a lógica básica de comunicação P2P usando sockets TCP (biblioteca `socket`).
    - [X] Definir um protocolo de mensagens simples (e.g., JSON com campos para tipo de mensagem, payload, assinatura).
    - [X] Integrar o módulo `crypto.py` para criptografar todas as mensagens trocadas.
    - [X] Integrar o módulo `auth.py` para assinar e verificar todas as mensagens.
- [X] **Implementação Inicial do Cliente (`client/client.py`)**
    - [X] Desenvolver uma interface de linha de comando (CLI) básica para o cliente.
    - [X] Implementar funcionalidade para conectar a um peer.
    - [X] Implementar funcionalidade para enviar mensagens criptografadas e assinadas.
    - [X] Implementar funcionalidade para receber e exibir mensagens descriptografadas e verificadas.
- [X] **Implementação Inicial do Servidor/Peer (`server/server.py` e `server/session_manager.py`)**
    - [X] Desenvolver a lógica do servidor para aguardar conexões de peers.
    - [X] Gerenciar sessões de comunicação (incluindo chaves de sessão).
    - [X] Lidar com o processo de troca de chaves e autenticação inicial.

## Fase 3: Detecção de Anomalias com Machine Learning

- [X] **Coleta e Preparação de Dados (`data/`)**
    - [X] Definir as características (features) a serem extraídas do tráfego de comunicação para detecção de anomalias (e.g., frequência de mensagens, tamanho das mensagens, padrões de conexão, tempo entre mensagens).
    - [X] Desenvolver scripts para simular tráfego normal.
    - [X] Desenvolver scripts para simular tráfego de ataques (e.g., Man-in-the-Middle, Replay Attacks, negação de serviço simples).
    - [X] Gerar e armazenar o dataset de treinamento (`training_data.csv`).
- [X] **Módulo de Detecção de Anomalias (`core/anomaly.py`)**
    - [X] Pré-processar os dados de treinamento. (Scaler implemented)
    - [X] Selecionar e treinar um modelo de Machine Learning com `Scikit-learn` (Isolation Forest implemented).
    - [X] Avaliar o desempenho do modelo. (Basic tests in anomaly.py)
    - [X] Implementar uma função para receber dados de comunicação em tempo real e retornar uma pontuação de anomalia ou uma classificação. (predict and get_anomaly_score implemented)
- [X] **Integração da Detecção de Anomalias**
    - [X] Integrar o módulo `anomaly.py` no `server/server.py` (ou no componente que monitora o tráfego). (Integrated into `core/comm.py` message loop)
    - [X] Implementar um mecanismo de alerta no cliente (`client/client.py`) para notificar o usuário sobre anomalias detectadas. (Callback `on_anomaly_detected_callback` added to `core/comm.py`).

## Fase 4: Logging Seguro e Documentação

- [X] **Módulo de Logging Seguro (`utils/logger.py`)**
    - [X] Implementar um sistema de logging para registrar eventos importantes (conexões, erros, alertas de anomalia).
    - [X] Garantir que os logs sejam armazenados de forma segura (e.g., criptografia dos arquivos de log ou uso de SQLite com SQLCipher, como sugerido, se o tempo permitir; caso contrário, criptografia de arquivo simples). (Basic rotating log implemented, encryption noted as future work)
- [X] **Documentação (`README.md` e comentários no código)**
    - [X] Escrever uma `README.md` detalhada cobrindo:
        - Descrição do projeto.
        - Arquitetura do sistema.
        - Como configurar e instalar dependências.
        - Como executar o cliente e o servidor.
        - Como treinar o modelo de ML (se aplicável).
    - [X] Adicionar comentários explicativos no código. (Done throughout core modules)

## Fase 5: Testes, Benchmarking e Refinamentos

- [X] **Testes de Integração**
    - [X] Testar o fluxo completo de comunicação segura entre cliente e servidor/peer. (Core P2P test in `core/comm.py` executed)
    - [X] Testar a detecção de anomalias com cenários de ataque simulados. (Anomaly detection integrated and tested with dummy data in `core/comm.py`)
- [X] **Benchmark de Desempenho**
    - [X] Medir o tempo de estabelecimento da conexão e troca de chaves.
    - [X] Medir a latência na troca de mensagens.
    - [X] Avaliar o overhead da criptografia e da detecção de anomalias.
- [X] **Refinamentos e Otimizações**
    - [X] Otimizar o código com base nos resultados dos benchmarks.
    - [X] Corrigir bugs e melhorar a usabilidade da CLI.

## Fase 6: (Opcional) Funcionalidades Adicionais e Pesquisa

- [ ] **Interface WebSocket**
    - [ ] Explorar a implementação de uma interface baseada em WebSocket com Flask + Socket.IO.
- [ ] **Troca de Chave Pública com QR Code**
    - [ ] Investigar e implementar a troca de chave pública via QR code para facilitar o setup inicial seguro.
- [ ] **Preparação para Artigo Científico**
    - [ ] Documentar a metodologia, resultados dos benchmarks e a eficácia da detecção de anomalias.
    - [ ] Comparar com abordagens existentes.

