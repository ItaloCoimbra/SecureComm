# Como Executar o Sistema de Comunicação Segura

Este guia mostra como configurar e executar o servidor e os clientes do sistema de comunicação segura.

## Requisitos

- Python 3.8 ou superior
- Dependências do projeto instaladas (ver `requirements.txt`)

## Preparação do Ambiente

1. Ative o ambiente virtual (se estiver usando):

    ```bash
    # No Windows
    venv\Scripts\activate

    # No Linux/Mac
    source venv/bin/activate
    ```

2. Antes de usar o sistema pela primeira vez, gere dados de treinamento para o modelo de detecção de anomalias:

    ```bash
    python -m data.training_data_generator
    ```

3. Treine o modelo com os dados gerados:

    ```bash
    python train_model.py
    ```

## Executando o Servidor

O servidor atua como um hub central para coordenar as comunicações entre os clientes.

```bash
# Iniciar o servidor na porta padrão 12345
python -m server.server

# Iniciar o servidor em uma porta específica
python -m server.server -p 12345

# Iniciar o servidor com um nome personalizado
python -m server.server -n "MeuServidor"

# Iniciar o servidor em um host específico (interface de rede)
python -m server.server -H 127.0.0.1
```

Após iniciar o servidor, você verá mensagens indicando que ele está escutando por conexões, mostrando estatísticas a cada minuto.

## Executando os Clientes

Você pode executar vários clientes, cada um em uma janela de terminal diferente, para simular a comunicação entre múltiplos usuários.

```bash
# Iniciar um cliente na porta padrão (aleatória)
python -m client.client

# Iniciar um cliente em uma porta específica
python -m client.client -p 12346

# Iniciar um cliente com um nome de usuário personalizado
python -m client.client -u "Usuario1"

# Iniciar um cliente em um host específico
python -m client.client -H 127.0.0.1
```

## Conectando Clientes ao Servidor

Após iniciar o servidor e os clientes, conecte os clientes ao servidor usando o comando `/conectar`:

```
/conectar 127.0.0.1:12345
```

Substitua `127.0.0.1:12345` pelo endereço IP e porta do servidor, se necessário.

## Comandos do Cliente

Depois de conectado, você pode usar vários comandos na interface CLI do cliente:

- `/ajuda` - Mostra a lista de comandos disponíveis
- `/peers` - Lista os peers conectados localmente
- `/listar` - Solicita lista de peers conectados ao servidor
- `/anomalias [N] [todas]` - Solicita lista de anomalias detectadas
- `/dm índice mensagem` - Envia uma mensagem direta para um peer específico
- `/nome [novo_nome]` - Exibe ou altera seu nome de usuário
- `/sair` ou `/quit` - Sai do cliente

## Exemplos de Uso

### Exemplo 1: Configuração Básica (1 Servidor + 2 Clientes)

Terminal 1 (Servidor):
```bash
python -m server.server
```

Terminal 2 (Cliente 1):
```bash
python -m client.client -p 12346 -u "Usuario1"
```
Depois conecte ao servidor:
```
/conectar 127.0.0.1:12345
```

Terminal 3 (Cliente 2):
```bash
python -m client.client -p 12347 -u "Usuario2"
```
Depois conecte ao servidor:
```
/conectar 127.0.0.1:12345
```

### Exemplo 2: Testando a Detecção de Anomalias

1. Conecte os clientes ao servidor como mostrado acima
2. De um cliente, envie mensagens anômalas para testar a detecção:
   - Mensagem muito grande (exfiltração de dados): envie uma mensagem com muitos caracteres repetidos
   - Sequência de mensagens rápidas (ataque DoS): envie muitas mensagens em sequência rápida
   - Padrão de mensagem incomum: envie algo como `CMD:exec:powershell -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAGMAYQBsAGMALgBlAHgAZQA=`

3. Verifique as anomalias detectadas:
```
/anomalias
```

## Resolução de Problemas

1. **Erro "Endereço em uso"**: Certifique-se de que a porta escolhida não está sendo usada por outro processo.
   ```bash
   python -m server.server -p 12346  # Tente uma porta diferente
   ```

2. **Erro "Não foi possível se conectar"**: Verifique se o servidor está rodando e se o endereço está correto.
   - Use `127.0.0.1` em vez de `0.0.0.0` ao se conectar
   - Verifique se está usando a porta correta

3. **"Modelo de detecção de anomalias não encontrado"**: Execute o treinamento do modelo:
   ```bash
   python -m data.training_data_generator
   python train_model.py
   ```

4. **Problemas no Windows com readline**: Instale a biblioteca pyreadline3:
   ```bash
   pip install pyreadline3
   ``` 