# SecureComm

## Chat web privado — em implementação

A direção atual é um website com vínculos independentes por contato, convites
descartáveis e estado criptográfico somente no navegador, **sem recuperação,
backup ou sincronização oferecidos pelo serviço**. O servidor web usa filas e
capacidades aleatórias; não usa as identidades globais do relay CLI histórico.

O escopo e os limites estão no [contrato web](docs/web-private-contract.md).
O [guia web/Linux](docs/web-deployment.md) descreve build, execução e operação.
O [registro de validação](docs/web-progress.md) separa trabalho realizado de
critérios ainda pendentes. Não há deploy nem certificação de anonimato.

## CLI histórica (protocolo separado)

CLI experimental de mensagens ponta a ponta entre identidades de dispositivo verificadas. O fluxo padrão foi substituído: o relay recebe envelopes cifrados, não o texto nem as chaves privadas das conversas.

Funciona diretamente entre clientes ou com relays independentes para entrega offline. Não há diretório central de identidades nem broadcast de mensagens privadas. Isso **não** é uma rede de federação automática, uma implementação de Signal/Matrix completa ou um produto auditado para uso sensível.

## Começar

Python 3.10+; validação local em Windows/Python 3.11.9.

~~~powershell
python -m venv .venv
./.venv/Scripts/python.exe -m pip install .
./.venv/Scripts/securecomm-client.exe --profile alice.vault init
~~~

No Linux/macOS, use os executáveis correspondentes de .venv/bin. A senha é pedida sem eco no terminal, nunca por argumento.

Siga o [guia completo de execução](COMO_EXECUTAR.md) para verificar contatos e abrir uma conversa.

## Implementado

- Identidade Ed25519/Curve25519 persistente; fingerprint completo confirmado por outro canal.
- Sessões Olm com vodozemac 0.10.0, evolução de chaves, envelopes autenticados e confirmações cifradas.
- Cofre local AES-GCM/Scrypt: conta, contatos, sessões, histórico, deduplicação e fila de saída.
- Gravação atômica, lock de perfil, reenvio do mesmo ciphertext e recuperação após reinício.
- Relay SQLite opaco com fila offline, expiração, quotas e operações autenticadas.
- TLS verificado obrigatório fora de loopback, com autenticação vinculada ao certificado do endpoint.
- Contato/destinatário explícito, revogação e substituição de identidade com confirmação.

ML e os experimentos antigos não são importados pela CLI/relay. Seus pacotes são opcionais; arquivos joblib históricos não entram na distribuição.

## Limites importantes

Criptografia não significa “segurança absoluta”. Um relay isoladamente não recebe material para abrir as conversas, mas pode observar metadados, atrasar ou impedir entregas. Cliente comprometido, senha fraca, destinatário que copia mensagens e restauração de cofres antigos não estão cobertos.

Olm deste binding usa MAC de 64 bits e não é pós-quântico. O histórico permanece acessível a quem desbloqueia o cofre. A integração precisa de auditoria especializada antes de dados sensíveis.

Há limites finitos de cofre, sessões e prekeys, descritos em [arquitetura](docs/architecture.md). Grupos, descoberta automática, federação entre servidores, recuperação de conta e sincronização de vários dispositivos não foram implementados.

## Documentação e desenvolvimento

- [Executar e verificar contatos](COMO_EXECUTAR.md)
- [Arquitetura, garantias condicionais e limites](docs/architecture.md)
- [Contrato da implementação](docs/implementation-contract.md)
- [Testes e desenvolvimento](docs/development.md)
- [Roadmap](todo.md)

~~~powershell
./.venv/Scripts/python.exe -m pip install -r requirements-dev.txt
./.venv/Scripts/python.exe -m pytest tests -q
~~~

CodeGraph está indexado localmente. [AGENTS.md](AGENTS.md) orienta CodeGraph antes da exploração e JEV nas decisões/revisões úteis. JEV é consultivo, não uma certificação nem autorização automática. Nenhum hook envia código indiscriminadamente.

O documento do TCC e os módulos core.comm, core.crypto, core.auth e utils.logger são históricos; não descrevem o fluxo atual.
