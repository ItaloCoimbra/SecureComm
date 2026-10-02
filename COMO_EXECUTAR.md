# Executar o SecureComm

Para o novo website, use o [guia web e Linux](docs/web-deployment.md).
Os comandos abaixo operam a **CLI histórica** e seu relay de identidades globais;
não são o backend do website com convites descartáveis.

Use inicialmente mensagens sintéticas. A integração é experimental, não auditada para dados sensíveis. Instale Python 3.10+ e execute na raiz do projeto:

~~~powershell
python -m venv .venv
./.venv/Scripts/python.exe -m pip install .
~~~

Os exemplos são PowerShell. No Linux/macOS use .venv/bin/securecomm-client e .venv/bin/securecomm-server. Opções globais do cliente vêm **antes** do subcomando.

## 1. Criar identidades e verificar contatos

~~~powershell
./.venv/Scripts/securecomm-client.exe --profile alice.vault init
./.venv/Scripts/securecomm-client.exe --profile bob.vault init
./.venv/Scripts/securecomm-client.exe --profile alice.vault identity --output alice-public.json
./.venv/Scripts/securecomm-client.exe --profile bob.vault identity --output bob-public.json
~~~

Cada operação pede a senha do cofre sem eco. Não há argumento de senha nem recuperação se ela for perdida. Arquivos públicos podem ser compartilhados; cofres e chaves TLS não.

Alice e Bob devem conferir seus fingerprints completos por outro canal confiável, por exemplo pessoalmente. Não basta copiar o fingerprint do mesmo arquivo recebido de uma origem não verificada. Substitua os marcadores abaixo pelos 64 caracteres hexadecimais realmente conferidos:

~~~powershell
./.venv/Scripts/securecomm-client.exe --profile alice.vault add-contact bob bob-public.json --fingerprint FINGERPRINT_COMPLETO_DO_BOB
./.venv/Scripts/securecomm-client.exe --profile bob.vault add-contact alice alice-public.json --fingerprint FINGERPRINT_COMPLETO_DA_ALICE
~~~

## 2. Conversa direta local, sem servidor

Em dois terminais:

~~~powershell
./.venv/Scripts/securecomm-client.exe --profile alice.vault --port 12346 chat
~~~

~~~powershell
./.venv/Scripts/securecomm-client.exe --profile bob.vault --port 12347 chat
~~~

No terminal de Alice:

~~~text
/conectar bob 127.0.0.1:12347
/usar bob
Olá de teste
~~~

Bob pode configurar a rota de resposta:

~~~text
/conectar alice 127.0.0.1:12346
/dm alice Resposta de teste
~~~

O envio direto exige ambos online e conectividade até o listener. Não há NAT traversal/discovery automático. Portas fixas acima são só para o teste local.

## 3. Relay local e entrega offline

Terminal do relay:

~~~powershell
./.venv/Scripts/securecomm-server.exe --database relay.sqlite --host 127.0.0.1 --port 12345
~~~

Terminais dos clientes:

~~~powershell
./.venv/Scripts/securecomm-client.exe --profile alice.vault chat --relay 127.0.0.1:12345
./.venv/Scripts/securecomm-client.exe --profile bob.vault chat --relay 127.0.0.1:12345
~~~

Alice usa /dm bob TEXTO. Antes de receber offline, Bob precisa conectar pelo menos uma vez para publicar prekeys. Depois pode sair; ao retornar, o cliente busca os envelopes e envia receipts cifradas. O relay pode ser reiniciado mantendo o mesmo banco.

“Enfileirada” não é confirmação de leitura/entrega. “Entregue” significa confirmação criptográfica de recebimento durável pelo dispositivo, não que uma pessoa leu.

Repita --relay para conectar vários relays. /relay HOST:PORT conecta/reconecta e seleciona a rota de envio; a sincronização consulta os conectados. Uma rota direta configurada para o alias tem prioridade. Não há fallback automático silencioso entre destinatários ou servidores.

## 4. Rede externa com TLS

Fora de loopback, TLS é obrigatório. Providencie certificado PEM com hostname/SAN correto, cadeia confiável e chave correspondente; não use o certificado público do exemplo como identidade do contato.

~~~powershell
./.venv/Scripts/securecomm-server.exe --database relay.sqlite --host 0.0.0.0 --port 12345 --tls-cert relay-cert.pem --tls-key relay-key.pem
./.venv/Scripts/securecomm-client.exe --profile alice.vault --tls-ca sua-ca.pem chat --relay relay.example.com:12345
~~~

Esses nomes/arquivos são marcadores, não serviços configurados. Para certificados de CA pública, o cliente usa as CAs do sistema e pode omitir --tls-ca. Não há opção de desabilitar a verificação TLS.

Para escuta direta externa, o próprio cliente também precisa de --tls-cert/--tls-key e --host apropriado. O cliente remetente deve confiar nessa CA e conectar pelo nome presente no certificado. A senha protege o cofre; a chave TLS deve ser protegida separadamente no sistema operacional. Consulte os algoritmos suportados em docs/architecture.md.

## Comandos do chat

| Comando | Efeito |
| --- | --- |
| /usar ALIAS | Seleciona o destinatário de texto sem comando. |
| /dm ALIAS TEXTO | Envia somente ao contato indicado. |
| /conectar ALIAS HOST:PORT | Configura rota direta do contato. |
| /relay HOST:PORT | Conecta/reconecta e seleciona um relay. |
| /sincronizar | Tenta reenviar pendências e receber mensagens. |
| /peers | Mostra contatos e fingerprints. |
| /historico | Exibe histórico local e estados. |
| /sair | Fecha conexões e cofre. |

Use aspas para aliases com espaços e [IPv6]:PORT para destinos IPv6. EOF/Ctrl+C também encerram. Não abra dois processos com o mesmo cofre.

Para administrar confiança, saia do chat primeiro:

~~~powershell
./.venv/Scripts/securecomm-client.exe --profile alice.vault contacts
./.venv/Scripts/securecomm-client.exe --profile alice.vault revoke bob --fingerprint FINGERPRINT_ANTIGO
./.venv/Scripts/securecomm-client.exe --profile alice.vault replace-contact bob novo-bob-public.json --old-fingerprint FINGERPRINT_ANTIGO --new-fingerprint FINGERPRINT_NOVO_VERIFICADO
~~~

Revogação não recolhe mensagens já transmitidas. Um novo dispositivo deve gerar nova identidade. Não copie/restaure cofres para operar simultaneamente ou recuperar um ratchet antigo.

## Erros e limites

- Cofre/armazenamento indisponível: preserve o arquivo e resolva espaço/permissões; não apague o perfil para “tentar de novo”.
- Relay desconectado: /relay HOST:PORT restabelece a conexão. Pendências já cifradas permanecem no cofre.
- Prekeys esgotadas: o perfil retém no máximo 50 privadas ainda não consumidas. Sessões existentes continuam, mas novas iniciações podem ficar indisponíveis. Não há recuperação automática de publicações abandonadas.
- Fila cheia: pendências não são descartadas; tente sincronizar quando o outro dispositivo/relay puder recebê-las.
- Senha errada/cofre inválido: abertura falha sem recriar identidade.

Histórico é exibido apenas sob comando local; redirecionar a saída pode criar um arquivo legível fora do cofre. O relay armazena ciphertext e metadados, não texto.

Para testes e experimentos opcionais de ML, consulte [desenvolvimento](docs/development.md). Não execute o chat legado como alternativa “compatível”.
