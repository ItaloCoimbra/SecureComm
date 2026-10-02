# Contrato da implementação E2EE

Decisão de 26/09/2026 para executar o pedido de comunicação descentralizada com
servidor incapaz de decifrar. Este contrato substitui as decisões abertas da
primeira análise; não representa certificação de segurança em produção.

## Escolhas

- Preservar CLI Python, agora Python >=3.10.
- Usar Olm Account/Session do `vodozemac==0.10.0`, sem escrever um ratchet próprio.
  O wheel CPython 3.11 Windows foi instalado e o fluxo inicial/resposta/pickle/
  assinatura foi verificado com dados sintéticos antes desta decisão.
- Contatos são identidades persistentes de dispositivo, verificadas por fingerprint
  completo fora do relay. Não há diretório central de confiança.
- Transporte direto e relays independentes. Relays guardam prekeys públicos
  assinados e envelopes cifrados para entrega offline; não têm contas Olm privadas.
- Cofre local único cifrado por senha guarda conta, contatos, sessões, histórico,
  deduplicação e outbox. Lock por processo e gravação atômica protegem o estado.
- Conversas de texto entre dispositivos verificados. Uma pessoa pode usar vários
  perfis/dispositivos como contatos distintos; associação automática de conta,
  grupos com membros/consenso e clientes móveis não são funcionalidades presumidas.
- Nenhum fallback para o chat antigo que termina a criptografia no servidor.
- Não usar `PkEncryption`, `PkDecryption` ou pickle Python/joblib no fluxo novo.

Olm deste binding usa a versão 1 (MAC de 64 bits), não é pós-quântico. Auditorias
históricas do núcleo não certificam esta integração. Senhas fracas, clientes
comprometidos, cópias antigas do cofre e destinatários que copiam conteúdo ficam
fora da garantia contra o relay. Metadados e disponibilidade são propriedades
separadas; relays podem observar endereços/horários e impedir entrega.

## Contratos compartilhados

`core/protocol.py` define formatos e validação pública, sem chave privada:

- PROTOCOL = `securecomm-olm-v1`, versão de objetos `v=1`.
- Identidade: `{v, id, ed25519, curve25519}`. id = SHA256 de domínio + chaves
  públicas cruas; chaves em base64 canônico sem padding. Fingerprint = id completo.
- Prekey: `{id, key, signature}`; assinatura Ed25519 cobre bytes canônicos de
  `{protocol, owner, key_id, key}` com owner = fingerprint da identidade.
- Bundle: `{identity, prekeys:[...]}`. Claim: `{identity, prekey}`.
- Envelope: `{v, sender, recipient, message_id, session_id, message_type, ciphertext}`.
  message_id é 32 hex; session_id é identificador Olm; type é 0/1; ciphertext é
  base64. A validação do conteúdo autenticado no cliente confere todos os IDs.
- Plaintext cifrado: `{v, sender, recipient, message_id, kind, timestamp, ...}`;
  kind=text inclui text; kind=receipt inclui acknowledged_id.
- Autenticação de transporte: hello com identity; challenge com nonce 32 bytes
  hex; assinatura de `auth_bytes(nonce, identity_id, channel_binding)`. O vínculo
  TLS deriva do certificado verificado/configurado localmente em cada lado;
  TCP puro tem marcador separado e fica restrito a loopback. O relay guarda só
  identidades públicas e sua própria chave TLS, nunca chaves privadas de conversa.

`core/identity.py`: `IdentityVault.create(path,password)` / `.open(path,password)`;
`.public_identity()`, `.sign(bytes)->str`, `.snapshot()->dict`, `.commit(dict)`;
`.add_contact(alias,identity,verified_fingerprint)`, `.get_contact(alias)`;
`.require_contact_id(id)`, `.list_contacts()`, `.revoke_contact(alias,expected_id)`;
`.replace_contact(alias,identity,expected_old,verified_new)`, `.close()`.
Métodos de contato retornam `{alias, identity, revoked}`. Cofre snapshot tem
`account` (pickle vodozemac), `pickle_key` (base64 de chave aleatória 32B),
`contacts` (dict por alias), `sessions` (dict), `outbox` (dict), `history` (list),
`seen` (dict), `prekey_count` (int). Account.sign pode ser reconstruída via pickle.
commit escreve completamente antes de substituir o snapshot em memória.

`core/e2ee.py`: `Messenger(vault)`, `.issue_prekeys(count=20)->bundle`,
`.needs_prekey(alias)->bool`, `.prepare_message(alias,text,claim=None)->envelope`,
`.receive(envelope)->dict|None`, `.pending_envelopes()->list`,
`.mark_submitted(message_id)`, `.history()->list`.
Receive de texto persiste a mensagem e uma receipt cifrada na outbox atomicamente;
receipts confirmam entrega e removem a mensagem original da outbox. Submissão ao
relay não equivale a entrega. Retries usam o mesmo envelope persistido.

`core/transport.py`: read_packet/write_packet com prefixo 4B, JSON limitado,
timeout e fechamento; authenticate_client e authenticate_server usam a identidade
e um signer callback, sem depender do cofre. Exceções públicas sem conteúdo.
TLS verificado é obrigatório fora de loopback. O servidor usa
`make_server_tls_context(certfile,keyfile)`; clientes verificam CA e hostname.
O vínculo segue o hash de certificado do RFC 5929, não um canal exclusivo nem
tls-exporter. Veja limitações de certificados e operação em architecture.md.

`server/relay.py`: `RelayServer(db_path,host='127.0.0.1',port=0)` com start/close
assíncronos e `.address`; SQLite guarda públicos e envelopes apenas. Operações
autenticadas publish(bundle), claim(recipient), send(envelope), fetch(limit),
ack(ids), status(). Prekeys consumidas não são republicadas; fila persiste até
ack do destinatário ou TTL. Limites de conexões, filas, tamanho e tempo.
Falha local de persistência/capacidade não autoriza ACK; mensagens remotas são
retidas para retry. Texto e receipt têm capacidades separadas. Sincronização
direta envia lotes limitados, reservando orçamento para fetch/ack/receipts.

`core/relay_client.py`: `RelayConnection.connect(host,port,identity,signer)`;
publish(bundle), claim(recipient), send(envelope), fetch(limit=50), ack(ids),
status(), close(). Resultado claim tem identity e prekey; fetch retorna list de
envelopes; outros retornam objeto de resposta com ok. Requests serializados.

## Critérios de conclusão funcional

1. Entry points padrão usam o fluxo novo; servidor não importa núcleo privado,
   ML ou logger legado e não recebe plaintext de conversa.
2. Cofre/contatos sobrevivem reinício e recusam substituição silenciosa.
3. Mensagem direta tem destinatário explícito e não chega a terceiros.
4. Dois clientes trocam texto e receipts com ratchet através do relay.
5. Envio a destinatário offline persiste cifrado; reinícios preservam entrega.
6. Mesmo fluxo E2EE funciona diretamente, sem relay nem autoridade central.
7. Estado e retries são persistidos antes de efeitos externos; duplicatas não
   reapresentam mensagens nem fazem o ratchet retroceder.
8. Revogação impede novos envios/recebimentos e elimina sessões correspondentes.
9. Banco/logs do relay contêm somente públicos/ciphertext/metadados; validação
   de integração usa dados sintéticos, sem exploração de sistemas externos.
10. Instalação, CLI, shutdown e limites têm testes e documentação atualizada.

## Referências

- https://github.com/matrix-org/vodozemac
- https://github.com/matrix-nio/vodozemac-python
- https://pypi.org/project/vodozemac/0.10.0/
- https://matrix.org/docs/matrix-concepts/end-to-end-encryption/

JEV comparou Olm com mailboxes, Noise com túneis e Matrix completo; apoiou Olm.
O parecer é auxiliar e não substitui os testes e revisão desta implementação.
