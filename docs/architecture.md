# Arquitetura implementada

Estado de 26/09/2026. Aplicação experimental, sem auditoria criptográfica independente.

## Fronteira de confiança

O cliente gera e conserva suas chaves. O fingerprint SHA-256 vincula as chaves públicas Ed25519 e Curve25519. Para adicionar/substituir contato, o usuário precisa confirmar o fingerprint completo por um canal independente do relay.

~~~text
Cliente A: cofre + Olm       Relay independente         Cliente B: cofre + Olm
texto -> envelope cifrado -> públicos + ciphertext -> envelope -> texto
              |                                          |
              +---------- conexão direta opcional -------+
~~~

Relays não têm acesso aos cofres nem às contas/sessões privadas. TLS protege a conexão e suas operações; Olm protege o conteúdo inclusive contra o próprio relay. Remetente, destinatário, sessão e identificador são conferidos também no conteúdo autenticado.

## Módulos

| Módulo | Responsabilidade |
| --- | --- |
| core/identity.py | Cofre, identidade persistente, contatos verificados, revogação, lock e gravação atômica. |
| core/e2ee.py | Account/Session Olm, prekeys assinadas, texto/receipt, ratchet, outbox e deduplicação. |
| core/protocol.py | Formatos canônicos, limites, fingerprints e validação pública. |
| core/transport.py | Frames limitados, TLS, desafio de identidade e vínculo ao certificado. |
| server/relay.py | Identidades públicas, prekeys e mailbox SQLite opaca. |
| core/relay_client.py | Requests serializados e erros estáveis do relay. |
| client/app.py | Entrega direta/relays e orquestração sem plaintext no servidor. |
| client/cli.py | Senha sem eco, contatos, comandos e apresentação sanitizada. |

O protocolo de conversa vem de vodozemac 0.10.0. Não há ratchet caseiro nem uso de PkEncryption/PkDecryption. O pickle de Account/Session é o formato cifrado da biblioteca, não pickle executável de Python.

## Persistência e entrega

Antes do envio, o cliente grava atomicamente o estado avançado da sessão, o histórico e o envelope de retry no cofre. No recebimento, texto, deduplicação, sessão e receipt cifrada são gravados juntos.

“Enfileirada” significa aceitação pelo transporte; “entregue” exige receipt autenticada do destinatário. O retry reutiliza exatamente o envelope original. Reinícios preservam sessões, prekeys privadas e pendências.

Falha de persistência não gera ACK para a mensagem remota. Capacidade local esgotada preserva o item e permite processar outros envelopes/receipts. Mensagens inválidas ou de contatos não confiáveis são descartadas sem exibir conteúdo. Uma fila remota cheia ou contato ausente daquele relay não impede a sincronização dos demais.

Revogação elimina sessões e pendências do contato e impede novas operações. Cada nova submissão revalida o contato; operações já em voo, mensagens recebidas anteriormente e cópias de terceiros não podem ser recolhidas.

## Transporte e descentralização

Cada usuário escolhe rotas diretas e/ou relays independentes. Clientes podem usar mais de um relay; servidores não federam nem descobrem destinos entre si. Entrega offline exige que o destinatário tenha publicado prekeys naquele relay antes de ficar offline.

Fora de loopback, conexões exigem TLS 1.2 ou superior, CA confiável e hostname correto. O servidor carrega certificado e chave TLS próprios. A prova Ed25519 de identidade inclui o vínculo ao certificado do servidor, derivado independentemente em ambos os lados. Certificados idênticos representam a mesma autoridade TLS, não canais exclusivos.

A construção de hash do certificado segue RFC 5929, com SHA-256 para assinaturas MD5/SHA-1 e SHA-256/384/512 nos demais casos suportados. Certificados com algoritmo indefinido para esse vínculo, como EdDSA, são recusados. Não é tls-exporter nem alegação de conformidade integral ao RFC 9266.

TCP sem TLS é permitido somente em loopback para desenvolvimento. Não oferece proteção contra outro processo local com acesso à rede/usuário. Um terminador TLS externo que encaminhe TCP puro rompe o vínculo esperado; use TLS na própria aplicação ou pass-through.

## Limites operacionais e segurança

- Cofre: até 16 MiB; senha não vazia, Scrypt com aproximadamente 32 MiB de memória e AES-GCM. Senha forte continua necessária. Sem rotação de senha, recuperação, compactação automática ou restauração segura de backup nesta versão.
- Estado histórico e deduplicação crescem até o limite do cofre. Atingi-lo bloqueia novas gravações sem apagar mensagens remotas.
- Até 2.000 textos e 2.000 receipts pendentes, capacidades separadas; até 64 sessões por contato. Texto até 16 KiB UTF-8, também sujeito ao limite do envelope JSON.
- Orçamento global de até 50 prekeys privadas não consumidas por perfil. A publicação solicita até 20 por relay. Publicações abandonadas/claims sem primeiro inbound podem esgotar novas iniciações; a CLI avisa. Sessões existentes continuam. Não há recuperação automática de chaves abandonadas: descartá-las poderia quebrar mensagens offline.
- Relay padrão: 1.000 mensagens/8 MiB por destinatário, 10.000 mensagens/64 MiB no total, TTL de 7 dias. O remetente mantém textos sem receipt e pode reenviá-los após expiração.
- Relay tem quotas finitas de identidades/prekeys/tombstones e não recupera todos esses registros automaticamente. Não é um serviço ilimitado; operação prolongada exige gestão/migração futura.
- Limites de frames, requests, conexões e timeouts não constituem proteção completa contra DoS. A quota de conexões é aplicada após o handshake TLS.
- IPs, fingerprints, destinatários, horários, tamanhos e padrões de tráfego são metadados visíveis ao relay. Não há promessa de anonimato.
- Olm v1 deste binding possui MAC de 64 bits; não é pós-quântico. Auditorias históricas do núcleo não certificam o binding nem esta aplicação.
- Histórico local é deliberadamente retido. Comprometer um cofre desbloqueado revela seu histórico; não alegar apagamento retroativo ou proteção contra endpoint comprometido.
- Não restaure uma cópia antiga do cofre para continuar a mesma identidade: isso pode reverter o estado do ratchet. Um novo dispositivo deve ter nova identidade verificada.
- A aplicação local não protege contra atualizações maliciosas, administradores do dispositivo, captura de tela ou compartilhamento pelo destinatário.

## Material histórico

core.comm, core.crypto, core.auth, utils.logger, benchmarks e ML permanecem isolados para estudo. O antigo servidor terminava a criptografia e fazia broadcast; esses comportamentos foram retirados dos entrypoints padrão. Não execute as demonstrações antigas como se fossem a arquitetura atual.

## Referências

- [vodozemac](https://github.com/matrix-org/vodozemac)
- [Binding Python](https://github.com/matrix-nio/vodozemac-python)
- [RFC 5929](https://www.rfc-editor.org/rfc/rfc5929.html)
- [RFC 9266](https://www.rfc-editor.org/rfc/rfc9266.html)
