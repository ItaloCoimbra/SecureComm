# Roadmap do SecureComm

Implementação de 26/09/2026. Os checklists históricos do TCC não certificam segurança.

## Concluído nesta implementação

- [x] CodeGraph local e instruções persistentes de uso proativo do JEV.
- [x] Empacotamento, ambiente isolado, testes e configuração de CI.
- [x] Escolha registrada: CLI Python, Olm, identidade por dispositivo e relays independentes.
- [x] Cofre cifrado, lock, contatos verificados, revogação/substituição explícita.
- [x] Conversa E2EE com destinatário explícito, ratchet, outbox, receipts e deduplicação.
- [x] Relay opaco persistente para offline, sem chaves privadas ou logs de conteúdo.
- [x] Conexão direta sem relay; operação com múltiplos relays independentes.
- [x] TLS verificado externo com vínculo de autenticação ao certificado.
- [x] CLI nova, encerramento seguro e sanitização de terminal.
- [x] Falhas locais preservam mailbox; quotas não bloqueiam contatos independentes.
- [x] ML opcional e artefatos históricos isolados.
- [x] Documentação de operação, pressupostos e limites.

## Evoluções de produto e operação — não implementadas

- [ ] Auditoria especializada da integração, protocolo e distribuição dos clientes.
- [ ] Homologação das plataformas/CI remota e instalação limpa em toda a matriz.
- [ ] Distribuição assinada, atualização segura e lock completo da cadeia de dependências.
- [ ] Ciclo de vida de prekeys abandonadas, rotação/recuperação de identidade e senha.
- [ ] Política de retenção/compactação do cofre e recuperação sem rollback de ratchet.
- [ ] Gestão de quotas/identidades/tombstones do relay para operação prolongada.
- [ ] Descoberta/NAT traversal e federação automática, se necessários ao produto.
- [ ] Grupos, anexos, dispositivos associados à mesma conta e clientes móveis.
- [ ] Privacidade adicional de metadados, antiabuso e avaliação de capacidade.
- [ ] Avaliação de protocolo/binding moderno, inclusive limitações de Olm v1 e pós-quântico.

Nenhum deploy/publicação foi feito. Os itens futuros não são garantias implícitas da versão atual.
