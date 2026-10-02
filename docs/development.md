# Desenvolvimento e validação

Validação de 26/09/2026, Windows / CPython 3.11.9. Use sempre uma .venv própria, nunca o Python global de outra ferramenta.

~~~powershell
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -r requirements-dev.txt
./.venv/Scripts/python.exe -m pytest tests -q -W error
./.venv/Scripts/python.exe -m pip check
git diff --check
~~~

## Evidência desta implementação

- Suíte completa: 140 testes passaram; 1 teste de permissões POSIX ignorado no Windows.
- pip check sem incompatibilidades; git diff --check sem erros de whitespace.
- Build local de sdist e wheel concluído com python -m build --no-isolation.
- Testes de packaging constroem sdist/wheel em árvore temporária e instalam a wheel fora do checkout; verificam origem de client/core/server e ausência de imports ML nos entrypoints.
- Sentinelas inertes comprovam exclusão de modelos, chaves, certificados privados, cofres e bancos de dados da distribuição.
- Hashes dos modelos históricos permaneceram iguais; nenhum joblib histórico foi carregado.
- CodeGraph sincronizado. Sem commit, push, deploy ou publicação.

O teste de instalação usa uma venv nova com diretórios das dependências de teste disponibilizados, sem executar hooks editáveis. A origem do código da aplicação é verificada dentro da wheel instalada. Não equivale a uma instalação limpa que resolve todas as dependências da Internet.

## Cobertura funcional

| Área | Evidências automatizadas |
| --- | --- |
| Identidade/cofre | Senha incorreta, autenticação AEAD, reinício, lock entre processos, DACL Windows, commit atômico e não sobrescrita. |
| Confiança | Fingerprint de ambas as chaves, prekeys assinadas, substituição explícita, revogação e rejeição de contato desconhecido. |
| Olm | Mensagens/respostas, reordenação, reinícios, iniciações simultâneas, deduplicação, receipt autenticada, persistência antes do envio. |
| Entrega | Direta sem relay, offline após reinício, dois relays independentes, destino explícito sem entrega a terceiro. |
| Recuperação | Falhas locais preservam mailbox, capacidade reservada para receipts, fila remota cheia, paginação do backlog direto. |
| Relay | Auth, ownership de fetch/ACK, persistência, prekey consumida, idempotência, quotas, TTL, frames e shutdown. |
| TLS | CA/hostname, versões 1.2/1.3, vínculo de certificado derivado nos endpoints, prova com contexto diferente recusada e timeout. |
| TLS + aplicação | Troca direta real e ciclo offline completo com reinício de clientes/relay, ambos por TLS. |
| CLI | Comandos, texto preservado, senha sem eco, controles de terminal, destino obrigatório, reconexão, EOF/cancelamento/background. |
| Legado | Primitivas e demonstração ML com modelos sintéticos temporários, isolados do fluxo novo. |

Dados são sintéticos; conexões de integração usam loopback. Não foram feitos testes ofensivos em sistemas de terceiros.

## Revisões e JEV

Agentes paralelos implementaram identidade/CLI, conversas Olm, transporte/relay/TLS e packaging. Um agente independente revisou as fronteiras de confiança e o fluxo de entrega.

A revisão encontrou problemas reais de ACK após falha local, códigos incompatíveis do relay, bloqueio por fila cheia, hierarquia de exceções, capacidade de receipts e orçamento de requests direto. Eles foram corrigidos e receberam regressões específicas. A conferência final não identificou bloqueios concretos restantes no escopo revisado.

JEV foi usado para seleção do protocolo/topologia, decisões delimitadas, verificação de alegações e gates de patches. Vários gates retornaram escalate/review por incerteza em correção, cobertura e alcance; isso **não** foi uma aprovação automática. No gate final de integração, as quatro alegações receberam o rótulo verified, mas todas abaixo do limiar automático. Fonte, testes e revisão independente fundamentam os resultados; não se repete o mesmo input para obter resposta favorável.

Revisão por agentes/JEV não substitui auditoria criptográfica formal, revisão humana especializada, validação do dispositivo ou segurança de distribuição.

## Plataformas e reprodução

CI configurada para Windows/Ubuntu, Python 3.10/3.11. A execução remota não foi realizada nesta entrega. O caminho de entrada nativo POSIX não foi executado localmente no Windows; a plataforma macOS também não foi homologada.

O backend de build e vodozemac estão fixados; ainda não existe lock completo de todas as dependências transitivas. O build isolado padrão pode consultar o índice de pacotes:

~~~powershell
./.venv/Scripts/python.exe -m build
~~~

O comando escreve em dist/ e não publica nada. A wheel do projeto depende do binding nativo vodozemac compatível com a plataforma.

## Experimentos opcionais

Runtime padrão não depende de ML. Para estudar o legado ou treinar modelos:

~~~powershell
./.venv/Scripts/python.exe -m pip install -r requirements-legacy.txt
./.venv/Scripts/python.exe -m pip install -r requirements-training.txt
~~~

core.anomaly usa diretório temporário na demonstração. train_model.py e data.training_data_generator continuam capazes de gravar artefatos: execute somente se quiser regenerá-los. Não carregue joblib/pickle de origem desconhecida. Demonstrações de core.comm podem abrir listeners e registrar plaintext; não fazem parte da aplicação E2EE.

## Navegação e preservação

~~~powershell
codegraph status
codegraph explore "SecureClient Messenger sync_relay receive"
codegraph sync
~~~

Use CodeGraph antes de localizar/ler código. Em clone sem índice, sua criação depende da decisão do usuário. O banco local está ignorado pelo Git.

Siga AGENTS.md para JEV: questão útil, evidência mínima sanitizada, uma chamada por input inalterado. Não envie senhas, chaves, conversas, dados pessoais ou segredos. As instruções são o lembrete persistente; não há hook que envie todo diff automaticamente.

Não versione cofres, bancos, chaves/certificados TLS ou modelos históricos novos. Permissões locais e .gitignore não substituem revisão do que será publicado.
