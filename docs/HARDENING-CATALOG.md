# Catálogo de hardening — referência gerada

> Gerado a partir de `hardening/catalog.json` (versão `2026.10.28`). A fonte da verdade é o JSON; este arquivo é só leitura humana.
> "Marcado" = vem marcado por padrão. Itens de **alto** risco nunca vêm marcados e exigem o pré-requisito indicado.

## Controladores de Domínio

GPO criada: `[Hardening] DC - Baseline` · vincular a: OU=Domain Controllers (somente DCs)

| Configuração | Risco | Marcado | Pré-requisito / cuidado |
|---|---|---|---|
| Auditar tráfego NTLM de entrada (todas as contas) `auth.ntlm-audit-incoming` | baixo | sim | Gera eventos de auditoria. Deixe coletando por 2 a 4 semanas antes de elevar o nível de autenticação LAN Manager. |
| Auditar autenticação NTLM no domínio (DC) `auth.ntlm-audit-domain` | baixo | sim | Somente auditoria. Volume moderado no log NTLM/Operational dos DCs. |
| Auditar tráfego NTLM de saída `auth.ntlm-audit-outgoing` | baixo | sim | Somente auditoria. |
| Nível de autenticação LAN Manager: somente NTLMv2, recusar LM e NTLM (nível 5) `auth.lm-compat` | ALTO | não | Coletar auditoria NTLM por 2 a 4 semanas e tratar as exceções encontradas. |
| Segurança mínima de sessão NTLM: NTLMv2 + 128 bits (cliente e servidor) `auth.ntlm-min-session-security` | ALTO | não | Mesmo pré-requisito de auth.lm-compat. |
| Não armazenar o hash LAN Manager na próxima troca de senha `auth.no-lm-hash` | baixo | sim | Só afeta clientes Windows 95/98 sem o Directory Services Client, que não devem mais existir. |
| Restringir enumeração anônima de contas SAM e compartilhamentos `auth.restrict-anonymous` | médio | sim | Aplicações muito antigas que dependem de sessão nula podem falhar. Em ambientes com domínios NT4 ou Samba antigo, teste antes. |
| Desabilitar WDigest (senha em texto claro na memória do LSASS) `auth.wdigest` | baixo | sim | Praticamente nenhum impacto em sistemas atuais. Só afeta autenticação HTTP Digest legada. |
| Kerberos: permitir somente AES128/AES256 (sem RC4) `auth.kerberos-aes-only` | ALTO | não | Inventariar contas de serviço e trusts com RC4 e migrá-las para AES. |
| Cliente LDAP: exigir assinatura `auth.ldap-client-signing` | médio | não | Clientes que falam com servidores LDAP não-Microsoft sem suporte a assinatura (Linux, appliances) param de funcionar. |
| UAC: manter ativo, consentimento em desktop seguro e filtrar contas locais na rede `auth.uac-core` | baixo | sim | Baixo. Administração remota com contas locais (não de domínio) passa a exigir conta de domínio. |
| Desabilitar SMBv1 (servidor e driver cliente) `net.smb1-off` | médio | sim | Equipamentos muito antigos (scanners, NAS, sistemas legados) que só falam SMBv1 perdem acesso. Identifique-os antes com auditoria de SMB1. |
| Servidor SMB: exigir assinatura de pacotes `net.smb-signing-server` | médio | sim | Clientes que não suportam assinatura (NAS e dispositivos antigos) deixam de conectar. Pode haver pequena perda de desempenho em transferências muito grandes. |
| Cliente SMB: exigir assinatura de pacotes `net.smb-signing-client` | médio | sim | Acesso a servidores/NAS sem assinatura passa a falhar. |
| Desabilitar LLMNR (resolução multicast de nomes) `net.llmnr-off` | baixo | sim | Baixo. Nomes de dispositivos fora do DNS deixam de resolver por multicast. |
| Área de Trabalho Remota: exigir NLA, TLS e criptografia alta `net.rdp-secure` | médio | sim | Clientes RDP muito antigos (sem NLA/CredSSP) deixam de conectar. |
| WinRM: bloquear autenticação Basic/Digest e tráfego sem criptografia `net.winrm-secure` | baixo | sim | Scripts que usam WinRM com autenticação Basic precisam migrar para Kerberos/Negotiate. |
| Firewall do Windows ativo nos 3 perfis, entrada bloqueada por padrão, log de descartes `net.firewall` | médio | sim | Levantar portas/serviços de terceiros em cada servidor e criar regras de entrada equivalentes na mesma GPO ou em outra. |
| Desabilitar AutoRun/AutoPlay em todas as unidades `sys.autorun-off` | baixo | sim | Baixo. Usuários passam a abrir mídias manualmente. |
| Point and Print: instalar drivers de impressora somente com administrador `sys.print-point-and-print` | baixo | sim | Usuários comuns deixam de instalar impressoras que exigem driver novo; use drivers pré-instalados ou servidor de impressão. |
| Habilitar log de eventos 2889 (clientes LDAP sem assinatura) `dc.ldap-diagnostics` | baixo | sim | Aumenta levemente o volume do log Directory Service. |
| LDAP channel binding: quando suportado (valor 1) `dc.ldap-channel-binding` | baixo | sim | Baixo no valor 1; apenas auditoria dos clientes sem CBT. O valor 2 só deve ser usado depois de limpar esses clientes. |
| Servidor LDAP do DC: exigir assinatura `dc.ldap-signing-required` | ALTO | não | Habilitar dc.ldap-diagnostics e analisar os eventos 2889 por 2 a 4 semanas; migrar clientes para LDAPS/SASL com assinatura. |
| Spooler de impressão do DC: não aceitar conexões de clientes `dc.print-spooler-remote-off` | baixo | sim | DCs deixam de funcionar como servidor de impressão (não devem ser). A poda de filas de impressão obsoletas no AD deixa de ocorrer: faça periodicamente. |
| Registrar blocos de script do PowerShell `log.powershell-scriptblock` | baixo | sim | Aumenta o volume do log PowerShell/Operational e pode registrar dados sensíveis passados em scripts. |
| Incluir linha de comando nos eventos de criação de processo `log.process-cmdline` | baixo | sim | A linha de comando pode conter segredos digitados por administradores; proteja o acesso ao log de segurança. |
| Tamanhos dos logs: Segurança 192 MB, Aplicativo e Sistema 32 MB `log.event-log-size` | baixo | sim | Consome mais disco (cerca de 256 MB por máquina). |
| Forçar subcategorias de auditoria a sobrepor as categorias legadas `audit.force-subcategory` | baixo | sim | Nenhum além da mudança de modelo de auditoria. É dependência de todas as subcategorias abaixo e é incluída automaticamente. |
| Auditar: Validação de credenciais (Sucesso e Falha) `audit.dc.credential-validation` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Serviço de autenticação Kerberos (Sucesso e Falha) `audit.dc.kerberos-authentication-service` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Operações de tíquete de serviço Kerberos (Sucesso e Falha) `audit.dc.kerberos-service-ticket-operations` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Gerenciamento de conta de computador (Sucesso) `audit.dc.computer-account-management` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Gerenciamento de grupo de segurança (Sucesso) `audit.dc.security-group-management` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Gerenciamento de grupo de distribuição (Sucesso) `audit.dc.distribution-group-management` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Outros eventos de gerenciamento de conta (Sucesso) `audit.dc.other-account-management-events` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Gerenciamento de conta de usuário (Sucesso e Falha) `audit.dc.user-account-management` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Acesso ao serviço de diretório (Sucesso e Falha) `audit.dc.directory-service-access` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Alterações no serviço de diretório (Sucesso) `audit.dc.directory-service-changes` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Logon (Sucesso e Falha) `audit.dc.logon` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Logoff (Sucesso) `audit.dc.logoff` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Bloqueio de conta (Falha) `audit.dc.account-lockout` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Logon especial (Sucesso) `audit.dc.special-logon` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Outros eventos de logon/logoff (Sucesso e Falha) `audit.dc.other-logon-logoff-events` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Associação a grupos (Sucesso) `audit.dc.group-membership` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Criação de processo (Sucesso) `audit.dc.process-creation` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Alteração da política de auditoria (Sucesso e Falha) `audit.dc.audit-policy-change` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Alteração da política de autenticação (Sucesso) `audit.dc.authentication-policy-change` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Uso de privilégio confidencial (Sucesso e Falha) `audit.dc.sensitive-privilege-use` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Alteração do estado de segurança (Sucesso) `audit.dc.security-state-change` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Extensão do sistema de segurança (Sucesso) `audit.dc.security-system-extension` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Integridade do sistema (Sucesso e Falha) `audit.dc.system-integrity` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |

## Servidores membros

GPO criada: `[Hardening] Servidores Membros - Baseline` · vincular a: OU de servidores membros (nunca vincular à OU Domain Controllers)

| Configuração | Risco | Marcado | Pré-requisito / cuidado |
|---|---|---|---|
| Auditar tráfego NTLM de entrada (todas as contas) `auth.ntlm-audit-incoming` | baixo | sim | Gera eventos de auditoria. Deixe coletando por 2 a 4 semanas antes de elevar o nível de autenticação LAN Manager. |
| Auditar tráfego NTLM de saída `auth.ntlm-audit-outgoing` | baixo | sim | Somente auditoria. |
| Nível de autenticação LAN Manager: somente NTLMv2, recusar LM e NTLM (nível 5) `auth.lm-compat` | ALTO | não | Coletar auditoria NTLM por 2 a 4 semanas e tratar as exceções encontradas. |
| Segurança mínima de sessão NTLM: NTLMv2 + 128 bits (cliente e servidor) `auth.ntlm-min-session-security` | ALTO | não | Mesmo pré-requisito de auth.lm-compat. |
| Não armazenar o hash LAN Manager na próxima troca de senha `auth.no-lm-hash` | baixo | sim | Só afeta clientes Windows 95/98 sem o Directory Services Client, que não devem mais existir. |
| Restringir enumeração anônima de contas SAM e compartilhamentos `auth.restrict-anonymous` | médio | sim | Aplicações muito antigas que dependem de sessão nula podem falhar. Em ambientes com domínios NT4 ou Samba antigo, teste antes. |
| Desabilitar WDigest (senha em texto claro na memória do LSASS) `auth.wdigest` | baixo | sim | Praticamente nenhum impacto em sistemas atuais. Só afeta autenticação HTTP Digest legada. |
| Kerberos: permitir somente AES128/AES256 (sem RC4) `auth.kerberos-aes-only` | ALTO | não | Inventariar contas de serviço e trusts com RC4 e migrá-las para AES. |
| Cliente LDAP: exigir assinatura `auth.ldap-client-signing` | médio | não | Clientes que falam com servidores LDAP não-Microsoft sem suporte a assinatura (Linux, appliances) param de funcionar. |
| UAC: manter ativo, consentimento em desktop seguro e filtrar contas locais na rede `auth.uac-core` | baixo | sim | Baixo. Administração remota com contas locais (não de domínio) passa a exigir conta de domínio. |
| UAC: Modo de Aprovação do Administrador para a conta Administrator interna `auth.uac-admin-token` | médio | sim | Scripts que usam a conta Administrator interna por rede ou sem elevação podem precisar de ajuste. |
| Restringir chamadas remotas ao SAM somente a administradores `auth.restrict-remote-sam` | médio | não | Ferramentas de inventário ou monitoração que consultam o SAM com contas sem privilégio de administrador deixam de funcionar. |
| Desabilitar SMBv1 (servidor e driver cliente) `net.smb1-off` | médio | sim | Equipamentos muito antigos (scanners, NAS, sistemas legados) que só falam SMBv1 perdem acesso. Identifique-os antes com auditoria de SMB1. |
| Servidor SMB: exigir assinatura de pacotes `net.smb-signing-server` | médio | sim | Clientes que não suportam assinatura (NAS e dispositivos antigos) deixam de conectar. Pode haver pequena perda de desempenho em transferências muito grandes. |
| Cliente SMB: exigir assinatura de pacotes `net.smb-signing-client` | médio | sim | Acesso a servidores/NAS sem assinatura passa a falhar. |
| Desabilitar LLMNR (resolução multicast de nomes) `net.llmnr-off` | baixo | sim | Baixo. Nomes de dispositivos fora do DNS deixam de resolver por multicast. |
| Área de Trabalho Remota: exigir NLA, TLS e criptografia alta `net.rdp-secure` | médio | sim | Clientes RDP muito antigos (sem NLA/CredSSP) deixam de conectar. |
| WinRM: bloquear autenticação Basic/Digest e tráfego sem criptografia `net.winrm-secure` | baixo | sim | Scripts que usam WinRM com autenticação Basic precisam migrar para Kerberos/Negotiate. |
| Firewall do Windows ativo nos 3 perfis, entrada bloqueada por padrão, log de descartes `net.firewall` | médio | sim | Levantar portas/serviços de terceiros em cada servidor e criar regras de entrada equivalentes na mesma GPO ou em outra. |
| Desabilitar AutoRun/AutoPlay em todas as unidades `sys.autorun-off` | baixo | sim | Baixo. Usuários passam a abrir mídias manualmente. |
| Point and Print: instalar drivers de impressora somente com administrador `sys.print-point-and-print` | baixo | sim | Usuários comuns deixam de instalar impressoras que exigem driver novo; use drivers pré-instalados ou servidor de impressão. |
| Microsoft Defender: proteção contra aplicativos potencialmente indesejados `sys.defender-pua` | baixo | sim | Se houver antivírus de terceiros como principal, o Defender fica em modo passivo e a configuração é inofensiva. |
| Windows LAPS: senha do administrador local gerenciada e salva no AD `sys.windows-laps` | médio | não | Executar Update-LapsADSchema e Set-LapsADComputerSelfPermission na OU de destino antes de vincular. |
| Registrar blocos de script do PowerShell `log.powershell-scriptblock` | baixo | sim | Aumenta o volume do log PowerShell/Operational e pode registrar dados sensíveis passados em scripts. |
| Incluir linha de comando nos eventos de criação de processo `log.process-cmdline` | baixo | sim | A linha de comando pode conter segredos digitados por administradores; proteja o acesso ao log de segurança. |
| Tamanhos dos logs: Segurança 192 MB, Aplicativo e Sistema 32 MB `log.event-log-size` | baixo | sim | Consome mais disco (cerca de 256 MB por máquina). |
| Forçar subcategorias de auditoria a sobrepor as categorias legadas `audit.force-subcategory` | baixo | sim | Nenhum além da mudança de modelo de auditoria. É dependência de todas as subcategorias abaixo e é incluída automaticamente. |
| Auditar: Validação de credenciais (Sucesso e Falha) `audit.client.credential-validation` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Gerenciamento de grupo de segurança (Sucesso) `audit.client.security-group-management` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Gerenciamento de conta de usuário (Sucesso e Falha) `audit.client.user-account-management` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Logon (Sucesso e Falha) `audit.client.logon` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Logoff (Sucesso) `audit.client.logoff` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Bloqueio de conta (Falha) `audit.client.account-lockout` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Logon especial (Sucesso) `audit.client.special-logon` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Outros eventos de logon/logoff (Sucesso e Falha) `audit.client.other-logon-logoff-events` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Associação a grupos (Sucesso) `audit.client.group-membership` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Criação de processo (Sucesso) `audit.client.process-creation` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Alteração da política de auditoria (Sucesso e Falha) `audit.client.audit-policy-change` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Alteração da política de autenticação (Sucesso) `audit.client.authentication-policy-change` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Uso de privilégio confidencial (Sucesso e Falha) `audit.client.sensitive-privilege-use` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Alteração do estado de segurança (Sucesso) `audit.client.security-state-change` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Extensão do sistema de segurança (Sucesso) `audit.client.security-system-extension` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Integridade do sistema (Sucesso e Falha) `audit.client.system-integrity` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |

## Estações Windows 10/11

GPO criada: `[Hardening] Estações - Baseline` · vincular a: OU de estações de trabalho

| Configuração | Risco | Marcado | Pré-requisito / cuidado |
|---|---|---|---|
| Auditar tráfego NTLM de entrada (todas as contas) `auth.ntlm-audit-incoming` | baixo | sim | Gera eventos de auditoria. Deixe coletando por 2 a 4 semanas antes de elevar o nível de autenticação LAN Manager. |
| Auditar tráfego NTLM de saída `auth.ntlm-audit-outgoing` | baixo | sim | Somente auditoria. |
| Nível de autenticação LAN Manager: somente NTLMv2, recusar LM e NTLM (nível 5) `auth.lm-compat` | ALTO | não | Coletar auditoria NTLM por 2 a 4 semanas e tratar as exceções encontradas. |
| Segurança mínima de sessão NTLM: NTLMv2 + 128 bits (cliente e servidor) `auth.ntlm-min-session-security` | ALTO | não | Mesmo pré-requisito de auth.lm-compat. |
| Não armazenar o hash LAN Manager na próxima troca de senha `auth.no-lm-hash` | baixo | sim | Só afeta clientes Windows 95/98 sem o Directory Services Client, que não devem mais existir. |
| Restringir enumeração anônima de contas SAM e compartilhamentos `auth.restrict-anonymous` | médio | sim | Aplicações muito antigas que dependem de sessão nula podem falhar. Em ambientes com domínios NT4 ou Samba antigo, teste antes. |
| Desabilitar WDigest (senha em texto claro na memória do LSASS) `auth.wdigest` | baixo | sim | Praticamente nenhum impacto em sistemas atuais. Só afeta autenticação HTTP Digest legada. |
| Kerberos: permitir somente AES128/AES256 (sem RC4) `auth.kerberos-aes-only` | ALTO | não | Inventariar contas de serviço e trusts com RC4 e migrá-las para AES. |
| Cliente LDAP: exigir assinatura `auth.ldap-client-signing` | médio | não | Clientes que falam com servidores LDAP não-Microsoft sem suporte a assinatura (Linux, appliances) param de funcionar. |
| UAC: manter ativo, consentimento em desktop seguro e filtrar contas locais na rede `auth.uac-core` | baixo | sim | Baixo. Administração remota com contas locais (não de domínio) passa a exigir conta de domínio. |
| UAC: Modo de Aprovação do Administrador para a conta Administrator interna `auth.uac-admin-token` | médio | sim | Scripts que usam a conta Administrator interna por rede ou sem elevação podem precisar de ajuste. |
| Restringir chamadas remotas ao SAM somente a administradores `auth.restrict-remote-sam` | médio | não | Ferramentas de inventário ou monitoração que consultam o SAM com contas sem privilégio de administrador deixam de funcionar. |
| Desabilitar SMBv1 (servidor e driver cliente) `net.smb1-off` | médio | sim | Equipamentos muito antigos (scanners, NAS, sistemas legados) que só falam SMBv1 perdem acesso. Identifique-os antes com auditoria de SMB1. |
| Servidor SMB: exigir assinatura de pacotes `net.smb-signing-server` | médio | sim | Clientes que não suportam assinatura (NAS e dispositivos antigos) deixam de conectar. Pode haver pequena perda de desempenho em transferências muito grandes. |
| Cliente SMB: exigir assinatura de pacotes `net.smb-signing-client` | médio | sim | Acesso a servidores/NAS sem assinatura passa a falhar. |
| Desabilitar LLMNR (resolução multicast de nomes) `net.llmnr-off` | baixo | sim | Baixo. Nomes de dispositivos fora do DNS deixam de resolver por multicast. |
| Área de Trabalho Remota: exigir NLA, TLS e criptografia alta `net.rdp-secure` | médio | sim | Clientes RDP muito antigos (sem NLA/CredSSP) deixam de conectar. |
| WinRM: bloquear autenticação Basic/Digest e tráfego sem criptografia `net.winrm-secure` | baixo | sim | Scripts que usam WinRM com autenticação Basic precisam migrar para Kerberos/Negotiate. |
| Firewall do Windows ativo nos 3 perfis, entrada bloqueada por padrão, log de descartes `net.firewall` | médio | sim | Levantar portas/serviços de terceiros em cada servidor e criar regras de entrada equivalentes na mesma GPO ou em outra. |
| Desabilitar AutoRun/AutoPlay em todas as unidades `sys.autorun-off` | baixo | sim | Baixo. Usuários passam a abrir mídias manualmente. |
| Point and Print: instalar drivers de impressora somente com administrador `sys.print-point-and-print` | baixo | sim | Usuários comuns deixam de instalar impressoras que exigem driver novo; use drivers pré-instalados ou servidor de impressão. |
| Microsoft Defender: proteção contra aplicativos potencialmente indesejados `sys.defender-pua` | baixo | sim | Se houver antivírus de terceiros como principal, o Defender fica em modo passivo e a configuração é inofensiva. |
| Windows LAPS: senha do administrador local gerenciada e salva no AD `sys.windows-laps` | médio | não | Executar Update-LapsADSchema e Set-LapsADComputerSelfPermission na OU de destino antes de vincular. |
| Registrar blocos de script do PowerShell `log.powershell-scriptblock` | baixo | sim | Aumenta o volume do log PowerShell/Operational e pode registrar dados sensíveis passados em scripts. |
| Incluir linha de comando nos eventos de criação de processo `log.process-cmdline` | baixo | sim | A linha de comando pode conter segredos digitados por administradores; proteja o acesso ao log de segurança. |
| Tamanhos dos logs: Segurança 192 MB, Aplicativo e Sistema 32 MB `log.event-log-size` | baixo | sim | Consome mais disco (cerca de 256 MB por máquina). |
| Forçar subcategorias de auditoria a sobrepor as categorias legadas `audit.force-subcategory` | baixo | sim | Nenhum além da mudança de modelo de auditoria. É dependência de todas as subcategorias abaixo e é incluída automaticamente. |
| Auditar: Validação de credenciais (Sucesso e Falha) `audit.client.credential-validation` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Gerenciamento de grupo de segurança (Sucesso) `audit.client.security-group-management` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Gerenciamento de conta de usuário (Sucesso e Falha) `audit.client.user-account-management` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Logon (Sucesso e Falha) `audit.client.logon` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Logoff (Sucesso) `audit.client.logoff` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Bloqueio de conta (Falha) `audit.client.account-lockout` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Logon especial (Sucesso) `audit.client.special-logon` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Outros eventos de logon/logoff (Sucesso e Falha) `audit.client.other-logon-logoff-events` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Associação a grupos (Sucesso) `audit.client.group-membership` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Criação de processo (Sucesso) `audit.client.process-creation` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Alteração da política de auditoria (Sucesso e Falha) `audit.client.audit-policy-change` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Alteração da política de autenticação (Sucesso) `audit.client.authentication-policy-change` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Uso de privilégio confidencial (Sucesso e Falha) `audit.client.sensitive-privilege-use` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Alteração do estado de segurança (Sucesso) `audit.client.security-state-change` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Extensão do sistema de segurança (Sucesso) `audit.client.security-system-extension` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Integridade do sistema (Sucesso e Falha) `audit.client.system-integrity` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Atividade Plug and Play (Sucesso) `audit.client.pnp-activity` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |
| Auditar: Armazenamento removível (Sucesso e Falha) `audit.client.removable-storage` | baixo | sim | Aumenta o volume do log de segurança. Os tamanhos de log recomendados (log.event-log-size) compensam. |

## Senha e bloqueio de conta do domínio

Política de senha e bloqueio de conta do domínio só vale pela Default Domain Policy ou por PSO; GPO em OU afeta apenas contas locais. A ferramenta compara os valores atuais com as referências da Microsoft e gera o plano, sem alterar a Default Domain Policy.

| Item | Referência | Observação |
|---|---|---|
| Tamanho mínimo da senha | 14 ou mais caracteres | Referência do baseline da Microsoft: 14 ou mais caracteres. |
| Requisitos de complexidade | Habilitada | Referência do baseline da Microsoft: habilitado. |
| Idade mínima da senha | 1 ou mais dias | Referência do baseline da Microsoft: 1 ou mais dias, para impedir troca em sequência que anule o histórico. |
| Histórico de senhas | 24 ou mais senhas | Referência comum de mercado (24 senhas). Confirme no baseline do seu sistema operacional. |
| Limite de bloqueio de conta | 1 a 10 tentativas | O baseline atual do Security Compliance Toolkit recomenda 10; benchmarks mais estritos usam 5 ou menos. Nunca 0 (desligado) sem monitoração de falhas de logon. |
| Duração do bloqueio | 15 ou mais minutos | Referência do baseline da Microsoft: 15 minutos ou mais. |
| Zerar contador de bloqueio após | 15 ou mais minutos | Referência do baseline da Microsoft: 15 minutos ou mais. |
