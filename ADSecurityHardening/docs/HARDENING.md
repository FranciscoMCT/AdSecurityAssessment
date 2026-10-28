# AD Security Hardening — GPOs de baseline Microsoft (criadas sem vínculo)

Este módulo é **separado** do app de avaliação. A avaliação (`ADSecurityAssessment.exe`) continua **somente leitura** e nunca referencia este código
(há testes que garantem isso). O hardening (`ADSecurityHardening.exe`) existe para *agir* sobre as lacunas: ele **gera GPOs** com configurações de segurança baseadas nas
recomendações e baselines publicados pela Microsoft, e as deixa **sem vínculo**, para você testar em uma OU piloto antes de qualquer efeito em produção.

## O que ele faz — e o que não faz

| Faz | Não faz |
|---|---|
| Mostra uma **prévia** (relatório HTML/JSON) de tudo o que seria criado, com risco, impacto e pré-requisito de cada item | Não **vincula** GPO a nenhuma OU/domínio/site |
| Cria GPOs **novas**, sem vínculo, para DCs, servidores membros e estações Windows 10/11 | Não **edita** nenhuma GPO existente (Default Domain Policy, Default Domain Controllers Policy, as suas) |
| Cria uma GPO **[ROLLBACK]** gêmea que desfaz a principal | Não altera objetos do AD (usuários, grupos, KRBTGT, Domain Admins) |
| Compara a política de **senha/bloqueio** do domínio com as referências Microsoft e orienta | Não altera a política de senha do domínio |
| Remove **somente** GPOs que ele mesmo criou (registro em `data\created-gpos.json`), e só se não estiverem vinculadas | Não envia nada para fora da máquina; não usa PowerShell, RSAT nem GPMC |

## A questão da GPO — o que você precisa entender

**1. Uma GPO são duas metades.** O *GPC* é um objeto do AD (`CN={GUID},CN=Policies,CN=System,DC=...`) e o *GPT* é uma pasta no `SYSVOL` com os arquivos das configurações.
O app cria as duas, na ordem certa (SYSVOL primeiro, GPC depois), no **PDC emulator**, e confere depois que o conteúdo gravado é idêntico (hash SHA-256) e que as versões batem.
Arquivos gerados: `Registry.pol` (Administrative Templates e chaves de registro), `GptTmpl.inf` (*Security Options*), `audit.csv` (auditoria avançada) e `GPT.INI`.

**2. Criar não é aplicar.** Uma GPO só afeta computadores quando é **vinculada** (atributo `gPLink`) a um site, domínio ou OU. Como o app nunca vincula, criar as GPOs **não muda nada em produção**.
O vínculo é decisão sua: no GPMC, arraste/vincule a GPO a uma **OU piloto** com poucas máquinas representativas.

**3. Escopo importa.** A GPO de **DC** vai só para a OU *Domain Controllers*; a de **servidores membros** para a OU dos servidores (nunca a dos DCs); a de **estações** para as OUs de estações.
Misturar escopos é a forma mais comum de causar incidente (por exemplo, firewall bloqueando entrada num servidor com aplicação de terceiros).

**4. "Tatuagem" — desvincular nem sempre reverte.** Valores de *Security Options*, de auditoria avançada e chaves de registro fora de `...\Policies\` **permanecem na máquina** depois que a GPO deixa de valer.
Valores em `...\Policies\...` (Administrative Templates) são removidos pelo próprio Windows. Por isso o app marca cada item com "fica gravada?" e gera a GPO **[ROLLBACK]**: se precisar reverter,
vincule a [ROLLBACK] ao mesmo alvo com **precedência maior** que a principal; ela grava os **valores padrão do Windows assumidos no catálogo** (não o valor que cada máquina tinha antes, que a ferramenta não consegue saber) e apaga os valores que normalmente não existem. Se alguma máquina usava um valor personalizado, ajuste-o manualmente. Itens sem reversão automática conhecida aparecem listados.

**5. Senha e bloqueio de conta são uma exceção.** Para contas de **domínio**, a política de senha e de bloqueio só vale pela **Default Domain Policy** (ou por um **PSO**). Uma GPO em OU só afeta contas locais.
Por isso essa parte é "avaliar e orientar": a aba 2 compara os valores atuais com as referências e você decide como alterar (editando a Default Domain Policy no GPMC ou criando um PSO).

**6. Ordem de precedência.** Última a ser processada vence: Local → Site → Domínio → OU (mais próxima do objeto, por último). `Enforced` e `Block inheritance` mudam isso. Em dúvida, `gpresult /h` na máquina piloto mostra a GPO vencedora de cada configuração.

**7. Replicação.** O AD e o SYSVOL replicam separadamente. Espere a replicação (verifique com `repadmin /showrepl` e o estado do DFSR) antes de vincular, principalmente com vários sites.

## Passo a passo

1. Copie a pasta `ADSecurityHardening` para uma máquina **ingressada no domínio**. Não há instalador nem dependências (o `.exe` é auto-contido).
2. Execute `ADSecurityHardening.exe` com uma conta que possa criar GPOs (**Domain Admins** ou **Group Policy Creator Owners**). Não precisa ser administrador local. Para usar outra conta sem trocar de logon: `runas /netonly /user:DOMINIO\conta ADSecurityHardening.exe`.
3. Aba **1. Plano**: marque os escopos e revise as configurações. Clique numa linha para ler o porquê, o impacto e o pré-requisito. Itens de **alto risco vêm desmarcados**.
4. Clique em **Conectar ao domínio** (opcional para a prévia; obrigatório para criar). A aba **2** mostra a política de senha/bloqueio atual contra as referências.
5. Aba **3. Prévia e criação**: **Gerar prévia** cria o relatório em `reports\` e abre no navegador. Revise.
6. **Criar GPOs no domínio (sem vínculo)** pede confirmação, cria, confere e registra. O resultado e o relatório ficam em `reports\`.
7. No **GPMC**: vincule **uma** GPO a **uma OU piloto**. Na máquina piloto: `gpupdate /force` e `gpresult /h piloto.html`.
8. Observe por alguns dias (veja "Rollout" abaixo), amplie por ondas. Para remover uma GPO criada pelo app (desde que desvinculada): aba **4**.

## Rollout recomendado para os itens que podem quebrar aplicação

* **NTLM**: deixe a auditoria (itens de baixo risco, já marcados) coletando 2 a 4 semanas — log *Microsoft-Windows-NTLM/Operational* (evento 8004 nos DCs). Só então avalie `LmCompatibilityLevel = 5` (alto risco, opt-in).
* **Assinatura LDAP**: o item `dc.ldap-diagnostics` habilita o evento **2889** (clientes que fazem bind sem assinatura) no log *Directory Service* dos DCs. Corrija os clientes listados e só então marque `dc.ldap-signing-required`.
* **Channel binding LDAP**: a GPO aplica o valor 1 (*quando suportado*), que registra sem rejeitar. O valor 2 (*sempre*) deve vir depois da limpeza dos clientes, como mudança separada.
* **Firewall**: levante portas e serviços de terceiros (backup, monitoração, ERP, banco) e crie as regras de entrada **antes** de vincular a GPO a servidores.
* **SMB**: SMBv1 e assinatura SMB podem afetar NAS, multifuncionais e sistemas legados. Piloto obrigatório.
* **Kerberos só AES**: inventarie contas de serviço e trusts que ainda usam RC4 antes (alto risco, opt-in).
* **LAPS (Windows LAPS)**: estenda o esquema (`Update-LapsADSchema`) e conceda permissões (`Set-LapsADComputerSelfPermission`) antes; senão a política falha nos clientes (opt-in).

## O que **não** é GPO (acompanhe manualmente)

* **KRBTGT**: redefinir a senha **duas vezes**, com intervalo de pelo menos o tempo de vida máximo de tíquete (padrão 10 h) entre elas. A Microsoft publica um script para isso (`New-KrbtgtKeys.ps1`). Faça em janela planejada.
* **Membros de grupos privilegiados** (Domain Admins, Enterprise Admins, Schema Admins, Administrators): revisar e reduzir; usar contas administrativas separadas.
* **Contas com SPN e senha antiga**, contas sem expiração de senha, delegação irrestrita: tratar conforme os achados do `ADSecurityAssessment.exe`.
* **LSA Protection (`RunAsPPL`)**: não incluída no catálogo porque, com *UEFI lock*, é difícil de reverter. Avalie à parte.
* **Protected Users, tiering de administração, Credential Guard**: decisões de arquitetura, fora do escopo de uma baseline automática.

## Permissões

* Criar GPOs: Domain Admins ou Group Policy Creator Owners (criar objetos em `CN=Policies,CN=System` e pastas em `SYSVOL\...\Policies`).
* Ler a política de senha: qualquer usuário do domínio. Ler PSOs: costuma exigir direito de leitura em `CN=Password Settings Container` (se faltar, a lista vem vazia).
* O app **não pede elevação local** (`asInvoker`).

## Segurança da própria ferramenta

* O app de avaliação e o de hardening são projetos diferentes; os testes `ReadOnlyGuardTests` falham o build se o app de avaliação passar a referenciar o hardening ou criar qualquer escrita LDAP.
* No módulo de hardening a escrita no AD é limitada a `AddRequest`/`DeleteRequest`, somente em `ADSecurityAssessment.Hardening.Windows/LdapGpoStore.cs`; `ModifyRequest`, `gPLink` e afins são proibidos em todo o repositório por teste.
* A interface `IGpoStore` não tem operação de vínculo nem de edição (também testado).
* O catálogo é JSON de esquema fechado (campo desconhecido invalida o arquivo) e só aceita referências em `learn.microsoft.com`. Um `config\catalog.json` inválido é recusado por inteiro.
* Remoção: só GPOs do registro `created-gpos.json`, sem vínculo, e cujo nome não tenha sido alterado por alguém.
* Nenhuma senha é lida ou gravada: a autenticação usa a identidade Windows do processo (Kerberos/Negociate, com assinatura e criptografia LDAP).

## Limitações e o que foi (e não foi) validado

* A lógica de geração dos arquivos (registry.pol, GptTmpl.inf, audit.csv), o catálogo, o planejamento, o executor, o relatório e os guardas têm testes automatizados.
* A gravação real no AD/SYSVOL (`LdapGpoStore`) e a janela WPF são compiladas no GitHub Actions; **valide a primeira execução em um domínio de laboratório** antes de usar em produção.
* Os GUIDs das subcategorias de auditoria seguem o padrão `0CCE92xx-69AE-11D9-BED3-505054503030` e há um botão **Verificar tabela de auditoria nesta máquina (auditpol)** que confere cada um contra o Windows em uso.
* A baseline é um ponto de partida alinhado a recomendações Microsoft, não um substituto da revisão do seu ambiente. Valores como histórico de senha 24 são referências comuns de mercado, sinalizadas como tal.
* O catálogo está em `hardening/catalog.json` (gerado e versionado). Para ajustar sem recompilar: copie `config\catalog.example.json` para `config\catalog.json` e edite.
