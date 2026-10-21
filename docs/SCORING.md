# Metodologia de pontuação

A pontuação é **determinística, documentada e configurável** (`config/scoring.json`). Não há IA, heurística oculta nem peso arbitrário
embutido em código: o que está abaixo é exatamente o que `Core/Pipeline/ScoringEngine.cs` executa.

## 1. Duas medidas separadas

| Medida | Pergunta que responde | Onde aparece |
|---|---|---|
| **Security Score** (0–100, maior = melhor) e **Risk Score** (0–100, maior = pior; `Risk = 100 − Security` antes dos tetos) | Das regras que **foi possível avaliar**, quanto do peso falhou? | Dashboard, relatório, JSON |
| **Assessment Coverage** (0–100 %) | Quanto do peso das regras aplicáveis **foi realmente avaliado**? | Dashboard, aba Cobertura, relatório |

Regra de ouro: **o que não foi avaliado nunca melhora o score**. Regras *Not Evaluated* (dado não coletado, permissão
insuficiente, configuração não legível por LDAP, cobertura parcial) e *Not Applicable* ficam fora do cálculo de risco e
reduzem apenas a Coverage. Uma categoria sem nenhuma regra avaliada é exibida como **Not Evaluated** — sem nota — e não entra com 100 % "de graça".

## 2. Resultado de cada regra

`Passed`, `Failed`, `NotEvaluated`, `NotApplicable`.

* `NotEvaluated` — dataset ausente/falho; dataset parcial sem achados; exceção na regra; evidência incompleta.
* `NotApplicable` — a regra avaliou 0 objetos (ex.: "AD CS não detectado", "sem indicadores de Entra Connect").
* Um `Finding` só existe para regra `Failed` e **somente com evidência técnica coletada** para cada objeto afetado.

## 3. Fórmulas

Para um conjunto de regras (todas, ou as de uma categoria):

```
peso(regra)        = SeverityWeights[severidade da regra]
Aplicáveis         = regras com resultado ≠ NotApplicable
Avaliadas          = regras Passed ou Failed
Risk %             = Σ peso(Failed) / Σ peso(Avaliadas) × 100
Security (bruto)   = 100 − Risk %
Coverage %         = Σ peso(Avaliadas) / Σ peso(Aplicáveis) × 100
```

Se `Σ peso(Aplicáveis) = 0` (só regras Informational), a Coverage usa a contagem de regras em vez do peso.

### Tetos (caps)

Para impedir que muitas regras de baixo risco "diluam" um problema grave, se houver ao menos uma regra **Failed** da severidade
indicada, o Security Score fica limitado ao teto:

| Severidade com falha | Teto padrão |
|---|---|
| Critical | 59 |
| High | 79 |

A interface e o relatório indicam quando um teto foi aplicado (`CapApplied`).

### Faixas de classificação

| Security Score ≥ | Classificação |
|---|---|
| 90 | Strong |
| 75 | Good |
| 60 | Fair |
| 40 | Weak |
| 0 | Poor |

### Score provisório

Se a **Coverage geral** for menor que `MinimumCoveragePercent` (padrão 50 %), o resultado é marcado como **provisório**, com o motivo,
no dashboard e no relatório: a nota existe, mas descreve apenas a parte avaliada.

## 4. Pesos e parâmetros padrão (`config/scoring.json`)

```json
{
  "SeverityWeights": { "Critical": 10, "High": 7, "Medium": 4, "Low": 1, "Informational": 0 },
  "ScoreCaps":       { "Critical": 59, "High": 79 },
  "MinimumCoveragePercent": 50,
  "RatingBands": [ { "MinScore": 90, "Label": "Strong" }, { "MinScore": 75, "Label": "Good" },
                   { "MinScore": 60, "Label": "Fair"   }, { "MinScore": 40, "Label": "Weak" },
                   { "MinScore": 0,  "Label": "Poor"   } ]
}
```

**Transparência:** esses valores são **escolhas do projeto** (uma escala de ponderação por severidade), **não** valores publicados pela
Microsoft. Por isso são configuráveis: ajuste-os à política de risco da sua organização. O arquivo é lido a cada inicialização; se estiver ausente usa-se o padrão, e se for inválido/ilegível a aplicação usa o padrão e registra um aviso no log (nunca falha).

## 5. Categorias do dashboard

Cada regra pertence a uma categoria; o score por categoria usa a **mesma fórmula** restrita às regras da categoria:
Identity Security, Privileged Access, Authentication, Active Directory Infrastructure, Group Policy, AD CS, Hybrid Identity.

## 6. Exemplo trabalhado

Categoria com 4 regras: 1 Critical *Failed*, 1 High *Passed*, 1 Medium *Passed*, 1 High *NotEvaluated*.

* Avaliadas = 10 + 7 + 4 = 21; Failed = 10 → Risk = 10/21 = 47,6 % → Security bruto = 52,4.
* Teto Critical (59) não reduz 52,4 (já é menor); nota final **52,4 — Weak**.
* Coverage = 21 / (21 + 7) = 75 %. A regra *Not Evaluated* não melhorou nem piorou o risco; só reduziu a Coverage.

Os testes `ScoringTests` cobrem esses casos (cobertura ⟂ risco, tetos, categoria sem avaliação, pesos configuráveis, provisório).
