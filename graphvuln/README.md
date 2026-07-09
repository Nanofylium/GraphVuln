# GraphVuln

Ferramenta forense standalone para GDScript e GraphQL — app desktop em Node.js/Express/React/Electron, com scanner estático próprio, servidor GraphQL real e dashboard interativo.

## Estrutura

```
graphvuln-node/
├── server/          Express API — scanners, catálogo CWE, exportadores, simulador de cenários
│   ├── src/
│   │   ├── scanners/         gdscriptScanner.js (16 passes), resourceScanner.js
│   │   ├── cweCatalog.js     mapeamento CWE
│   │   ├── reportExporter.js JSON / SARIF / CSV / Markdown
│   │   ├── attackSimulator.js simulador de cenários (nunca executa nada real)
│   │   ├── projectScanner.js  walker de diretório
│   │   ├── graphqlSchema.js   schema GraphQL real (graphql-js)
│   │   └── app.js / index.js  rotas Express
│   └── test-fixtures/         arquivo .gd propositalmente vulnerável, pra teste manual
├── client/           React (Vite) — dashboard
├── electron/         shell desktop
│   ├── main.js                 entry point — sobe a API in-process e abre a janela
│   ├── scripts/prebuild.js     vendoriza server/src + client/dist pra dentro do pacote
│   └── test/e2e-smoke-test.js  smoke test automatizado (preenche path, escaneia, clica)
└── misc-logo/        ícones do app (icon.ico, icon.png)
```

## GraphQL de verdade (graphql-js + graphql-http + ruru)

O servidor GraphQL é construído sobre a implementação de referência do GraphQL como dependência npm, não código vendorizado:

- **[`graphql`](https://www.npmjs.com/package/graphql)** v16.14.2 (graphql-js, mantida pela GraphQL Foundation/OpenJS) — MIT
- **[`graphql-http`](https://www.npmjs.com/package/graphql-http)** v1.22.4 (sucessora do `express-graphql`, descontinuado) — MIT
- **[`ruru`](https://www.npmjs.com/package/ruru)** v2.0.0 (IDE leve estilo GraphiQL) — MIT

| Rota | O que é |
|---|---|
| `POST /graphql` | Endpoint GraphQL real, spec-compliant |
| `GET /graphiql` | IDE interativo pra explorar o schema |

Schema (`server/src/graphqlSchema.js`):

```graphql
type Query {
  health: String
  scenarios: [String]
  scan(projectDir: String!): ScanResult
}

type Mutation {
  runScenario(name: String!, target: String, payload: String): ScenarioResult
}
```

## Rodando em desenvolvimento

```bash
# 1. instalar dependências (uma vez)
cd server && npm install
cd ../client && npm install
cd ../electron && npm install

# 2. buildar o client (o Electron carrega o build, não o dev server)
cd client && npm run build

# 3. abrir o app desktop
cd ../electron && npm start
```

Sem `nodemon` em nenhum passo — o `electron/main.js` sobe a API Express diretamente no processo principal.

## Gerando o instalador/executável

```bash
cd electron

npm run build:win              # instalador NSIS (.exe) para Windows x64
npm run build:win:portable     # pasta portátil com GraphVuln.exe direto, sem instalador
npm run build:linux            # AppImage
npm run build:mac              # DMG (precisa rodar em macOS, ou CI com runner macOS)
```

Cada comando roda `scripts/prebuild.js` automaticamente antes de empacotar — ele copia `server/src` e `client/dist` pra dentro de `electron/vendor/`, porque o `electron-builder` não segue bem caminhos `../` fora da pasta do pacote.

Recomendado: gerar o instalador NSIS (`build:win`) numa máquina Windows real ou via o workflow de CI incluído (`.github/workflows/build.yml`), que builda nos três sistemas operacionais em runners dedicados a cada push. O alvo `build:win:portable` é o mais direto pra testar rapidamente, já que gera o `.exe` sem passar pela etapa de instalador.

## API (Express)

| Rota | Método | Descrição |
|---|---|---|
| `/api/health` | GET | status |
| `/api/scan` | POST `{ projectDir }` | escaneia um diretório de projeto |
| `/api/export/:format` | POST `{ codeFindings, resourceFindings }` | `format` = json \| sarif \| csv \| markdown |
| `/api/scenarios` | GET | lista cenários simuláveis |
| `/api/scenarios/:name` | POST `{ target, payload? }` | roda uma simulação (nunca ataca nada real) |

## Limitações

- O scanner é heurístico (regex), não faz parsing de AST — espera-se falso positivo/negativo, igual qualquer SAST leve. Cobertura maior de casos (snake_case, ofuscação, etc.) exigiria migrar pra um parser real de GDScript.
- O simulador de cenários (`attackSimulator.js`) é só descrição estruturada de impacto hipotético — não executa nada contra um alvo real (`success: false` sempre, `simulationMode: true` sempre). Serve pra documentar impacto num laudo, não como ferramenta de exploração ativa.
- A geração do instalador NSIS é mais confiável em Windows nativo ou CI do que via `electron-builder` rodando em Linux — prefira `build:win:portable` ou o workflow de GitHub Actions para builds reprodutíveis.
