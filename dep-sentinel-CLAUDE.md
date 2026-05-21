# CLAUDE.md — Dep Sentinel

> Briefing pour reprendre ce projet dans une nouvelle session Claude ou Claude Code.
> Lis ce fichier **en entier** avant d'écrire la moindre ligne.

---

## 1. Le projet en une phrase

**Dep Sentinel** audite tes dépendances Go **en local, hors-ligne, sans API payante** : CVEs connues via `govulncheck` et la base OSV (téléchargeable), licences incompatibles, modules abandonnés, et mises à jour disponibles. C'est le plus simple des 5 agents — environ 1 journée de code.

---

## 2. Relation avec l'écosystème

Dep Sentinel est le **5e agent**, le plus indépendant. Il **n'a pas besoin** de Git Archaeologist ni de Blast Radius pour fonctionner. Il écrit ses propres tables `dep_*` dans la DB partagée si elle existe, ou dans sa propre SQLite sinon.

Optionnellement, il peut croiser avec Blast Radius : si un module vulnérable est utilisé dans une zone à fort risk score, l'alerte monte en priorité.

Tables lues dans archaeo (optionnel) : `meta` (pour le chemin du repo).
Tables lues dans blast (optionnel) : `blast_metrics` pour pondérer les CVEs.

---

## 3. Sources de données (toutes gratuites et offline)

| Source | Ce qu'elle donne | Comment l'utiliser |
|---|---|---|
| **`govulncheck`** | CVEs pour les modules Go | Binary officiel Google, gratuit, `go install golang.org/x/vuln/cmd/govulncheck@latest` |
| **Base OSV** | Base de CVEs open source téléchargeable | `https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip` — JSON, téléchargeable une fois par jour |
| **`go list -m -json all`** | Liste complète des modules avec versions | Standard Go toolchain, pas de dépendance externe |
| **SPDX license list** | Catalogue des licences connues | Fichier JSON public, bundlé dans le binaire |
| **`pkg.go.dev` API** | Dernière version disponible d'un module | `https://proxy.golang.org/{module}/@latest` — gratuit, pas d'auth |

Pour le mode **full offline** (pas d'accès réseau) : la base OSV est téléchargée une fois et mise en cache localement. `govulncheck` peut tourner entièrement offline si le module cache Go est chaud.

---

## 4. Ce que Dep Sentinel détecte

### CVE / vulnérabilités
- Lance `govulncheck ./...` et parse sa sortie JSON
- Fallback : cherche dans la base OSV téléchargée localement si `govulncheck` n'est pas installé
- Sévérité : CVSS score si disponible, sinon `critical/high/medium/low` depuis OSV

### Licences
- Extrait la licence de chaque module via `go list -m -json all` + lecture du fichier `LICENSE`
- Compare contre une liste de licences incompatibles avec usage commercial ou avec l'OSS : `AGPL-3.0`, `GPL-2.0`, `GPL-3.0`, `SSPL`, `Commons Clause`
- Licences permissives OK : `MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `MPL-2.0`

### Modules abandonnés
- Critères : dernier commit > 2 ans ET pas de version stable (< v1.0.0) ET > 0 CVE
- Source : `pkg.go.dev` API pour la dernière activité

### Mises à jour disponibles
- Compare la version utilisée vs la dernière stable via `proxy.golang.org`
- Signal : majors disponibles (breaking changes potentiels) séparés des mineures

---

## 5. Schema SQLite (`dep_*`)

```sql
CREATE TABLE dep_modules (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    path          TEXT NOT NULL UNIQUE,
    version       TEXT NOT NULL,
    latest_version TEXT,
    license       TEXT,
    license_ok    INTEGER NOT NULL DEFAULT 1,  -- 0 si licence problématique
    last_commit_ts INTEGER,
    is_abandoned  INTEGER NOT NULL DEFAULT 0,
    direct        INTEGER NOT NULL DEFAULT 1   -- 0 si dépendance transitive
);

CREATE TABLE dep_vulnerabilities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    module_id   INTEGER NOT NULL REFERENCES dep_modules(id),
    vuln_id     TEXT NOT NULL,      -- ex: "GO-2024-1234" ou "CVE-2024-1234"
    severity    TEXT NOT NULL,
    cvss_score  REAL,
    summary     TEXT NOT NULL,
    fixed_in    TEXT,               -- version qui corrige, si connue
    blast_risk  REAL NOT NULL DEFAULT 0  -- copié depuis blast_metrics si dispo
);
CREATE INDEX idx_dep_vuln_sev ON dep_vulnerabilities(severity, cvss_score DESC);

CREATE TABLE dep_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

---

## 6. Les 3 outils MCP

| Tool | Input | Output |
|---|---|---|
| `vulnerability_report` | `min_severity?` ('critical'/'high'/'medium'/'low') | CVEs triées par sévérité × blast_risk, avec version de fix si connue |
| `license_audit` | — | Modules avec licence problématique ou inconnue |
| `outdated_modules` | `major_only?` | Modules avec mises à jour disponibles, majors en priorité |

---

## 7. Layout du projet

```
cmd/
  dep/             CLI : `dep scan | vulns | licenses | outdated`
  dep-mcp/         Binaire MCP stdio
internal/
  store/           DB layer — peut ouvrir une DB archaeo existante OU créer la sienne
  scanner/         Orchestre govulncheck + go list + proxy.golang.org
  vulns/           Parse sortie govulncheck + base OSV locale
  licenses/        Détection et classification des licences
  modules/         Versions actuelles vs latest, abandoned detection
  mcpserver/       Les 3 outils MCP
data/
  licenses.json    SPDX license list bundlée (pas de téléchargement requis)
```

---

## 8. Décisions architecturales

| Décision | Raison |
|---|---|
| **`govulncheck` comme source principale** | Officiel Google, précis, sait quelle version corrige. Pas de faux positifs sur les CVEs qui ne s'appliquent pas à ton code. |
| **Fallback OSV JSON** | Si `govulncheck` pas installé ou pas de Go toolchain. La base OSV est téléchargeable une fois et cachée. |
| **DB propre possible** | Dep Sentinel est le seul agent qui peut tourner sans Git Archaeologist. Un utilisateur peut l'utiliser standalone sur n'importe quel repo Go avec un `go.mod`. |
| **Proxy.golang.org pour les versions** | Gratuit, pas d'auth, cache CDN mondial, supporte les modules privés via `GOPROXY` env var. |
| **Licences AGPL en rouge** | Une dépendance AGPL dans un SaaS = obligation de publier ton code source. Beaucoup d'équipes l'ignorent. |

---

## 9. Pièges à anticiper

- **`govulncheck` a besoin que le module soit téléchargé** — si le module cache Go est froid (premier run), il peut faire des requêtes réseau. En mode strict offline, utiliser uniquement la base OSV.
- **Les modules privés** — `go list -m -json all` peut échouer sur des modules privés sans `GONOSUMCHECK`/`GOFLAGS` appropriés. Dégrader gracieusement : skip les modules privés plutôt que de crasher.
- **Les remplacements `go.mod`** — `replace` directives peuvent pointer vers des forks locaux. Parser `go.mod` directement pour les détecter et les signaler séparément.
- **AGPL-3.0 vs AGPL-3.0-only vs AGPL** — les identifiants SPDX ont des variantes. Normaliser vers l'identifiant SPDX canonique avant de classifier.
- **`govulncheck` output format** peut changer entre versions. Toujours parser le JSON (`govulncheck -json ./...`), pas le texte.
- **Logs sur stderr uniquement** dans `dep-mcp`.
- **Rate limiting sur `proxy.golang.org`** — pour un `go.mod` avec 200 dépendances, espacer les requêtes ou les batcher.

---

## 10. État initial

Rien n'est implémenté. Ordre de construction (1 journée estimée) :
1. `internal/store` + schéma
2. `internal/scanner` + `internal/vulns` — govulncheck + fallback OSV
3. `internal/modules` — go list + proxy.golang.org
4. CLI `dep scan` + `dep vulns`
5. `internal/licenses`
6. `internal/mcpserver` — 3 outils

---

## 11. Commandes utiles

```bash
# Standalone (sans archaeo)
dep scan --dir /path/to/go/project
dep vulns --dir /path/to/go/project --min-severity high
dep licenses --dir /path/to/go/project
dep outdated --dir /path/to/go/project --major-only

# Avec DB archaeo partagée
dep scan --repo /path/to/repo   # lit .archaeo/index.db, y écrit dep_*

dep-mcp --repo /path/to/repo
# ou standalone :
dep-mcp --dir /path/to/go/project
```

---

## 12. Comment reprendre

1. Lis ce fichier en entier.
2. Vérifie que `govulncheck` est installé : `go install golang.org/x/vuln/cmd/govulncheck@latest`.
3. Commence par `internal/scanner` + `internal/vulns` — c'est la valeur principale.
4. Mets à jour ce fichier si tu découvres un piège.
