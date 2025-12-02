# MVP vens v0.1.0 — Plan de test rapide (manuel)

Objectif: vérifier que la CLI charge `config.yaml`, indexe les SBOMs, lit un input Trivy et produit un fichier de sortie (MVP minimal), sans encore brancher les scores OWASP dans le VEX.

## Pré-requis
- Go 1.24+
- Accès LLM configuré si vous voulez aller au-delà (facultatif pour l’instant). La génération des scores est un no-op en MVP.

## Jeux de données fournis
- `examples/mvp/config.yaml` — OWASP scores/facteurs par PURL (sans version; la version est ignorée au chargement).
- `examples/mvp/sbom.cdx.json` — SBOM CycloneDX minimal contenant des composants avec PURL.
- `examples/mvp/trivy.json` — Échantillon d’output Trivy minimal.

## Commande de test
1) Build (optionnel si vous utilisez `go run`):
```
go build -o _output/bin/vens ./cmd/vens
```

2) Exécution (produit `_output/vex_mvp.json`):
```
go run ./cmd/vens \
  generate \
  --config-file examples/mvp/config.yaml \
  --sboms examples/mvp/sbom.cdx.json \
  examples/mvp/trivy.json \
  _output/vex_mvp.json
```

Attendu dans les logs:
- "Config loaded" avec le nombre d’entrées OWASP > 0
- "SBOM libraries indexed" avec un compte > 0

Note: la sortie JSON peut être vide en MVP (le branchement des scores OWASP dans le VEX sera fait dans une étape ultérieure).

## Check-list rapide (5 minutes)
- Cas nominal: la commande ci-dessus s’exécute sans erreur et crée `_output/vex_mvp.json`.
- Cas erreur: modifiez `examples/mvp/config.yaml` pour mettre `score: 90` → la CLI doit échouer avec un message "score must be between 0 and 81".
- Cas normalisation: changez une clé en `pkg:npm/lodash@4.17.21` → la version est ignorée, la clé est normalisée en `pkg:npm/lodash` (pas d’erreur).
