# Falco CTF App Conventions

正典は AGENTS.md。ここには **絶対に外せないキーガード** だけを再掲する。

## Key Guards

- scoreboard / auth-policy / ttyd / challenge image の tag は **同一 git SHA** で push
- scoreboard は **replica 1 + strategy: Recreate** 固定 (SQLite 並行書込不可)
- challenges/ は **scoreboard と同一 repo** に置く(falco-rule.yaml が scoreboard 一次消費)
- challenge コンテナの Dockerfile に Service / Ingress を生やさない
- ttyd Dockerfile の USER は **1000 (非 root)**。kubectl 同梱は CTF 仕様
- Kustomize の `base/` は環境非依存。host / domain は placeholder のみ
- image tag を `latest` で本番 deploy しない (git SHA pin)

## Security

- `.env` / kubeconfig / `*.key` / `*.pem` / `*.db` は絶対にコミットしない
- Dockerfile / yaml にトークンや実シークレットを焼き込まない
- 課題用ダミー値 (`P@ssw0rd`, `flag{...}`) は LOW 扱い、明確にダミーと示す
- `git add .` / `git add -A` 禁止

## Scope

- `scoreboard/` 変更 → 採点ロジック直結。`POST /falco/events` の payload 規約を変えるなら
  platform 側 chart にも同時 PR
- `auth-policy/` 変更 → セキュリティ境界。`X-Auth-Request-Email` 解釈を緩めない
- `challenges/<NN>-<slug>/` 変更 → その課題のみ影響
- `images/{ttyd,challenge}/` 変更 → 全ユーザ環境に影響
- `deploy/<app>/base/` 変更 → 全環境影響。`overlays/<env>/` は当該環境のみ
