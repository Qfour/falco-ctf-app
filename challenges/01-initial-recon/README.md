# 01 — Initial Recon

NimbusBreach のオープニング。Pod に侵入した attacker が真っ先に
やる事 = **K8s API Server に直接話しかけて環境を探る**。
クラスタ管理 API への接触を Falco が即検知する。

## ゴール (operator view)

Falco ルール `Contact K8S API Server From Container` をユーザ
Namespace で発火させる。Rule の condition: `evt.type=connect` +
`k8s_api_server` macro 一致 + `not k8s_containers` (= 一般 workload
からの connect) + `not user_known_*`。

## 想定解

```bash
curl -sk https://kubernetes.default.svc/api
# あるいは
wget -q -O- --no-check-certificate https://kubernetes.default.svc/api
```

curl が SA token を持たないため認証は失敗 (401) するが、TCP connect
は成立しており、その瞬間に rule が発火する。

## 解説

- K8s API への接触は **正規 workload なら ServiceAccount + 既知の
  controller** から行われる。challenge container のような無 SA の
  pod から **匿名 connect が来ること自体が異常**
- 攻撃者が侵入直後にやる典型 reconnaissance
