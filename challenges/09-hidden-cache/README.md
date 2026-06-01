# 09 — Hidden Cache

機密ファイルを別場所に hardlink で確保しておく defense-evasion 手口。
オリジナルが rotate / 削除されても、hardlink 経由で **同じ inode に
アクセス可能** な状態を維持する。Falco は sensitive file への
hardlink 作成を直接検知。

## ゴール

`/etc/shadow` 等の sensitive file に対する hardlink を作成して
`Create Hardlink Over Sensitive Files` を発火させる。

## 想定解

```bash
ln /etc/shadow /tmp/.cache.bak
# 確認:
ls -la /tmp/.cache.bak   # → リンク数 2 / 内容は /etc/shadow と同一
```

## 解説

- hardlink は **同じ inode を指す追加の path**。元ファイルが
  unlink されても inode の参照カウントが 0 にならない限り内容は残る
- 攻撃者: credential rotate / log rotate 対策として hardlink で
  「自分用コピー」を確保 (file event 監査を回避するため hardlink を
  使うのも常套手口)
- 本番防御: sensitive file の hardlink 作成を阻止 (`nofollow` mount
  option / SELinux / AppArmor / Falco)
