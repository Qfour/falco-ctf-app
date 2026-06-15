# ミッション画像の置き場

各ミッションの図・スクリーンショットはここに置く:

```
docs/assets/missions/<NN>-<slug>/*.png   (例: 01-initial-recon/flow.png)
```

`gen-pages.sh` がビルド時にこのディレクトリの画像を拾い、対応する
ミッションページの先頭に自動で差し込む(ファイル名順)。`<NN>-<slug>` は
リポジトリ root の `challenges/<NN>-<slug>/` と一致させること。

画像を 1 枚も置かなくてもページ・PDF は生成される(画像なしで出るだけ)。
