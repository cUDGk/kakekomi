# kakekomi 仕様書

> **改訂版 (2026-05-15)**: 初版設計レビューで識別した 5 個の致命的穴を安全側に全倒しで修正した版。
> 変更点サマリ:
> - 通報者鍵を廃止 → 双方向通信は **code-derived symmetric key** 方式に変更 (通報者の鍵管理負担ゼロ)
> - PDF/Office 受信を **v1 では拒否** (メタ除去の漏れ穴対策)
> - PoW を **サーバ側のみ**で実施 → ブラウザ JS 完全撤廃、Tor Browser "Safest" モードで送信可能
> - timing/size オラクル対策を MUST 化
> - go-libtor 同梱はオプション、デフォルトは外部 tor 推奨

## 1. 製品コンセプト

個人ジャーナリスト/弁護士/監査人が **30 分以内** に自前の **匿名通報窓口** を立てるための、Go 単一バイナリ製 OSS。

ゴール: 「シンプルにセキュリティを高く」。機能を足さず、削る事で攻撃面を最小化する。

## 2. 設計原則

1. **削減主義**: 機能を足すよりも削る。攻撃面の最小化こそ最大のセキュリティ機能。
2. **デフォルトで最強**: 設定を弄らずとも安全に動く。弱める方向のみオプトイン。
3. **書かない情報は漏れない**: ログ・IP・UA・Referer などを一切記録しない。
4. **平文を残さない**: ディスク上の通報内容はすべて age 暗号化済み。
5. **シンプルな UI**: 通報者画面は 3 つだけ。装飾なし、外部リソースゼロ、JavaScript ゼロ。
6. **項目は受信者が自由定義**: フォームは config 駆動、全項目 optional がデフォルト。
7. **通報者に何も保管させない**: 鍵もファイルも持たせない。7 語のコードだけ。

## 3. 機能要件

### 3.1 通報受信 (MUST)

| ID | 要件 |
|---|---|
| F-01 | Tor Hidden Service v3 経由で通報フォームを公開できる |
| F-02 | 受信した通報内容は age 暗号化してディスクに保存する |
| F-03 | 通報者は BIP39 (英単語) 7 語のコードを受け取り、再訪・追加情報送信・返信受信できる |
| F-04 | 添付ファイルは v1 で **画像 (jpg/png/webp/gif/heic) と plain text (.txt) のみ受け付ける** |
| F-05 | 添付画像の EXIF / XMP / ICC を除去する (画像のみなので包括的に対応可能) |
| F-06 | 通報 1 件ごとに **サーバ側 PoW** を要求 (ブラウザ JS 不要) |
| F-07 | TTL を超えた通報は自動削除される |
| F-08 | 双方向通信は **code-derived symmetric key** で行う (通報者は鍵を持たず、コードだけで返信を復号できる) |

### 3.2 設定 (MUST)

| ID | 要件 |
|---|---|
| F-10 | フォーム項目は `kakekomi.yaml` で受信者が自由定義できる |
| F-11 | 全項目のデフォルトは optional (`required: true` 明示時のみ必須) |
| F-12 | デフォルト設定では「通報内容」フィールドのみ必須 |
| F-13 | 項目タイプ: text / textarea / select / date / checkbox / number |
| F-14 | `kakekomi config validate` で構文・論理エラーを検出 |
| F-15 | 項目の追加・削除・並び替えがすべて可能 |
| F-16 | `receiver.public_key` のハッシュを `config/pubkey.lock` に pinning し、起動時に照合 |

### 3.3 受信者ダッシュボード (MUST)

| ID | 要件 |
|---|---|
| F-20 | 別の .onion v3 (Client Authorization 付き) で公開 |
| F-21 | ログインは **パスフレーズ (KDF 復号鍵) + TOTP** |
| F-22 | 通報一覧は ID / 受信日時 / サイズ (固定 bucket に丸めて表示) のみ |
| F-23 | 暗号化 blob (.tar.age) を DL できる |
| F-24 | 受信者は **コードを入力して返信文を投稿** する (コードから対称鍵を導出してサーバが暗号化保存) |
| F-25 | 通報の削除を手動で行える |

### 3.4 鍵・秘密情報の管理 (MUST)

| ID | 要件 |
|---|---|
| F-30 | `kakekomi init` で age 鍵ペアを生成 |
| F-31 | 受信者の age **秘密鍵**はサーバに保存しない (init 時に提示、即削除) |
| F-32 | TOTP secret / 管理者パスフレーズハッシュ / Tor Client Auth 秘密鍵 は **受信者パスフレーズ由来 KDF (argon2id) で派生したキーで age 暗号化** してディスク保存、起動時にパスフレーズ入力で in-memory 復号 |
| F-33 | 鍵ローテーションコマンドあり (旧 blob は旧鍵でアクセス可能) |

### 3.5 タイミング・サイズ対策 (MUST)

| ID | 要件 |
|---|---|
| F-50 | コード照合は **constant-time compare** + 失敗/成功に **固定 wait (500ms ± jitter)** を入れる |
| F-51 | 全ての通報受信レスポンスは固定 wait + 固定長 padding (4 KiB ブロック単位) で正規化 |
| F-52 | tarball は age 暗号化前に **PKCS#7-style block padding (64 KiB 倍数)** を入れる |
| F-53 | inbox の各通報サイズ表示は **対数バケット (例: <100KB, 100KB-1MB, 1-10MB, >10MB)** に丸める |

### 3.6 CLI (MUST)

| ID | コマンド |
|---|---|
| F-40 | `kakekomi init`           — 鍵生成 + .onion 発行 + パスフレーズ設定 + config 雛形 |
| F-41 | `kakekomi run`            — 起動時にパスフレーズを stdin から読み、メモリ展開 |
| F-42 | `kakekomi config validate` |
| F-43 | `kakekomi rotate-key` |
| F-44 | `kakekomi gc` |
| F-45 | `kakekomi version` |

### 3.7 やらない事 (MUST NOT)

| ID | 禁止事項 |
|---|---|
| F-X1 | IP アドレスをログに残さない |
| F-X2 | UserAgent / Referer を記録しない |
| F-X3 | アクセスログを一切出力しない (エラーログのみ stderr) |
| F-X4 | 外部 CDN / Web フォント / GA / 解析ツールを読み込まない |
| F-X5 | **JavaScript を一切配信しない** (通報者画面/受信者画面ともに) |
| F-X6 | 通報内容をサーバ上で復号しない (UI に「閲覧」ボタンを作らない) |
| F-X7 | 通報者の Cookie / LocalStorage を残さない (通報者画面は完全 stateless) |
| F-X8 | 受信者の age 秘密鍵をサーバに保存しない |
| F-X9 | **PDF / Office / SVG / 動画 / 音声を受信しない** (v1) — メタ除去の漏れ穴を排除 |
| F-X10 | `Server` / `X-Powered-By` 等のフィンガープリント可能なヘッダを返さない |

### 3.8 セキュリティヘッダ (MUST)

全レスポンスに以下を付与:

```
Cache-Control: no-store
Pragma: no-cache
Content-Security-Policy: default-src 'none'; img-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: interest-cohort=(), camera=(), microphone=(), geolocation=()
```

`Server` ヘッダは削除。

### 3.9 SHOULD

| ID | 要件 |
|---|---|
| S-01 | i18n: 日本語 / 英語 (v1) |
| S-02 | Honeypot フィールド対応 (簡易ボット検出) |
| S-03 | 受信者向け通知 (Tor 経由 webhook のみ、平文通知は禁止) |
| S-04 | 添付ファイル名の自動ハッシュ化 (元名は中身の暗号化済み JSON 内のみに保存) |
| S-05 | 再現可能ビルド (GitHub Actions) + SBOM |
| S-06 | Tor の guard discovery 対策 (vanguards-lite 相当を tor の torrc で設定する手順を docs 化) |

### 3.10 MAY (将来)

| ID | 要件 |
|---|---|
| M-01 | 多受信者 (組織内の複数ジャーナリストで受信) |
| M-02 | PDF / Office 受信 (mat2 を外部 subprocess で叩く実装が安定したら) |
| M-03 | SaaS 版 (運営型) — ★ 別レイヤとして開発、本リポでは扱わない |
| M-04 | 公益通報者保護法準拠の証跡管理モード (別プロダクト) |

## 4. UI 仕様

### 4.1 通報者画面 (公開 .onion)

JavaScript **ゼロ**。Tor Browser "Safest" モード (JS off) で完全動作する。

#### `/` (トップ)

```
┌────────────────────────────────────────┐
│                                        │
│  通報窓口                              │
│                                        │
│  [config.site.intro の本文]            │
│                                        │
│  [ 通報を始める ]                      │
│                                        │
│  すでにコードをお持ちの方 → /reply     │
│                                        │
└────────────────────────────────────────┘
```

#### `/submit` (送信フォーム)

- config.yaml の `fields` を動的レンダリング (サーバサイドのみ)
- `required: true` の項目のみアスタリスク
- 送信フローは pure HTML form の POST
  1. 通報者がフォーム送信
  2. サーバが PoW チャレンジ付き中間ページを返す (最初の送信が PoW なし → サーバが challenge を発行 → 通報者がフォーム再 submit で nonce 含む)
  3. サーバ側で PoW 検証 (実態: hashcash 風 hash の検証 — 通報者は計算する必要なし、サーバが「短時間内に再送できる総数」を hash chain で抑制)
  4. /done へ遷移

> 補足: 「サーバ側 PoW」とは、通報者にブラウザで計算させるのではなく、**サーバ側で時間窓 × 累積コスト** を強制する方式 (token bucket + hash puzzle ハイブリッド)。JS 不要で no-JS 通報者を切り捨てない。

#### `/done` (完了)

```
┌────────────────────────────────────────┐
│  ✓ 通報を受け付けました                │
│                                        │
│  あなたのコード:                       │
│  ┌────────────────────────────────┐    │
│  │ ocean marble pencil ladder     │    │
│  │ thunder hollow spring          │    │
│  └────────────────────────────────┘    │
│                                        │
│  ⚠ このコードを紙にメモして保管して    │
│    ください。サーバには保存されません。 │
│    紛失すると追加通報・返信受信が      │
│    できなくなります。                  │
│                                        │
└────────────────────────────────────────┘
```

★ 鍵ファイル DL は **廃止**。通報者は 7 語のコードだけ覚えれば返信が読める (コードから対称鍵を導出する方式)。

#### `/reply` (再訪)

- コード入力欄 1 つ
- 入力後:
  - 受信者からの返信があれば **その場でサーバが復号して表示** (★ 例外的にサーバ復号する箇所。これは通報者→サーバ→通報者で完結し、サーバ運営者でもコード自体を知らなければ復号できない設計のため許容)
  - 追加通報フォーム (`/submit` と同じ動的フォーム) も同居

  ★ 重要: コードから導出した対称鍵による暗号化のため、**サーバが保持するのは暗号化済み blob のみ**。サーバ運営者が blob を読むには通報者のコードが必要 (= 通報者の協力なしには読めない)。「コードはサーバに保存されない (argon2id ハッシュのみ)」が前提条件。

### 4.2 受信者画面 (.onion v3 + Client Auth)

JavaScript **ゼロ**。

#### `/admin` ログイン

- パスフレーズ + TOTP のみ
- ログイン失敗時は **理由を返さない** (アカウント存否を漏らさない) + 失敗 / 成功で **同じ wait time**

#### `/admin/inbox` 受信箱

```
┌───────────────────────────────────────────────────┐
│ ID         受信日時          サイズ帯    状態     │
├───────────────────────────────────────────────────┤
│ a3f9...   2026-05-15 09:22  小 (<1MB)   未読     │
│ 7c01...   2026-05-14 22:11  小 (<1MB)   既読     │
│ ...                                               │
└───────────────────────────────────────────────────┘
```

- 本文プレビューなし
- サイズは bucket 表示 (F-53)
- ID クリック → `/admin/case/:id`

#### `/admin/case/:id`

- メタ情報 (受信時刻、サイズ帯、TTL) のみ表示
- 「暗号化 blob (.tar.age) を DL」 ボタン
- 大きい警告: 「★ このサーバ上で開かないこと。手元の端末で `age -d -i secret.age tarball.age` してください」

#### `/admin/reply/:id`

- **受信者が通報コードを入力** + 返信文を入力
- サーバ側で `HKDF(code)` から対称鍵を導出 → 返信文を暗号化して保存
- 受信者が通報コードを知っていることが前提 (受信した暗号化 tarball を開いて中の "code" フィールドを取り出す or 通報者が再訪した時にコードを記録しておく)

  ★ 設計の含意: 「受信者は通報を一度復号する」プロセスが必要。これは v1 では受信者の手元 PC を信頼するという妥協 (THREAT_MODEL §3 で out of scope 宣言済み)。

### 4.3 デザイン規約

- カラー: 背景 `#fafafa` / 文字 `#1a1a1a` / アクセント `#1f6feb` (1 色のみ)
- フォント: `font-family: ui-sans-serif, system-ui, -apple-system, sans-serif` のみ
- 角丸: なし or 2px 固定
- アニメーション: なし
- 影: なし
- レスポンシブ: mobile-first, `max-width: 720px`
- ダークモード: v1 では未対応 (固定テーマで指紋を減らす)
- **JavaScript: ゼロ**
- `<noscript>` 不要 (そもそも JS を配信しない)

## 5. 設定ファイル仕様

### 5.1 必須キー

- `receiver.public_key` (init で自動投入)
- `tor.ingress_onion_dir`

### 5.2 pubkey pinning

- `init` 完了時に `config/pubkey.lock` に `sha256(receiver.public_key)` を書く
- `run` 起動時に config の public_key と lock を照合、不一致なら **起動拒否** (config 改竄検出)
- 鍵ローテーション時は `rotate-key` コマンドで lock も更新

### 5.3 デフォルト動作

すべての設定にコード内デフォルトあり。`kakekomi.yaml` が無くても `kakekomi init` で雛形が生成される。

### 5.4 検証

- `kakekomi config validate` でスキーマ + 論理検証
- 危険な設定 (例: ログ有効化、retention 無限、PDF 受信オプトイン) は **エラー** (警告ではない)

### 5.5 ホットリロード

- v1 では未対応 (config 変更時は `kakekomi run` を再起動)

## 6. 非機能要件

- 起動時間: < 2 秒 (Tor 起動含むと別途 + 20〜60 秒)
- メモリ: < 100 MB アイドル時
- 配布: 単一バイナリ
  - linux/amd64
  - linux/arm64
  - darwin/arm64
  - windows/amd64
- 依存ランタイム: なし (外部 tor モード時は tor のみ)

## 7. 監査・配布

- 第三者監査を受けるまで `v1.0.0` を切らない
- 起動時バナーに **"EXPERIMENTAL - NOT YET AUDITED"** を常時表示 (v1.0.0 まで)
- リリースバイナリは GitHub Actions で再現可能ビルド (`-trimpath -buildvcs=true -ldflags='-buildid='`)
- SBOM (CycloneDX) を release artifact に同梱
- リリースタグは GPG 署名
- 全リリースに SHA-256 を README とリリースノートの両方に併記

## 8. ライセンス

**AGPL-3.0**

## 9. 開発フェーズ

- **Phase 0** (現在): 設計文書 (THREAT_MODEL / ARCHITECTURE / SPEC)
- **Phase 1**: 骨組み実装 — `init` + `run` + テキスト通報のみ (Tor 統合前、localhost で動作)
- **Phase 2**: 添付 (画像のみ) + メタデータ除去
- **Phase 3**: Tor 統合 (外部 tor を control port 経由で操作)
- **Phase 4**: 受信者ダッシュボード + 通報コード再訪
- **Phase 5**: code-derived 双方向通信 + retention + GC
- **Phase 6**: timing/size 正規化 + サイズバケット + pubkey pinning
- **Phase 7**: go-libtor 同梱モードをオプションで追加
- **Phase 8**: RC + 第三者監査依頼
- **Phase 9**: v1.0.0 リリース

## 10. リポジトリ構成 (予定)

```
kakekomi/
├── THREAT_MODEL.md
├── ARCHITECTURE.md
├── SPEC.md
├── README.md             # 実装後に書く
├── LICENSE               # AGPL-3.0
├── go.mod / go.sum
├── cmd/kakekomi/main.go
├── internal/
│   ├── server/           # HTTP layer
│   ├── crypto/           # age wrapper + HKDF(code)
│   ├── store/            # SQLite + blob
│   ├── tor/              # 外部 tor control + (option) go-libtor
│   ├── stripper/         # 画像メタ除去のみ
│   ├── pow/              # サーバ側 token bucket + hash chain
│   ├── config/           # YAML loader + validator + pubkey pinning
│   └── timing/           # constant-time + 固定 wait + padding
├── web/
│   └── templates/        # html/template のみ (static/ は空 or 数 KB の CSS のみ)
├── examples/
│   └── kakekomi.example.yaml
└── .github/workflows/
    └── release.yml       # 再現可能ビルド + SBOM
```
