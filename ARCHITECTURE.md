# kakekomi アーキテクチャ

> **改訂版 (2026-05-15)** + **ハードニング統合 (2026-05-16)**: 設計レビューで識別した穴を安全側に全倒し、その上で多層防御を統合。実装時のガチガチ運用詳細は `HARDENING.md` を参照 (defense-in-depth の各層、systemd / Docker / torrc の具体)。
> 主要な変更:
> - 通報者鍵を廃止 → **code-derived symmetric key (HKDF(code))** で双方向通信
> - PDF/Office を受信拒否 (v1)、画像と plain text のみ
> - PoW を **サーバ側だけ**で処理、ブラウザに JS を一切配信しない
> - timing/size 正規化を MUST 化
> - go-libtor 同梱は option、デフォルトは外部 tor + control port

## 1. システム構成

```
            [通報者]                                 [受信者]
               │                                        │
               │ Tor Browser (Safest 可)                │ Tor Browser
               ▼                                        ▼
   ┌──────────────────────┐               ┌──────────────────────┐
   │ ingress.onion (v3)   │               │ admin.onion (v3)     │
   │ 公開                  │               │ Client Auth 必須      │
   └──────────────────────┘               └──────────────────────┘
                │                                       │
                └───────────────┬───────────────────────┘
                                ▼
                  ┌─────────────────────────┐
                  │  kakekomi (Go binary)    │
                  │  ┌────────────────────┐  │
                  │  │ HTTP (chi)         │  │
                  │  │ field renderer     │  │
                  │  │ server-side PoW    │  │
                  │  │ image meta stripper│  │
                  │  │ age encryptor      │  │
                  │  │ HKDF(code) cipher  │  │
                  │  │ timing/padding     │  │
                  │  │ TTL GC             │  │
                  │  └────────────────────┘  │
                  └────────────┬────────────┘
                               │
                  ┌────────────┴────────────┐
                  ▼                         ▼
          ┌──────────────┐         ┌─────────────────────────┐
          │ SQLite       │         │ blob/  (暗号化済)        │
          │ (meta のみ)   │         │  case-data.tar.age       │
          │  - case id   │         │  reply-from-receiver.bin │
          │  - timestamp │         │   (HKDF(code) で復号)     │
          │  - code hash │         └─────────────────────────┘
          │  - ttl       │
          └──────────────┘
```

## 2. 鍵設計 — 二層方式

> 鍵運用とメモリ保護の詳細 (mlock / memguard / domain-separated HKDF / 90 日ローテ / アルゴリズム versioning) は HARDENING.md §L0 を参照。

### 2.1 受信者の age 鍵 (envelope encryption)

**用途**: 通報者→受信者の片方向通信 (通報本文・添付)

```
[init 時]
  - age 鍵ペア (X25519) を生成
  - 公開鍵   → サーバ config に焼く + sha256 を config/pubkey.lock に pin
  - 秘密鍵   → 受信者がローカルに保管 (USB / 暗号化ボリューム)
              ★ サーバには絶対に残さない

[通報受信時]
  1. 受信フォームから body + 添付をメモリ上で受信
  2. fields(JSON) + 画像/テキストファイル を tar にまとめる
  3. tar に PKCS#7-style block padding (64 KiB 倍数) を追加
  4. tar を age で受信者公開鍵宛に暗号化 → case-data.tar.age
  5. 平文を即 zero 化

[受信者読み出し時]
  1. ダッシュボードで暗号化 blob を DL
  2. ★ 手元の端末で age -d で復号
  3. UI には「ブラウザで開く」ボタンを置かない
```

### 2.2 通報コードから派生する対称鍵 (HKDF)

**用途**: 受信者→通報者の双方向通信 (返信)

通報者には鍵を持たせない。代わりに 7 語の **コードそのものから対称鍵を毎回派生** する。

```
code           = "ocean marble pencil ladder thunder hollow spring"  (BIP39 7 語)
salt           = case_id (公開、ランダム)
reply_key      = HKDF-SHA256(code, salt, "kakekomi/v1/reply", 32 bytes)

[受信者が返信を投稿する時]
  - 受信者は手元で復号した tarball 内の "code" フィールドからコードを取り出す
    (★ または通報者が再訪した時にコードを記録しておく)
  - 受信者は /admin/reply/:id で「コード + 返信文」を入力
  - サーバは HKDF(code) で reply_key を導出
  - 返信文を ChaCha20-Poly1305 で暗号化 → reply.bin に保存
  - reply_key をメモリから zero 化

[通報者が再訪して返信を読む時]
  - 通報者は /reply でコードを入力
  - サーバは argon2id(code) で SQLite と照合 (通報者の正当性確認)
  - 一致したらサーバは HKDF(code) で reply_key を導出
  - reply.bin を復号して通報者に表示
  - reply_key をメモリから zero 化

★ 重要な特性
  - サーバはコードを「知らない」(ハッシュしか持たない)
  - 受信者の age 秘密鍵が漏れても、返信内容は読まれない (HKDF 独立)
  - サーバが押収されても、コードが分からなければ返信は復号不能
  - 通報者は鍵ファイルの管理が不要 (7 語覚えるだけ)
```

### 2.3 受信者の運用秘密 (KDF + age)

TOTP secret / 管理者パスフレーズハッシュ / Tor Client Auth 秘密鍵 などサーバが必要とする秘密:

```
[init 時]
  - 受信者がパスフレーズを設定
  - master_key = argon2id(passphrase, random_salt, mem=1GB, time=4, threads=4)
  - 秘密情報を age (symmetric mode, master_key 由来 X25519) で暗号化してディスク保存
  - master_key をメモリから zero 化

[run 起動時]
  - kakekomi run が stdin からパスフレーズを読む
  - master_key を派生
  - 秘密情報を in-memory 復号
  - master_key を zero 化
  - in-memory 平文は process lifetime のみ保持、stop で消える
```

これにより、停止中サーバの押収で TOTP secret や Tor Client Auth 鍵が漏れない。

## 3. データフロー: 通報送信

```
[通報者]
   │ GET /submit
   ▼
[サーバ]
   1. ランダム challenge token を発行 (cookie ではなく HTML 内 hidden field)
   2. フォームを返す (JS なし)
   ▼
[通報者]
   │ POST /submit (multipart, hidden challenge token 含む)
   │   - 各フィールド (全 optional がデフォルト)
   │   - 添付ファイル 0..N (画像/テキストのみ許可)
   ▼
[サーバ]
   1. challenge token の検証 (時間窓 + 1 回限り + 累積コスト)
   2. PoW (hash chain) 検証 — サーバ側でハッシュチェーンを進めるコストを払う
      → 同一 onion service 上での連続送信を抑制 (DoS 対策)
   3. サイズ・件数・MIME チェック (PDF/Office/SVG/動画/音声は 415 で拒否)
   4. 画像メタ除去 (EXIF/XMP/ICC)
   5. fields(JSON) + 添付 + code を tar 化 → padding → age 暗号化
   6. SQLite に行追加 (case_id, created_at, argon2id(code), expires_at)
   7. 固定 wait (500ms + jitter) 後にレスポンス
   8. レスポンスは固定長 padding (4 KiB 単位)
   9. 通報者に BIP39 7 語のコードを表示
   ▼
[通報者]  コードをメモして離脱 (鍵ファイル DL なし)
```

## 4. データフロー: 通報再訪・返信読み出し

```
[通報者]
   │ GET /reply → コード入力フォーム (HTML)
   ▼
[通報者]
   │ POST /reply (コード入力)
   ▼
[サーバ]
   1. argon2id(code) を SQLite の code_hash と照合 (constant-time)
   2. 失敗/成功ともに固定 wait
   3. 一致した case_id を取得
   4. reply.bin が存在すれば:
      - HKDF(code, case_id) → reply_key
      - reply.bin を ChaCha20-Poly1305 復号
      - 平文返信を画面に表示
      - reply_key を即 zero 化
   5. 追加通報フォームを同居表示
```

## 5. 設定ファイル: kakekomi.yaml

受信者がフォーム項目を **自由に定義** できる。デフォルトはすべて optional。

```yaml
site:
  title: "通報窓口"
  intro: |
    安全に情報をお寄せください。
    身元の入力は不要です。

receiver:
  public_key: "age1..."            # init 時に自動投入
  display_name: "○○新聞 調査報道班"

tor:
  mode: external                   # external (推奨) | embedded
  control_port: 9051               # external 時のみ
  cookie_auth_file: /var/run/tor/control.authcookie
  ingress_onion_dir: ./tor/ingress
  admin_onion_dir: ./tor/admin
  admin_client_auth: true

# ★ ここを受信者が自由に編集する
fields:
  - id: body
    label: "通報内容"
    type: textarea
    required: true                 # 唯一のデフォルト必須項目
    max_length: 50000

  - id: subject
    label: "件名 (任意)"
    type: text
    required: false
    max_length: 200

  # 受信者が項目を増減・並び替え自由
  # 利用可能 type: text | textarea | select | date | checkbox | number

attachments:
  enabled: true
  max_files: 10
  max_size_mb_per_file: 50
  max_total_size_mb: 200
  allowed_mime:                    # ★ v1 はこれだけ
    - image/jpeg
    - image/png
    - image/webp
    - image/gif
    - image/heic
    - text/plain
  strip_metadata: true             # 画像メタ (EXIF/XMP/ICC) を除去

security:
  pow:
    enabled: true
    mode: server_side              # ブラウザ JS なし
    target_cost_ms: 2000           # サーバ側ハッシュチェーンの目標コスト
  honeypot_field: true
  pubkey_lock: ./config/pubkey.lock

retention:
  default_ttl_days: 90
  on_read_delete: false

ui:
  theme: minimal                   # v1 は minimal のみ
  show_powered_by: false
```

### フォーム項目の自由度

- 項目の **追加・削除・並び替え** すべて可能
- `required: true` を付けた項目だけが必須、他はすべて空送信可能
- デフォルトの kakekomi.yaml では `body` だけが必須
- フォーム描画は config から動的生成 (テンプレ非依存)

## 6. UI 設計指針 — JavaScript ゼロ

- 通報者画面は **3 ページ** (`/`, `/submit`, `/done`) + `/reply`
- 受信者画面は **4 ページ** (`/admin`, `/admin/inbox`, `/admin/case/:id`, `/admin/reply/:id`)
- **JavaScript を一切配信しない** (Tor Browser "Safest" モード対応)
- 装飾なし、ボタンは画面ごとに 1〜2 個
- フォントは OS 既定のみ (Web フォント禁止 = フィンガープリント低減)
- カラーは 3 色 (背景 / 文字 / アクセント 1 色) のみ
- アニメーション禁止
- 外部リソース完全ゼロ
- CSS は self-hosted の数 KB のみ
- `Cache-Control: no-store` 全レスポンス
- `Server` ヘッダなし

## 7. Tor 統合

| 方式 | デフォルト | メリット | デメリット |
|---|---|---|---|
| **external + control port** | ✅ v1 default | OS の tor の security update を自動享受。プロセス分離で kakekomi 側クラッシュが Tor に波及しない | ユーザに `apt install tor` を強いる |
| **go-libtor 同梱** | option | 単一バイナリで `kakekomi run` 即起動 | tor の security update のたびに再ビルド・再リリースが必要 = 維持コスト高 |

v1 default を external にした理由: tor の security update 追従の責務を OS パッケージマネージャに委譲する方が、kakekomi メンテナの怠惰によるユーザのリスクが減るため。

### Tor 運用ベストプラクティス

`docs/tor-hardening.md` (将来作成) で以下を案内:

- `HiddenServiceVersion 3`
- `HiddenServiceMaxStreams 64`
- `HiddenServiceMaxStreamsCloseCircuit 1`
- vanguards-lite (Tor 0.4.7+ で built-in、要 enable)
- 受信者 .onion は `HiddenServiceAuthorizeClient` で Client Authorization 必須化

### 7.1 暗号化 blob のフォーマット (versioned)

すべての暗号化 blob は以下の固定ヘッダで始まる:

```
| magic "KKK1" (4B) | version (2B, BE) | reserved (2B, 0x0000) | payload (age) |
```

- `version=1`: age (X25519 + ChaCha20-Poly1305) + HKDF-SHA256
- 復号時に version を見て分岐 → 旧 version も永久に読める (post-quantum など将来移行時に新 version を追加するだけ)

## 8. ストレージレイアウト

```
<data_dir>/
  kakekomi.db                  # SQLite (meta のみ)
  blob/
    <case_id>/
      case-data.tar.age        # fields(JSON) + 添付 を age 暗号化
      reply.bin                # 受信者からの返信 (HKDF(code) で暗号化)
  tor/
    ingress/hostname           # 公開 .onion v3
    admin/hostname             # 受信者用 .onion
    admin/client_auth/         # Client Authorization 鍵 (KDF 派生キーで暗号化)
  config/
    kakekomi.yaml
    receiver.pub               # 公開鍵のみ
    pubkey.lock                # sha256(receiver.pub) の固定値
    secrets.age                # TOTP secret / admin passphrase hash / Tor auth 等を KDF 派生キーで暗号化
```

## 9. CLI

```
kakekomi init [--data-dir ./data]    # 鍵生成 + .onion 発行 + パスフレーズ設定 + config 雛形
kakekomi run                          # stdin からパスフレーズ読み込み → in-memory 復号 → サーバ起動
kakekomi config validate              # config.yaml の検証
kakekomi rotate-key                   # 鍵ローテーション (旧 blob は旧鍵で読める)
kakekomi gc                           # TTL 切れ通報の削除 (cron 用)
kakekomi version                      # バージョン情報 (SBOM ハッシュ含む)
kakekomi backup --out PATH            # 暗号化バックアップ (受信者鍵 + 第二鍵で多重暗号化)
kakekomi backup-key --shamir 3of5     # 受信者秘密鍵を Shamir's Secret Sharing で分散
```

### 9.1 別バイナリ: kakekomi-viewer (air-gap モード)

```
kakekomi-viewer decrypt --identity ~/.age/key.txt --in case-data.tar.age --out ./out/
```

- build tag `airgap` 付きで `net` import を除外してビルド
- ネットワーク機能ゼロ、stdin/stdout/ファイル I/O のみ
- Qubes DispVM / Tails / 物理 air-gap PC で動作する事を想定

## 10. 技術選定まとめ

| レイヤ | 選定 | 理由 |
|---|---|---|
| HTTP | `net/http` + `go-chi/chi` | 余計な依存なし、単一バイナリ |
| Tor (default) | 外部 tor + `bine` (control port) | security update 追従を OS に委譲 |
| Tor (option) | `berty/go-libtor` | 単一バイナリ運用したい人向け |
| age 暗号 | `filippo.io/age` | モダン、誤用しにくい |
| HKDF / 対称暗号 | `golang.org/x/crypto/hkdf` + `golang.org/x/crypto/chacha20poly1305` | code-derived reply key |
| DB | `modernc.org/sqlite` (pure Go) | CGo 不要 |
| メタ除去 | `dsoprea/go-exif` + `disintegration/imaging` で再エンコード | **画像のみ**なので包括的対応可能 |
| PoW | 自前: hash chain (SHA-256) + token bucket | サーバ側のみ、JS 不要 |
| パスワードハッシュ | `golang.org/x/crypto/argon2` (argon2id) | コード照合 + master_key 派生 |
| 設定 | YAML (`gopkg.in/yaml.v3`) | 受信者が手で編集する想定 |
| Diceware | BIP39 英単語リスト (2048 語) | 入力ミス耐性が高い、国際的に枯れている |
| ライセンス | **AGPL-3.0** | SaaS 化による囲い込み防止 |

## 11. リリース戦略

- v0.1.0: ローカルでテキストのみ通報 (Tor 統合前、開発用)
- v0.2.0: 画像/テキスト添付 + メタデータ除去
- v0.3.0: Tor 統合 (external tor + control port)
- v0.4.0: 受信者ダッシュボード
- v0.5.0: code-derived 双方向通信 + retention
- v0.6.0: PoW + timing/size 正規化 + pubkey pinning
- v0.7.0: secrets.age (KDF 派生キー) で TOTP/管理者秘密保護
- v0.8.0: go-libtor 同梱モード (option)
- v0.9.0: RC + 外部監査依頼
- v1.0.0: 第三者監査受領後

★ v1.0.0 まで README + バイナリ起動時バナーに **"EXPERIMENTAL - NOT YET AUDITED"** を出し続ける。

## 12. 再現可能ビルド

- GitHub Actions で `-trimpath -buildvcs=true -ldflags="-buildid="` を指定
- SBOM (CycloneDX) を release artifact に同梱
- タグは GPG 署名
- バイナリの SHA-256 を README とリリースノートの両方に記載
