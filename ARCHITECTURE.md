# kakekomi アーキテクチャ

## 1. システム構成

```
            [通報者]                                 [受信者]
               │                                        │
               │ Tor Browser                            │ Tor Browser
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
                  │  │ PoW verifier       │  │
                  │  │ metadata stripper  │  │
                  │  │ age encryptor      │  │
                  │  │ TTL GC             │  │
                  │  └────────────────────┘  │
                  └────────────┬────────────┘
                               │
                  ┌────────────┴────────────┐
                  ▼                         ▼
          ┌──────────────┐         ┌────────────────────┐
          │ SQLite       │         │ blob/  (暗号化済)   │
          │ (meta のみ)   │         │  meta.age           │
          │  - case id   │         │  attachments/*.age  │
          │  - timestamp │         └────────────────────┘
          │  - code hash │
          │  - ttl       │
          └──────────────┘
```

## 2. 鍵設計 (envelope encryption)

```
[init 時]
  - age 鍵ペア (X25519) を生成
  - 公開鍵   → サーバ config に焼く
  - 秘密鍵   → 受信者がローカルに保管 (USB / 暗号化ボリューム)
              ★ サーバには絶対に残さない (init コマンドの最後で削除)

[通報受信時]
  1. 受信フォームから body + files をメモリ上で受信
  2. 通報 1 件ごとに対称鍵 K を生成 (実態は age が内部処理)
  3. K で本文+添付を暗号化
  4. K を受信者公開鍵宛に包む
  5. 暗号化済み blob のみディスクへ書き出し
  6. 平文をメモリから zero 化

[受信者読み出し時]
  1. ダッシュボードで暗号化 blob を DL
  2. ★ 手元の端末で age -d で復号 (サーバ上では絶対に復号しない)
  3. UI に「ブラウザで開く」ボタンは置かない
```

## 3. データフロー: 通報送信

```
[通報者]
   │ POST /submit (multipart)
   │   - PoW nonce
   │   - 各フィールド (全 optional がデフォルト)
   │   - 添付ファイル (0..N)
   ▼
[Go サーバ]
   1. PoW 検証 (失敗 → 400)
   2. サイズ・件数チェック
   3. 添付メタデータ除去 (EXIF/XMP/ICC/PDF/Office)
   4. fields(JSON) + files を tar 化
   5. tarball を age で受信者公開鍵宛に暗号化
   6. SQLite に行追加 (case_id, created_at, argon2id(code), expires_at)
   7. 通報者に diceware コード (7 語) を表示
   ▼
[通報者]  コードをメモして離脱
```

## 4. データフロー: 通報再訪 (双方向通信)

```
[通報者]
   │ GET /reply  → コードを入力
   ▼
[Go サーバ]
   1. argon2id(code) を SQLite と照合
   2. 該当 case_id 配下の「受信者からの返信 blob」があれば返す
      → 通報者は手元で age -d で復号
   3. 追加通報を受け付ける → 同じ case_id に追記
```

### 通報者の鍵管理

v1 では **通報者にも age 鍵ペアを発行**:
- 初回 /submit 直後に `your-secret-key.age.txt` を DL させ、コードと共に保管を促す
- 受信者からの返信は通報者の公開鍵で暗号化 → サーバが復号不能
- 完全 E2E (受信者⇔通報者の双方向で平文がサーバに無い)

メリット/デメリット:
- ✅ サーバ押収時に受信者の返信内容も守られる
- ❌ 通報者が秘密鍵を失うと返信を読めない (許容)

## 5. 設定ファイル: kakekomi.yaml

受信者がフォーム項目を **自由に定義** できる。デフォルトはすべて optional。

```yaml
site:
  title: "通報窓口"
  intro: |
    安全に情報をお寄せください。
    身元の入力は不要です。

receiver:
  public_key: "age1..."        # init 時に自動投入
  display_name: "○○新聞 調査報道班"

tor:
  mode: embedded                # embedded | external
  ingress_onion_dir: ./tor/ingress
  admin_onion_dir: ./tor/admin
  admin_client_auth: true       # 受信者ダッシュボードは Client Auth 必須

# ★ ここを受信者が自由に編集する
fields:
  - id: body
    label: "通報内容"
    type: textarea
    required: true              # 唯一のデフォルト必須項目
    max_length: 50000

  - id: subject
    label: "件名 (任意)"
    type: text
    required: false
    max_length: 200

  - id: when
    label: "事案の時期 (任意)"
    type: text
    required: false
    placeholder: "例: 2025年秋頃"

  - id: org
    label: "対象組織 (任意)"
    type: text
    required: false

  # 受信者が項目を増減・並び替え自由
  # 利用可能 type: text | textarea | select | date | checkbox | number

attachments:
  enabled: true
  max_files: 10
  max_size_mb_per_file: 200
  max_total_size_mb: 500
  strip_metadata: true          # EXIF/XMP/PDF/Office メタ除去

security:
  pow_difficulty: 18            # bits, ~ 数秒の計算
  rate_limit_per_ip: false      # Tor 経由なので IP 単位は無意味、PoW で代替

retention:
  default_ttl_days: 90
  on_read_delete: false         # 既読即削除モード (必要なら true)

ui:
  theme: minimal                # minimal のみ v1
  show_powered_by: false
```

### フォーム項目の自由度

- 項目の **追加・削除・並び替え** すべて可能
- `required: true` を付けた項目だけが必須、他はすべて空送信可能
- デフォルトの kakekomi.yaml では `body` だけが必須 → 「とりあえず通報内容だけ書いて送信」できる
- フォーム描画は config から動的生成 (テンプレ非依存)

## 6. UI 設計指針 (くっそシンプル)

### ルール
- 通報者画面は **3 ページ** だけ (`/`, `/submit`, `/done` + `/reply`)
- 受信者画面は **4 ページ** だけ (`/admin`, `/admin/inbox`, `/admin/case/:id`, `/admin/reply/:id`)
- 装飾なし、ボタンは画面ごとに 1 〜 2 個
- フォントは OS 既定のみ (Web フォント禁止 = フィンガープリント低減)
- カラーは 3 色 (背景 / 文字 / アクセント 1 色) のみ
- アニメーション禁止
- 外部リソース完全ゼロ (CDN / GA / フォント / 解析ツール 全て NG)
- JavaScript は PoW 計算のみ (単一ファイル `static/pow.js`、外部読み込みなし)

### Tor Browser 想定
- max-width: 720px
- prefers-color-scheme は無視 (固定テーマ)
- `<noscript>` 用に PoW なしの遅延フォールバックを用意 (ただし PoW なしは難易度 ↑↑ で代替)

## 7. Tor 統合

| 方式 | メリット | デメリット |
|---|---|---|
| **A: go-libtor 同梱** | 単一バイナリで `kakekomi run` 即起動 | バイナリ ~30MB、libtor 更新追従が必要 |
| **B: 外部 tor + control port** | OS の tor を再利用、軽量 | ユーザ側に tor インストールが必要 |

→ **v1 デフォルトは A**、`tor.mode: external` で B に切替可能。

## 8. ストレージレイアウト

```
<data_dir>/
  kakekomi.db                  # SQLite (meta のみ)
  blob/
    <case_id>/
      meta.age                 # fields(JSON) を暗号化
      attachments/
        001.age
        002.age
  tor/
    ingress/hostname           # 公開 .onion v3
    admin/hostname             # 受信者用 .onion (Client Auth 鍵含む)
  config/
    kakekomi.yaml
    receiver.pub               # 公開鍵のみ (秘密鍵はここに置かない)
```

## 9. CLI

```
kakekomi init [--data-dir ./data]    # 鍵生成 + .onion 発行 + config 雛形作成
kakekomi run                          # サーバ起動
kakekomi config validate              # config.yaml の検証
kakekomi rotate-key                   # 鍵ローテーション (旧 blob は旧鍵で読める)
kakekomi gc                           # TTL 切れ通報の削除 (cron 用)
kakekomi version                      # バージョン情報 (SBOM ハッシュ含む)
```

## 10. 技術選定まとめ

| レイヤ | 選定 | 理由 |
|---|---|---|
| HTTP | `net/http` + `go-chi/chi` | 余計な依存なし、単一バイナリ |
| Tor | `berty/go-libtor` 同梱 + 外部 tor フォールバック | 単一バイナリで .onion 即発行 |
| 暗号 | `filippo.io/age` | GPG より誤用しにくいモダン暗号 |
| DB | `modernc.org/sqlite` (pure Go) | CGo 不要、クロスコンパイル容易 |
| メタ除去 | `dsoprea/go-exif` + 独自 PDF/Office stripper | mat2 の Go 版が無いため最小実装 |
| PoW | hashcash 風 (SHA-256 prefix-zeros) | 軽量、JS 実装も容易 |
| パスワードハッシュ | `golang.org/x/crypto/argon2` (argon2id) | 通報コード照合用 |
| 設定 | YAML (`gopkg.in/yaml.v3`) | 受信者が手で編集する想定 |
| ライセンス | **AGPL-3.0** | SaaS 化による囲い込み防止、SecureDrop 精神の継承 |

## 11. リリース戦略

- v0.1.0: ローカルでテキストのみ通報 (Tor 統合前、開発用)
- v0.2.0: 添付ファイル + メタデータ除去
- v0.3.0: Tor 統合 (.onion 発行)
- v0.4.0: 受信者ダッシュボード
- v0.5.0: 通報者⇔受信者の双方向通信
- v0.6.0: PoW + retention + GC
- v0.9.0: 外部監査依頼 (RC)
- v1.0.0: 第三者監査受領後

★ 第三者監査前は README とバイナリ起動時バナーに **"EXPERIMENTAL - NOT YET AUDITED"** を出し続ける。命に関わる領域なので、過剰なくらい慎重に。

## 12. 再現可能ビルド

- GitHub Actions で `-trimpath -buildvcs=true -ldflags="-buildid="` を指定
- SBOM (CycloneDX) を release artifact に同梱
- タグは GPG 署名
- バイナリの SHA-256 を README とリリースノートの両方に記載
