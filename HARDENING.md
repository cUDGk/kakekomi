# kakekomi ハードニング (Defense-in-Depth)

> このドキュメントは「設計の穴を塞ぐ」より一段深い、**多層防御** の仕様。
> SPEC.md / ARCHITECTURE.md が「何を作るか」、本ファイルは「**それを各レイヤでどう硬くするか**」。
>
> 想定読者: 実装者 + 運用者 (受信者本人)。

## 0. 防御層の俯瞰

| 層 | 攻撃面 | 主な防御 |
|---|---|---|
| L0: 暗号 | 鍵漏洩・サイドチャネル・暗号危殆化 | domain-separated HKDF / メモリ mlock / アルゴリズム versioning / 90 日鍵ローテ |
| L1: プロセス | プロセスメモリダンプ・core dump・特権昇格 | systemd hardening / `mlock` / no-core / DynamicUser / SystemCallFilter |
| L2: ファイルシステム | 押収・残留データ | LUKS/BitLocker 必須 / `secrets.age` / data_dir noatime / shred ガベコレ |
| L3: ネットワーク | 受動観測・能動 MITM・DoS | Tor v3 full onion / vanguards-lite / IntroDoSDefense / IPAddressDeny |
| L4: HTTP | フィンガープリント・タイミング・サイズ | 固定 wait / 固定 padding / strict CSP / no keep-alive / `Server` 除去 |
| L5: 受信者端末 | 復号後の漏洩 | `kakekomi viewer` (air-gap モード) / Qubes/Tails 推奨 / 鍵 USB |
| L6: ビルド | サプライチェーン・改竄バイナリ | reproducible build / SLSA L3 / cosign 署名 / vendored deps |
| L7: 配布 | 偽バイナリ・古いバージョン | GPG 署名タグ / SHA-256 in README / SBOM |
| L8: 運用 | 押収状態の通知・暴露 | warrant canary / security.txt / 暗号化バックアップ |

---

## L0: 暗号衛生

### L0.1 domain-separated HKDF

すべての派生鍵に **独立した info ラベル** を入れる。同じ素材から複数鍵を派生する時に、ラベルが違えば鍵も独立 (info を string として固定):

```go
const (
    hkdfReplyKey   = "kakekomi/v1/reply-key"          // 通報者⇔受信者の返信
    hkdfMasterKey  = "kakekomi/v1/master-key"          // パスフレーズ→秘密保護
    hkdfChallenge  = "kakekomi/v1/pow-challenge"       // サーバ側 PoW
    hkdfSessionTok = "kakekomi/v1/admin-session-token" // 受信者ログインセッション
    hkdfBlobNonce  = "kakekomi/v1/blob-nonce-prefix"   // ChaCha20-Poly1305 nonce
)
```

label に **必ずバージョン (`/v1/`) を含める**。v2 で algorithm 変える時に label も `/v2/` に上げると、旧 v1 鍵と衝突しない。

### L0.2 メモリ保護

#### mlock
鍵素材を保持するメモリ領域は **`mlock`** (Linux) / `VirtualLock` (Windows) で swap 出禁:

```go
import "golang.org/x/sys/unix"

func protect(buf []byte) error {
    return unix.Mlock(buf)
}
```

対象: `master_key`、`reply_key` 一時バッファ、age 復号後の age identity 一時バッファ、TOTP secret、admin passphrase ハッシュ材料。

#### memguard
plain `[]byte` の零クリアは Go GC の都合で確実に消えない。**`github.com/awnumar/memguard`** を使う:

```go
buf := memguard.NewBufferRandom(32)
defer buf.Destroy()  // zero化 + munmap 確定
```

#### 明示零クリア (memguard 不要な軽量箇所)
`crypto/subtle` + 手動 zero loop。Go コンパイラの DCE を回避するため `runtime.KeepAlive` を最後に置く。

### L0.3 アルゴリズム versioning

すべての暗号化済み blob に **versioned ヘッダ** を付ける:

```
| magic "KKK1" (4B) | version (2B) | reserved (2B) | payload (age envelope) |
```

- `version=1`: age (X25519+ChaCha20-Poly1305) + HKDF-SHA256
- `version=2` (将来): post-quantum (HPKE-X25519+ML-KEM-768 + ChaCha20-Poly1305)
- 復号時に version をディスパッチ → 旧 blob は旧コードで読める (永久互換)

### L0.4 鍵ローテーション (forward secrecy 簡易版)

完全な FS は実装が重いので、**90 日強制ローテ** で妥協:

| 鍵 | ローテ頻度 | 旧鍵の扱い |
|---|---|---|
| 受信者 age 鍵 | 90 日 | 旧鍵で暗号化された blob は復号可能 (read-only) |
| master_key (パスフレーズ KDF) | パスフレーズ変更時のみ | 旧 master で暗号化された秘密を新 master で再暗号化 |
| Tor Hidden Service 鍵 | 推奨 365 日 | .onion アドレスが変わる (受信者が再配布) |

`kakekomi rotate-key --age` で 90 日ローテ。`config validate` で「鍵が 90 日超え」を **エラー** に。

### L0.5 constant-time / 副作用なし操作チェックリスト

- コード照合: `crypto/subtle.ConstantTimeCompare`
- pubkey 照合: 同上
- HMAC 検証: 同上
- ループは秘密値長に依存させない (固定長操作)
- branch on secret 禁止
- table lookup with secret index 禁止 (キャッシュサイドチャネル)

### L0.6 ChaCha20-Poly1305 nonce 管理

reply.bin の nonce は **ランダム 96bit** で十分 (1 件あたり 1 メッセージ前提、再利用なし)。
ただし AEAD nonce 再利用は致命的なので、暗号化前に nonce 衝突チェック (SQLite UNIQUE 制約 + 失敗時は再生成リトライ最大 3 回、それでもダメなら fail-stop)。

### L0.7 RNG

すべて `crypto/rand` のみ。`math/rand` を import 禁止 (lint で禁止):

```go
//go:build !test
// +build !test

package main

import _ "crypto/rand" // OK
// import _ "math/rand" // 禁止: lint で reject
```

---

## L1: プロセス / OS ハードニング

### L1.1 systemd unit

`deploy/systemd/kakekomi.service` 参照。要点:

- `DynamicUser=yes` (動的 UID、ホストに永続化なし)
- `ProtectSystem=strict` + `ProtectHome=yes` + `ReadWritePaths=<data_dir>` のみ書ける
- `CapabilityBoundingSet=` (空) + `NoNewPrivileges=yes`
- `SystemCallFilter=@system-service` + 危険 syscall を `~` で除外
- `IPAddressDeny=any` + `IPAddressAllow=localhost` (Tor 以外への外向き通信を禁止)
- `MemoryDenyWriteExecute=yes` (JIT 防止 — Go ランタイムは互換性あり)
- `LockPersonality=yes` / `RestrictRealtime=yes` / `RestrictNamespaces=yes`
- `LimitCORE=0` (core dump 禁止)
- `MemoryMax=512M` / `TasksMax=64` / `LimitNPROC=64` (リソース枯渇耐性)

### L1.2 core dump 無効化

systemd 経由でない実行でも core dump を出さないようプロセス内で:

```go
import "golang.org/x/sys/unix"
unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
```

これにより `gcore` も拒否、`/proc/<pid>/mem` も読めなくなる (root 以外)。

### L1.3 ptrace 拒否

```go
unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)  // ptrace も拒否される副作用あり
```

### L1.4 ファイルパーミッション

| パス | 所有者 | パーミッション |
|---|---|---|
| `<data_dir>/` | kakekomi | 0700 |
| `<data_dir>/kakekomi.db` | kakekomi | 0600 |
| `<data_dir>/blob/**` | kakekomi | 0600 |
| `<data_dir>/config/secrets.age` | kakekomi | 0600 |
| `<data_dir>/config/receiver.pub` | kakekomi | 0644 |
| `<data_dir>/tor/admin/client_auth/` | kakekomi | 0700 |

起動時に **umask 0077** を強制、ファイル作成時に mode を明示。

### L1.5 LUKS / BitLocker 必須

- README / init wizard の最初に「**フルディスク暗号化が有効でないサーバには絶対に install しないでください**」と警告
- `kakekomi init` 時に `/etc/crypttab` (Linux) を確認、無ければ **警告 + 確認入力を要求**

### L1.6 atime 無効化

`<data_dir>` をマウントする際に `noatime` で。アクセス時刻の漏洩を防ぐ。

### L1.7 シェル履歴

`kakekomi init` 中にパスフレーズを引数で受け取らない (stdin のみ)。bash 履歴に残らないよう徹底。

---

## L2: ファイルシステム / 残留データ

### L2.1 シュレッダ削除

`gc` コマンドで通報削除時:
1. ファイルサイズと同サイズの 0x00 で上書き
2. fsync
3. unlink

(SSD 上は完全消去にならないが、cold cache / kernel page cache レベルの痕跡は減らせる。完全性は FDE に依存する設計)

### L2.2 SQLite VACUUM

通報削除後に SQLite の `VACUUM INTO` で空き領域を解放 (SQLite ファイル内の旧データ残痕を消す)。

### L2.3 tmpfs / RAM disk オプション

`<data_dir>` を tmpfs (RAM disk) に置く運用モードを docs で案内。電源断で全消える代わりに、押収時もディスク残留なし。

---

## L3: ネットワーク / Tor

### L3.1 torrc

`deploy/tor/torrc.example` 参照。要点:

- `HiddenServiceVersion 3` (v2 は使わない、deprecated)
- **single onion service ではなく full onion** (`HiddenServiceSingleHopMode 0` 暗黙)
- `HiddenServiceMaxStreams 32` + `HiddenServiceMaxStreamsCloseCircuit 1`
- `HiddenServiceEnableIntroDoSDefense 1` (Tor 0.4.7+)
- `HiddenServicePoWDefensesEnabled 1` (Tor 0.4.8+) — Tor 層の PoW
- vanguards-lite: `GuardLifetime 60 days` / `HSLayer2Guards 4` / `HSLayer3Guards 8`
- `SocksPort 0` (server-only モード、SOCKS は出さない)
- `SafeLogging 1` (ログに onion アドレスを書かない)

### L3.2 IntroDoSDefense + Tor PoW

Tor 自体が onion service 層で PoW を実装している (0.4.8+)。kakekomi 側の application PoW と二重で抑止する。

### L3.3 受信者 .onion の Client Authorization

`admin.onion` は **必ず** Client Auth 鍵を要求:
- `HiddenServiceDir/authorized_clients/<name>.auth` に受信者公開鍵を配置
- 受信者の Tor Browser に対応する秘密鍵を入れる
- 鍵を持たない第三者は admin.onion の存在すら証明できない (descriptor 取得自体が暗号化された鍵交換を要求)

### L3.4 出方向通信の全遮断

kakekomi プロセスは外部に出ない (DNS / HTTP / NTP 一切なし):
- systemd `IPAddressDeny=any` で強制
- アプリ内で `http.DefaultTransport` への http.RoundTripper を **nil 化** (もし誤って http.Get 等を書いても fail close)
- 時刻は内部時計のみ、NTP は OS に任せる

### L3.5 onion アドレスの公開チャネル

kakekomi の責務ではないが、docs で:
- 公開チャネル (Keybase / Twitter / 名刺) で .onion を周知する時は **複数チャネルで同じアドレス** を出すよう案内
- onion アドレスは固定値なので、初回公開以降は不変 (鍵ローテ時のみ変わる)

### L3.6 HTTP keep-alive 禁止

`Connection: close` を全レスポンスに付与。
理由: 同一 TCP 上の連続リクエストはタイミング相関しやすい。1 リクエスト 1 接続で circuit isolation を強化。

```go
srv := &http.Server{
    Handler:    h,
    SetKeepAlivesEnabled: func() { /* no-op */ },
}
srv.SetKeepAlivesEnabled(false)
```

### L3.7 HTTP/2 / HTTP/3 無効化

Tor over .onion では HTTP/1.1 だけで十分。HTTP/2 / 3 のフィンガープリント面を増やさない。
`http.Server{TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}` で HTTP/2 を明示無効。

---

## L4: HTTP / アプリケーション

### L4.1 セキュリティヘッダ (完全版)

```
Cache-Control: no-store, no-cache, must-revalidate, max-age=0, private
Pragma: no-cache
Expires: 0
Content-Security-Policy:
  default-src 'none';
  img-src 'self';
  style-src 'self';
  form-action 'self';
  frame-ancestors 'none';
  base-uri 'none';
  require-trusted-types-for 'script';
  upgrade-insecure-requests
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: interest-cohort=(), camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
X-Robots-Tag: noindex, nofollow, noarchive, nosnippet
```

- **`Server` ヘッダは削除** (`net/http` のデフォルト挙動を上書き)
- `X-Powered-By` は出さない
- `Date` ヘッダは秒単位に丸める

### L4.2 リクエストサイズ制限 (slowloris / memory bomb 対策)

```go
srv := &http.Server{
    ReadHeaderTimeout: 5 * time.Second,    // slowloris 対策
    ReadTimeout:       30 * time.Second,
    WriteTimeout:      30 * time.Second,
    IdleTimeout:       1 * time.Second,    // keep-alive 無効と組み合わせ
    MaxHeaderBytes:    8 * 1024,           // ヘッダ最大 8KiB
    Handler:           h,
}
// body は handler 側で http.MaxBytesReader で制限
```

通報 POST: 合計 `attachments.max_total_size_mb` まで。
管理 POST: 1 MiB まで。

### L4.3 goroutine 上限

シンプルに `Server.Handler` の前にセマフォを置く:

```go
sem := make(chan struct{}, 64)  // 同時 64 接続まで
handler := func(w http.ResponseWriter, r *http.Request) {
    select {
    case sem <- struct{}{}:
        defer func() { <-sem }()
        inner.ServeHTTP(w, r)
    default:
        w.WriteHeader(503)
    }
}
```

### L4.4 ディスク容量上限

`<data_dir>/blob/` のサイズが `quota.total_gb` を超えたら 503 を返す (旧通報を勝手に消さない、受信者の判断に委ねる)。

### L4.5 固定 padding / 固定 wait

| エンドポイント | 固定 wait | レスポンス padding |
|---|---|---|
| `POST /submit` | 1000ms + 0〜200ms jitter | 4 KiB ブロック単位 |
| `POST /reply` (コード検証) | 500ms + 0〜100ms jitter | 4 KiB ブロック単位 |
| `POST /admin/login` (成功/失敗とも) | 1500ms + 0〜200ms jitter | 4 KiB ブロック単位 |

padding は HTML コメントとして `<!-- pad: AAAAAAAA... -->` を末尾に挿入。

### L4.6 CSRF

- 全 POST に hidden double-submit token を要求
- token はサーバ側の HMAC(session_id || form_id || rand) で発行
- session_id を持たない通報者画面でも、challenge token と一体化して機能

### L4.7 セッション (受信者管理画面のみ)

- Cookie: `kakekomi_admin_session=<random_64B>`
- 属性: `HttpOnly; Secure; SameSite=Strict; Path=/admin; Max-Age=900` (15 分)
- セッションストアは **in-memory のみ** (再起動で全 invalidate)
- アイドル 15 分で自動失効
- ログアウト時に明示的に invalidate + zero 化

### L4.8 入力バリデーション

- YAML 設定: 既知キーのみ許可 (`yaml.KnownFields(true)`)
- フォーム入力: max_length を超えたら 400
- ファイル MIME: マジックバイトで検査 (`net/http.DetectContentType` + 独自 sniffer)、拡張子だけで信用しない
- ファイル名: ASCII 英数 + `_.-` のみ許可 (元名は中身 JSON に保存)

### L4.9 エラーレスポンスの均質化

- 4xx は全て同じ HTML テンプレ + 同じサイズで返す
- 内部エラー詳細は **絶対** クライアントに見せない
- stderr ログにユーザ入力を含めない (ログから ReDoS 等で復元されないよう)

---

## L5: 受信者端末 / Air-gap viewer

### L5.1 `kakekomi viewer` CLI

サーバとは別の **viewer モード** バイナリ:

```
kakekomi viewer decrypt --identity ~/.age/key.txt --in case-data.tar.age --out ./out/
```

仕様:
- **ネットワーク機能ゼロ** (build tag `airgap` で `net` import を除外)
- stdin / stdout / ファイル I/O のみ
- 復号 → tar 展開 → 平文ディレクトリ書き出し
- 監査用にハッシュも表示

build:
```
go build -tags airgap -trimpath -ldflags="-s -w" -o kakekomi-viewer ./cmd/viewer
```

### L5.2 推奨プラットフォーム

docs で以下を案内:

1. **Qubes OS DispVM**: 一度だけ使う使い捨て VM で復号
2. **Tails OS** + 暗号化永続ボリュームに秘密鍵を保管、復号は Tails の amnesic 環境で
3. **Air-gapped Raspberry Pi**: ネットワーク機能を物理的に殺した Pi + USB で blob を運ぶ

最低限の妥協ライン:
4. 受信者の日常 PC で復号 (これは v1 では out of scope の妥協、THREAT_MODEL §3 参照)

### L5.3 鍵 USB 戦略

受信者の age 秘密鍵:
- LUKS で暗号化した USB に保管
- バックアップは Shamir's Secret Sharing で 3-of-5 分散 (`kakekomi backup-key --shamir 3of5`)
- 秘密鍵の平文ファイルは絶対に作らない (パイプ経由で `age -d -i -`)

### L5.4 Panic / Duress モード

- TOTP secret を **2 つ生成** する: 通常用 + duress 用
- duress TOTP でログインした場合、サーバは:
  - すぐに `<data_dir>/blob/` を shred 削除
  - `secrets.age` を削除
  - SQLite を VACUUM して 0 埋め
  - `/var/log/kakekomi/panic.flag` を作って `exit 0`
- 受信者が「強制的にログインさせられた」シーンでこっそり全データ消去できる
- 既知制約: バックアップを取っていれば復活可能 (これは意図された挙動)

---

## L6: ビルドハードニング

### L6.1 reproducible build

```yaml
# .github/workflows/release.yml
- name: Build
  env:
    CGO_ENABLED: '0'
    GOFLAGS: '-trimpath -buildvcs=true'
    SOURCE_DATE_EPOCH: ${{ env.SDE }}
  run: |
    go build \
      -trimpath \
      -buildvcs=true \
      -ldflags="-s -w -buildid= -X main.version=$GITHUB_REF_NAME" \
      -tags 'netgo osusergo' \
      -o kakekomi ./cmd/kakekomi
```

### L6.2 SLSA Level 3 provenance

`actions/attest-build-provenance` で GitHub Actions の build provenance attestation を生成。リリースに `.intoto.jsonl` を同梱。

### L6.3 cosign / sigstore 署名

```
cosign sign-blob --yes --output-signature kakekomi.sig kakekomi
```

verify:
```
cosign verify-blob --certificate-identity-regexp='^https://github.com/<org>/kakekomi/.github/workflows/release.yml@refs/tags/v.*' --certificate-oidc-issuer='https://token.actions.githubusercontent.com' --signature kakekomi.sig kakekomi
```

### L6.4 vendored dependencies

```
go mod vendor
git add vendor/
```

理由: go.sum hash 検証 + go mod proxy への依存を切る。タグから直接ビルドできる。

### L6.5 dependency 監査

- 直接依存は **20 個未満** に保つ目標
- 各依存を docs/DEPS.md に「なぜ必要か」「何を代替したか」を書く
- `govulncheck` を CI で必須化
- `dependabot.yml` で patch アップデートのみ自動 PR

### L6.6 Fuzzing

Go 1.18+ の native fuzzing で:

- multipart parser
- YAML config loader
- tar reader
- code (BIP39) parser
- age envelope wrapper

CI で 60 秒 fuzz、リリース前に 1 時間 fuzz。

---

## L7: 配布ハードニング

### L7.1 リリース成果物

各リリースに同梱:
- `kakekomi-<version>-<os>-<arch>` バイナリ
- `kakekomi-<version>-<os>-<arch>.sha256`
- `kakekomi-<version>-<os>-<arch>.sig` (cosign)
- `kakekomi-<version>-<os>-<arch>.intoto.jsonl` (SLSA)
- `SBOM.cdx.json` (CycloneDX)
- `SHA256SUMS` (全バイナリのハッシュ一覧、GPG 署名付き)

### L7.2 README 表記

- 各バイナリの SHA-256 を README に直接記載
- `git tag -s` (GPG 署名タグ) のみリリース対象
- リリースノートに provenance verify コマンドを書く

### L7.3 init wizard でのバイナリ検証

`kakekomi init` 起動時に自分自身のハッシュを表示:
```
This binary: kakekomi 0.5.0
  SHA-256:  abc123...
  
Please verify this matches the README on GitHub before continuing.
Continue? [y/N]
```

---

## L8: 運用ハードニング

### L8.1 Warrant Canary

`docs/canary.txt.example`:

```
I, <受信者名>, hereby state that as of <DATE>:

- I have NOT received any National Security Letter, FISA court order,
  or other classified government request that would require me to share
  data from kakekomi.
- I have NOT been compelled to backdoor kakekomi or any of its keys.

This statement is signed with my GPG key <FINGERPRINT> and will be
refreshed monthly. If this statement disappears or fails to refresh,
treat it as a signal that the above conditions may no longer hold.

Date: <DATE>
Signed: <GPG signature>
```

毎月再署名する運用、`<data_dir>` 内のファイルではなく **別系統で公開** する。

### L8.2 security.txt

`.well-known/security.txt`:

```
Contact: mailto:<受信者>@<domain> (PGP only)
Encryption: https://<domain>/pgp.txt
Preferred-Languages: ja, en
Expires: 2027-01-01T00:00:00.000Z
Acknowledgments: https://<domain>/security/credits
```

### L8.3 暗号化バックアップ

`kakekomi backup --out /mnt/usb/kakekomi-backup-2026-05-15.tar.age` コマンド:
- `<data_dir>` 全体を tar
- 受信者 age 公開鍵 + 第二の独立公開鍵 (separation of duties) で多重暗号化
- バックアップから復元するには両方の秘密鍵が必要

### L8.4 ディスク交換時の責務

サーバ移行 / ディスク交換時:
- 旧ディスクは物理破壊 (SSD は秘密鍵がレベルウェアリングで複数セルに分散している可能性)
- BitLocker / LUKS で暗号化されていても物理破壊する

---

## L9: 反フィンガープリント / 反メタデータ

### L9.1 /submit ページの注意書き

通報フォームの上部に固定で:

```
⚠ 安全のためのお願い:
- 文章の言い回しから個人を特定される可能性があります。普段書かない文体で書く、
  または別ツールで文章をリライトしてから貼り付ける事を検討してください。
- 時刻や曜日を本文に書くとタイムゾーンが推定されます。
- 写真は EXIF を除去しても、カメラ固有の PRNU パターンで撮影機種を識別できる
  事があります。第三者の撮影写真や、十分に古い写真を使う事を推奨します。
```

### L9.2 ロケール処理

- `Accept-Language` ヘッダは無視 (フィンガープリント低減)
- UI 言語は **URL クエリ `?lang=ja|en` のみ**、cookie には保存しない
- デフォルトは config の `site.default_lang`

### L9.3 タイムスタンプ丸め

- SQLite の `created_at` は **1 時間単位に丸める** (秒精度で書かない)
- 受信者の inbox 表示も時間粒度に丸める
- audit log (もしあれば) は日単位

### L9.4 画像再エンコード

EXIF 削除に加えて、`disintegration/imaging` で **再エンコード** (decode → encode):
- 圧縮プロファイル / 量子化テーブルから機種推定する手法に対して粗いが効く
- ICC profile を sRGB に統一
- ファイルサイズが変わってもいいので、内容は変えずに quality を 90 で再エンコード

### L9.5 onion descriptor 周辺

- `HiddenServiceNumIntroductionPoints` を 3 (デフォルト) で固定 — 増減で間接的な fingerprint になりうる
- `HiddenServiceDescriptorRefreshInterval` (Tor 内部値) はデフォルトのまま

---

## L10: 強度プロファイル (config)

`security.profile` を 1 つだけ用意:

```yaml
security:
  profile: paranoid   # paranoid のみ (v1 では他のプロファイルを用意しない)
```

「paranoid 以外を提供する」と弱い設定を選ぶ受信者が出るので **本リリースでは paranoid 固定**。docs で「他の設定は v2 以降で慎重に追加検討する」と明記。

---

## 11. ガチガチ運用チェックリスト (init / 定期)

### 初回セットアップ
- [ ] ホスト OS が最新の patch を当てているか
- [ ] LUKS / BitLocker でフルディスク暗号化されているか
- [ ] swap が暗号化されているか (LUKS swap)
- [ ] `/etc/sysctl.d/99-kakekomi.conf` で `kernel.dmesg_restrict=1` 等を設定したか
- [ ] systemd unit を `deploy/systemd/kakekomi.service` でデプロイしたか
- [ ] tor を `deploy/tor/torrc.example` ベースで設定したか
- [ ] 受信者 age 秘密鍵を サーバから物理的に持ち出したか (USB + LUKS)
- [ ] Shamir backup を 3 箇所に分散したか
- [ ] duress TOTP を別の場所に保管したか
- [ ] warrant canary の初回公開を済ませたか
- [ ] バイナリの cosign / SHA-256 を verify したか

### 毎月
- [ ] warrant canary を再署名・再公開したか
- [ ] `govulncheck` でサーバ上の go バイナリ依存に既知 CVE が無いか確認
- [ ] OS の security update を当てたか
- [ ] tor の version が最新メジャーに追従しているか

### 90 日ごと
- [ ] `kakekomi rotate-key --age` で age 鍵をローテートしたか
- [ ] 鍵ローテ後の旧鍵を別ストレージにアーカイブしたか
- [ ] 暗号化バックアップを 2 系統取ったか

### 鍵漏洩疑いがあった時
- [ ] サーバを停止
- [ ] duress TOTP でログイン (in-band で消すなら、別ホストで再デプロイなら不要)
- [ ] 既存通報を別経路で受信者に引き渡してから shred
- [ ] 新規 `kakekomi init` で別 .onion を立てる
- [ ] 公開チャネルで「旧 .onion は使わないでください」を周知
