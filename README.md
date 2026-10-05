# tightlip

Plugin Claude Code giúp model không thấy secret. Tên lấy từ *tight-lipped* (kín miệng): Claude vẫn làm việc với project của bạn nhưng không được thấy key, token hay mật khẩu. Repo này vừa là marketplace (tên `vntrungld`) vừa chứa plugin (tên `tightlip`).

| Hook | Làm gì |
|---|---|
| `SessionStart` | Đặt tên phiên mới theo thư mục, ví dụ `teeinblue-backend 10-04 16:15`. Mục đích là để Claude Code không gửi prompt đầu tiên cho model nhỏ đặt tên phiên, vì request đó chạy trước khi hook kịp chặn. |
| `UserPromptSubmit` | Chặn prompt có secret. Ngay sau khi chốt chặn cuối kích hoạt, prompt kế tiếp cũng bị chặn một lần để nhắc bạn. |
| `PreToolUse` | Chặn từ trước các lệnh và file chắc chắn làm lộ secret: `env`, `echo $DB_PASSWORD`, `gh auth token`, `kubectl get secret -o yaml`, `~/.ssh/id_*`, `~/.aws/credentials`... Đồng thời chặn mọi Write/Edit/Bash/MCP có chứa placeholder `[REDACTED:...]`. |
| `PostToolUse` | Che secret trong output của mọi tool bằng `updatedToolOutput`. Cấu trúc JSON giữ nguyên. |
| `PostToolBatch` | Chốt chặn cuối trước mỗi request lên model. Nếu kết quả nào còn secret (thường là output của lệnh bị lỗi, loại hook không sửa được), nó dừng vòng lặp. |

Plugin chỉ chạy hook, không thêm gì vào context của model, nên không tốn token. Cần Claude Code ≥ 2.1.121 và Python ≥ 3.8 (chỉ dùng thư viện chuẩn).

## Cài qua marketplace

**1. Đưa repo lên git host.** GitHub private cũng được. Ví dụ: `github.com/<ban>/tightlip`.

**2. Cài trong Claude Code:**

```
/plugin marketplace add <ban>/tightlip
/plugin install tightlip
```

Hoặc chạy từ shell:

```bash
claude plugin marketplace add <ban>/tightlip
claude plugin install tightlip
```

Nếu có marketplace khác cũng chứa plugin tên `tightlip`, hãy dùng id đầy đủ `tightlip@vntrungld`.

Nếu chưa muốn push lên đâu, có thể cài thẳng từ thư mục: `claude plugin marketplace add ./tightlip`. Với cách này, hook chạy thẳng từ thư mục repo (dù Claude Code vẫn tạo một bản copy trong `~/.claude/plugins/cache/`), nên sửa `tightlip.py` xong thì lần gọi hook kế tiếp đã dùng code mới, không cần tăng version hay update. Riêng khi sửa `hooks.json` thì cần mở phiên mới.

**3. Chỉnh tùy chọn (nếu cần):** chạy `/plugin configure tightlip@vntrungld`, hoặc vào `/config`.

| Tùy chọn | Mặc định | Tác dụng |
|---|---|---|
| `name_sessions` | bật | Đặt tên phiên theo thư mục (xem giới hạn 2) |
| `quiet` | tắt | Không hiện dòng thông báo mỗi khi có che |
| `block_dotenv` | tắt | Chặn hẳn việc đọc `.env` thay vì che (vẫn cho đọc `.env.example`) |
| `allow_regex` | trống | Giá trị khớp toàn bộ regex này sẽ không bị che, ví dụ dữ liệu test |

**4. Phát hành bản mới:** tăng `version` trong `plugins/tightlip/.claude-plugin/plugin.json` rồi push. Nếu không tăng version, người dùng sẽ không nhận được bản mới. Phía người dùng chạy `claude plugin update tightlip@vntrungld`, hoặc bật auto-update trong `/plugin` → Marketplaces.

### Dùng cho cả team

Thêm đoạn sau vào `.claude/settings.json` của repo dự án:

```json
{
  "extraKnownMarketplaces": {
    "vntrungld": { "source": { "source": "github", "repo": "<ban>/tightlip" } }
  },
  "enabledPlugins": { "tightlip@vntrungld": true }
}
```

Khi mỗi người trust thư mục dự án, marketplace sẽ được đăng ký tự động, nhưng mỗi người vẫn phải chạy `/plugin install` một lần. Muốn bắt buộc toàn tổ chức thì admin khai báo hai key này trong managed settings (`/etc/claude-code/managed-settings.json` trên Linux).

### Phần plugin không tự làm được

Plugin không được phép thêm `permissions`. Vì vậy, nếu muốn chặn cả trường hợp bạn tự gắn file credential bằng `@` (cách này không đi qua hook), hãy tự thêm vào `~/.claude/settings.json`:

```json
{
  "permissions": {
    "deny": [
      "Read(~/.ssh/id_*)",
      "Read(~/.aws/credentials)",
      "Read(~/.kube/config)",
      "Read(~/.docker/config.json)",
      "Read(~/.claude/.credentials.json)"
    ]
  }
}
```

## Cài không qua plugin

```bash
python3 standalone/install.py --dry-run   # xem settings.json sau khi merge
python3 standalone/install.py
```

Script này copy hook vào `~/.claude/hooks/`, merge cấu hình (gồm cả các deny rule ở trên) vào `~/.claude/settings.json`, giữ nguyên hook cũ và backup trước khi ghi. Ở chế độ này, tùy chọn được đặt bằng biến môi trường: `TIGHTLIP_QUIET=1`, `TIGHTLIP_BLOCK_DOTENV=1`, `TIGHTLIP_NAME_SESSIONS=0`, `TIGHTLIP_ALLOW_REGEX=...`, `TIGHTLIP_DISABLE=1`. Chỉ dùng một trong hai cách cài, không dùng cả hai.

## Kiểm tra

```bash
python3 -m unittest discover -v tests                                       # 38 test
echo 'DB_PASSWORD=abc123xyz' | python3 plugins/tightlip/scripts/tightlip.py --filter
```

Đã cài thử qua marketplace trên Claude Code 2.1.289:
- `claude plugin details` nhận đủ 5 hook.
- Trong phiên thật, `cat .env` chỉ cho model thấy placeholder.
- Với `cat .env && exit 3`, phiên dừng trước khi output được gửi lên model.
- Không có request đặt tên phiên nào được gửi đi.

## Nhận diện được gì

- **Token có định dạng riêng (khoảng 50 rule):** AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI/Anthropic/DeepSeek, DigitalOcean, Shopify, Atlassian, Sentry, PostHog `phx_`, npm, Docker Hub, Telegram, Grafana, Vault, Doppler, JWT, private key PEM, Laravel `APP_KEY`...
- **Nhận diện theo ngữ cảnh:**
  - `KEY=value` kiểu dotenv/shell.
  - YAML, JSON, mảng PHP có key nhạy cảm.
  - URL dạng `user:pass@`, header `Authorization`/`X-API-Key`, query `?token=`, tham số `--password=`.
  - Khối `env` của k8s, output của `php artisan config:show`.
- **Giá trị ngẫu nhiên dài** trong `UPPER_CASE=...`.

Đã chạy thử trên laravel/framework, express, thư viện chuẩn Python và npm (khoảng 6.500 file). Những thứ bị che chỉ là giá trị test trông như secret thật. Validation rule, `env('APP_KEY')`, file dịch và hash trong lock file không bị che nhầm.

## Giới hạn

1. **Output của lệnh bị lỗi.** Hook không sửa được loại output này, chỉ dừng được trước khi gửi đi. Nội dung đó vẫn nằm trong hội thoại, và nếu bạn nhắn tiếp thì model sẽ thấy nó. Vì vậy hãy dùng `/rewind` (Esc Esc) để quay về trước lượt đó. Thông báo chặn có ghi nơi chứa secret (lệnh hoặc file và số dòng, ví dụ `config/.env.prod:12`) để bạn xem lại, nhưng không ghi giá trị.
2. **Tên phiên.** Khi `name_sessions` bật, phiên mang tên thư mục và giờ, thay vì tên do model tóm tắt. Nếu tắt, prompt đầu tiên của mỗi phiên sẽ được gửi đi trước khi hook kịp chặn.
3. **File gắn bằng `@` và lệnh `!` bạn tự chạy không qua hook.** Output của `! cat .env` vào thẳng hội thoại mà không bị che. Với file gắn bằng `@`, xem phần deny rule ở trên.
4. **Regex có giới hạn.** Những thứ sẽ lọt: giá trị in ra không kèm tên biến (ví dụ `cut -d= -f2 .env`), secret mã hóa base64, token có định dạng lạ. Thêm định dạng riêng vào `FORMAT_RULES` trong `scripts/tightlip.py`.
5. **Hook chỉ thay đổi những gì model thấy.** Lệnh vẫn chạy thật. OpenTelemetry (nếu bật) vẫn ghi output gốc.
6. **Model vẫn có thể sửa file plugin qua Bash.** Muốn chắc chắn, admin force-enable plugin trong managed settings và bật `allowManagedHooksOnly`.
7. **Chỉ dùng cho Claude Code.** Codex chưa cho hook thay output (openai/codex#38135).
