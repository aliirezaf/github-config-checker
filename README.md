# GitHub Config Checker

Collect public proxy share links from configured sources, deduplicate them, test real HTTPS connectivity through each proxy, and publish working links as TXT files.

Supported link types: VLESS, VMess, Trojan, Shadowsocks, SOCKS (`socks://` / `socks5://`), and HTTP proxy links where the URI contains enough information to construct a Sing-box outbound.

> Use only sources you are authorized to access. Public proxy links are untrusted and may log traffic. This project tests connectivity only; it does not verify privacy, security, or operator trustworthiness.

## How it works

1. `sources.txt` lists direct raw-text URLs (one per line). The collector also accepts GitHub raw-file URLs and plain subscription endpoints.
2. `collector.py` downloads source text, decodes Base64 subscription bodies when applicable, extracts supported share links, and deduplicates them.
3. `checker.py` converts each supported share link into a temporary Sing-box configuration, starts a local SOCKS listener, and sends an HTTPS request through it.
4. GitHub Actions runs hourly and commits `output/working.txt`, protocol-specific files, and `output/status.json`.

## Setup

1. Create a **public** GitHub repository (or keep it private if you do not want to publish proxy links).
2. Upload all files in this project.
3. Edit `sources.txt`. Add one source URL per line. Prefer stable raw-text subscription URLs. Lines starting with `#` are comments.
4. In the repository, open **Settings → Actions → General → Workflow permissions** and enable **Read and write permissions** so the workflow can commit updated output.
5. Open **Actions**, enable workflows if prompted, then run **Update proxy list** manually once.
6. Check `output/working.txt` and the workflow logs.

## Schedule

The workflow is scheduled hourly. GitHub can delay scheduled workflows, especially during high load; it is not an exact timer. Scheduled workflows run from the default branch.

## Important limitations

- This is an availability check, not a guarantee that a proxy is safe, private, fast, or suitable for sensitive accounts.
- The initial implementation supports common share-link formats. Some uncommon URL encodings, plugin-based Shadowsocks links, transport combinations, and future protocol extensions may need additional parsing.
- Only a limited number of candidates are tested per run to avoid excessively long jobs. Adjust `MAX_CANDIDATES` in the workflow environment if needed.
- GitHub Actions runners may be blocked by some proxy endpoints, and results can differ from your own network.
- Do not put credentials, private subscriptions, or other secrets in a public repository. Do not publish links unless you have the right to redistribute them.
