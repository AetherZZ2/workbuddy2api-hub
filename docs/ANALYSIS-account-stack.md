# workbuddy2api — account / identity / transport stack review

Scope: `wb_accounts.py`, `wb_identity.py`, `wb_fingerprint.py`, `wb_egress.py`,
`wb_upstream_pool.py`, `wb_atrest.py`, `wb_ipintel.py` (+ call sites in
`wb_proxy.py`, `wb_settings.py`, `wb_scheduler.py`).

**Three premises in the brief are wrong:** `wb_egress.py` is not per-account
proxy binding (it is egress-level backoff); `wb_upstream_pool.py` is not a set of
upstream base URLs (it is an HTTP keep-alive connection pool); `derive_id` lives
in `wb_fingerprint.py`, not `wb_identity.py`.

## 1. Account storage model

* Default dir: `ACCOUNTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'accounts')` — `wb_proxy.py:5658`. One JSON per account, `<sanitized uid>.json` (`wb_accounts.py:757-761`).
* Schema = `Account.to_dict()` (`wb_accounts.py:639-672`): `uid, nickname, domain, realm, platform, product, enterpriseId, accessToken, refreshToken, expiresAt, addedAt, source, proxySlot, proxy, enabled, weight, note, lastError, cooldownUntil, credits, lastCheckin, lastDailyChat, lastActivityReport, modelCaps`. Credentials are the raw bearer JWT plus `refreshToken` (654-655).
* Atomic write — `Account.save()` (757-787): unique temp `"%s.%d.%d.tmp" % (path, pid, tid)` under a per-account `_save_lock` (627, 768), `json.dump`, then `os.replace(tmp, path)` (777-779); temp unlinked on failure (780-784). `RUNTIME_ONLY_FIELDS` `("lastError","cooldownUntil")` (3465) are stripped first (775-776).
* Read — `AccountPool.load()` (2430-2450): `sorted(os.listdir(dir))` for `*.json`, unreadable files skipped with a log line, then `apply_reserve_credits()`, `apply_expiring_window()`, `restore_model_caps()` (2445-2449).
* Portability — `build_export_document()` (3477-3505, `format="workbuddy-accounts"` 3453), `normalise_import_row()` (3546-3621); `VOLATILE_FIELDS` (3459) exported but reset on import.

## 2. Pool / scheduling

* Entry: `wb_proxy.py:12682` → `AccountPool.pick_for_session(realm, session_key, exclude=tried, model, page=affinity_page)`.
* `pick_for_session()` (`wb_accounts.py:2847-2884`) first tries the conversation's warm accounts via `SessionAffinity.recent()` (class 2157-2242, `history=3`, ttl 7200 s), then `pick()`.
* `AccountPool.pick()` (2886-2919), strict preference chain: `_pick_weighted_first()` (2921-2942, operator `weight > 1`), `_pick_expiring_first()` (2944-2962, weights `_expiry_weight()` 2964-2978), `_pick_remaining_first()` (2980-3010, `(uid, model)` table pushed by `apply_remaining_weights()` 2685-2705), then `_rotate_pick()` (3112-3137, round-robin on `_cursor` or `_page_cursors[page]`). Weighted tiers use `_smooth_weighted_pick()` (3018-3065, nginx smooth WRR).
* Eligibility — `Account.ready()` (1079-1112): enabled, has token, `throttle_wait(model) == 0` (2110-2120 = max of `cooldown_until`, `balance_until`, `breaker_until`, `degrade_until`, `model_cooldowns[model]`), not `reserve_blocked()`, not daily-token/credit/model-token blocked; JWT expiring within 120 s triggers `refresh()` and its result decides availability (1104-1112).
* Health state, all `_throttle_lock`-guarded: `note_error()` 1995 (model-scoped when `model=` passed, 2002-2007), `note_soft_rate()` 2047 (600 s→7200 s, `SOFT_RATE_BASE` 414), `note_unscoped_rate()` 2056 (60 s→600 s), `note_failure()` 2070 (breaker: 3 fails→1800 s→21600 s, 424-425), `note_unknown_failure()` 2080 (degrade: 5→600 s→7200 s, 427-428), `note_success()` 2095 clears all, `note_balance_cooled()` 2011 parks a 402 until local 04:00 (`next_local_4am` 393).
* Per-account **per-model** state: `model_cooldowns` (539, runtime-only), persisted `model_caps` (568) written by `note_model_cap()` (927-959, free-cap models only), re-armed across restarts by `restore_model_caps()` (979-1001, pool-level 2452-2464); per-model daily token cap via `model_token_limit_blocked()` (1003-1024).

## 3. Token refresh

* `Account.refresh()` (1221-1226) serialises on `_refresh_lock` (627), then `_refresh_locked()` (1228-1270).
* POST to `cfg["chat_upstream"] + REFRESH_PATH` (`/v2/plugin/auth/token/refresh`, 203); the refresh token travels in the **`X-Refresh-Token` header** (1241) with `X-Auth-Refresh-Source` (1242), `X-User-Id`, `X-Domain`, enterprise header (1248-1249), sent via `http_json(..., proxy=self.proxy)` (1251-1252).
* Success: access token, **rotated** refresh token (1263) and `expires_at` updated, error/cooldown cleared, account re-saved (1268-1269).
* Errors: no refresh token → `"no refresh token; sign in again"` (1229-1231); transport failure → `"refresh failed: %s"` (1253-1255); empty token → `"refresh returned no token (%s)"` (1259-1261); all through `_set_last_error()` (1989-1993, 200-char truncation).
* Triggers: reactive in `ready()` at <120 s (1104-1112); proactive keep-alive in `wb_scheduler.py:150` at <7200 s; manual `_route_accounts_refresh()` `wb_proxy.py:17916-17925`. **HTTP 401 does not refresh** — `wb_proxy.py:12845-12851` cools 60 s and rotates.

## 4. `derive_id` device fingerprinting

`wb_fingerprint.py:11-17`: `seed = f"{salt}:{uid or 'anonymous'}"`; `hashlib.md5(seed.encode()).hexdigest()[:36]`.

* 36 **hex characters** (144 bits of MD5), not a UUID — no version/variant bits.
* Salts: `"machine"` (`wb_accounts.py:753, 1136, 1168`; `wb_fingerprint.py:42`), `"session"` (754, 1137, 1169; 43), `"req"` in `generate_request_id()` (`wb_fingerprint.py:20-24`: prefix + `time_ns() % 1000000`).
* Derived: `X-Machine-ID`/`X-Session-ID` headers (`wb_accounts.py:1136-1137, 1168-1169`), `machineId`/`sessionId` in the panel view (753-754) and in `get_desktop_fingerprint()` (`wb_fingerprint.py:27-53`).
* Why (docstring 3-5): a per-uid deterministic pseudo-device so each account always looks like one fixed machine and accounts cannot be correlated with each other. `wb_identity.py` has **no** fingerprinting — only `build_identity_headers()` (76-145) and realm/product endpoints (`_ENDPOINTS` 51-62, `endpoint_for` 65-68).

## 5. `wb_atrest.py` — desktop at-rest credential decryption

* Envelope `{"$wbEncrypted": 1, "envelope": base64(JSON{suite,keyId,nonce,authTag,ciphertext})}` (50, 111-139).
* Crypto: **AES-256-GCM in pure Python** (`_AES256` 200-234, `_ghash` 260-265, `_gcm_open` 285-292), tag checked with `hmac.compare_digest` (290). `key = sha256(atRestSecretKey_base64_string)` (818, docstring 12); `keyId = sha256(key).hexdigest()[:16]` (`derive_key_id` 106-108).
* AAD frame, byte-exact: `b"WB-AAD\0" | 0x01 | LP(framingMagic) | LP("sym-v1") | u32(suite) | LP(keyId) | framingCode | 0x00 | 0x00` (`aad()` 95-103); framings `WBEF1/1` file, `WBEV1/2` field (52-53).
* Protector key: **Windows process-memory read only**. `hunt_supported()` 697-699 (`os.name == "nt"`); `hunt_key()` 708-771 enumerates processes (`_list_procs` 471-486), picks the Electron main pid (`_main_pids` 494-505), finds readable private committed non-guard regions with `VirtualQueryEx` (`_private_regions` 508-523) and reads them with `ReadProcessMemory` (`_scan_regions` 526-589). Three modes, first hit wins: literal `atRestSecretKey` + 44-char base64, then 44-char base64 regex, then stride-8, then stride-1 windows; candidates are validated by `sha256(key).hex[:16] == protectorKeyId` and finally by GCM-unsealing the keyblob (`unwrap_keyblob` 373-385, called at 767). Scans fan out to subprocesses (`python wb_atrest.py --scan-worker`, 616-676).
* keyblob `<config_dir>/keyblob`; `config_dir()` (324-343) = `WORKBUDDY_CONFIG_DIR`/`CODEBUDDY_CONFIG_DIR` or `~/.workbuddy-ai`, `~/.workbuddy`; path pinned inside it by `_safe_path()` (66-82).
* Non-Windows: `adopt_key()` (823-835) takes a pasted 64-hex key or the 44-char base64 secret, validated identically. Key lives only in `_KEY_CACHE` (778), revalidated by `cached_key()` (838-851). Consumers: `desktop_decrypt_tokens()` `wb_accounts.py:3290`, `desktop_refresh_token()` 3303, `scan_desktop_credentials()` 3356 (read-only, cached key only).

## 6. `wb_upstream_pool.py` — connection pool, not an endpoint pool

Docstring 1-26: urllib's `do_open` hardcodes `Connection: close`, so every request paid a fresh TCP+TLS handshake (measured 118 ms). This module reuses `http.client` connections keyed by **(scheme, host, port, proxy string)** (`urlopen` 651-721, key 673). Pieces: `_KeepAlivePool` 285-403 (LIFO reuse 306, cap 2 via `_pool_size` 58-67, idle TTL 90 s via `_idle_ttl` 70-80, `_sweep_locked` 350-370), liveness probe `_connection_looks_alive` 181-213, process-wide `shared_ssl_context()` 109-133 (verification not relaxed, 119-121), one safe retry on a stale reused connection (686-697), `PoolBypass` for non-HTTP proxies and 3xx (136-141, 715-719), `egress_key()` 635-649. Toggle `WB_UPSTREAM_KEEPALIVE` (46-55). Upstream *endpoints* are selected elsewhere: `wb_identity._ENDPOINTS` (51-62) and `wb_accounts.REALM_CONFIGS` (173-199).

## 7. `wb_egress.py` and `wb_ipintel.py`

* `wb_egress.py` = egress-level transient-failure backoff (issue #271): same-exit accounts share one counter, so a blip costs seconds rather than N × 30-minute breakers (docstring 1-16). `transient_backoff()` 35-38 (1 s doubling, cap 15 s), `note_transient()` 46-60 (jitter 0.75-1.25×, 27-28), `note_success()` 63-70; keyed by `wb_upstream_pool.egress_key()` (`wb_proxy.py:12672-12674` `charge_egress`, `note_success` 12716).
* Per-account proxy binding is `Account.proxy_slot` / `proxy` / `proxy_legacy` (`wb_accounts.py:504-507`), resolved by `AccountPool.apply_proxy_slots()` (2629-2646) from `wb_settings.proxy_slots()` (`wb_settings.py:1756-1770`, entries normalised by `_clean_slot_entry` 1703-1736) stored in `accounts/settings.json` under `proxy_slots`; applied on the wire by `wb_accounts.urlopen(req, timeout, proxy=...)` (123-141) / `opener_for_proxy()` (103-120) and used as the pool key.
* `wb_ipintel.py`: exit IP is fetched **through the proxy** from `https://api.ipify.org` (`probe_proxy_exit` `wb_proxy.py:5925-5934`), then `lookup()` (77-94) queries `http://ip-api.com/json/<ip>` **directly** (`GEO_ENDPOINT` 23) for country/countryCode/isp/as; `hosting` maps to `residential`/`datacenter` (`classify` 48-69). Used for slot naming (`slot_name` 97-107, `slot_label` `wb_proxy.py:5982-5991`) and discovery (`discover_proxy_slots` 5961-5971). Failures return empty, never raise (43-45).

## 8. Security observations

1. **Plaintext credentials on disk.** `accessToken`/`refreshToken` written verbatim (`to_dict` 654-655); `accounts/README.txt` says so explicitly. Exports carry them by default (`include_secrets=True`, 3477) — an export file is a bearer-token dump.
2. **No permission hardening.** No `chmod`/`umask`/`0o600` in `wb_accounts.py`, `wb_settings.py`, `wb_proxy.py` or `wb_atrest.py`; observed `accounts/*.json` and `accounts/settings.json` are `0644` in a `0755` directory, so any local user can read every token. The atomic temp file is created with default mode too (777-779). `accounts/settings.json` also holds API keys in plaintext plus the panel password hash.
3. **The at-rest secret is client-global.** The protector key is `sha256()` of a secret compiled into the desktop client's native module (docstring 19-22) — no per-install salt, no KDF stretching (818). One extracted secret unwraps any user's `keyblob`, so it stops casual file inspection, not an attacker holding the binary or one user's memory.
4. **Hand-rolled crypto.** AES-256-GCM reimplemented in Python (200-292); the construction looks correct but is unaudited, and `seal()` (295-317) reuses a caller-supplied nonce if given one.
5. **Process-memory scanning.** `hunt_key()` opens the client with `PROCESS_VM_READ` (534-535, 731-732) and reads private memory; read-only, but same-user (or admin, 734-735) and behaviourally indistinguishable from a credential scraper.
6. **Credential logging.** No token/`Authorization` values are logged in these modules — failure logs use `uid[:8]` (`wb_proxy.py:12808, 12846, 12851`; `wb_accounts.py:2733`). Residual risk: `note_error(..., detail=...)` keeps up to 2000 chars of the raw upstream body (`last_error_detail`, 2001), and `lastError` is exported (`VOLATILE_FIELDS` 3459) and rendered in the panel.
7. **`derive_id` is obfuscation, not a secret.** MD5 over `salt:uid`, with the uid public in the JWT `sub` (`wb_fingerprint.py:11-17`, `wb_accounts.py:472`) — upstream can recompute every device id.
8. **IP-intelligence leak.** `wb_ipintel.lookup()` sends the operator's proxy exit IPs to a third party over plaintext HTTP with no key (`GEO_ENDPOINT` 23) and deliberately bypasses the proxy (docstring 80-83), exposing the operator's own egress as well.
