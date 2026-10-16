"""
ProxyScrape 注册机

协议发现（chrome-devtools-mcp）：
  页面 https://dashboard.proxyscrape.com/v2/sign-up
  POST /v2/v4/account/auth/register  (email, password, cf_turnstile_token)
  POST /v2/v4/account/verify-email   (verificationCode + Bearer access_token)
  Turnstile sitekey: 0x4AAAAAAAFWUVCKyusT9T8r
"""
import os
import sys
import time
import re
from curl_cffi import requests
from dotenv import load_dotenv

load_dotenv()

from src import (
    EmailService,
    GPTMailService,
    TurnstileService,
)
from src.proxyscrape_helpers import (
    SIGNUP_URL,
    LOGIN_URL,
    REGISTER_ENDPOINT,
    LOGIN_ENDPOINT,
    VERIFY_EMAIL_ENDPOINT,
    RESEND_CODE_ENDPOINT,
    TYPEFORM_ENDPOINT,
    PREMIUM_TRIAL_CLAIM_ENDPOINT,
    ME_ENDPOINT,
    TYPEFORM_FORM_ID,
    TURNSTILE_SITEKEY,
    DEFAULT_PROXY_PROTOCOL,
    CREDENTIAL_FORMAT_PROTOCOL_URL,
    PROXIES_FILE,
    generate_register_password,
    password_meets_rules,
    parse_verification_code,
    save_account_credentials,
    save_proxy_lines,
    load_proxies_file_content,
    build_resin_subscription_payload,
    build_register_form_fields,
    build_login_form_fields,
    build_typeform_complete_fields,
    build_proxy_download_params,
    build_proxy_display_params,
    needs_typeform_onboarding,
    extract_register_success,
    pick_subaccount_id,
    proxy_list_download_url,
    proxy_list_page_url,
    overview_url,
    parse_proxy_download_text,
    is_protocol_url_proxy_line,
    is_access_token_expired,
    update_account_access_token,
)

REGISTER_PASSWORD = os.getenv("REGISTER_PASSWORD", "random").strip()
try:
    REGISTER_INTERVAL = float(os.getenv("REGISTER_INTERVAL", "0") or "0")
except ValueError:
    REGISTER_INTERVAL = 0.0

DEFAULT_IMPERSONATE = "chrome120"
# Protocol for premium list download: trial is HTTP-only; paid may support socks5
PROXY_DOWNLOAD_PROTOCOL = (
    os.getenv("PROXY_DOWNLOAD_PROTOCOL", DEFAULT_PROXY_PROTOCOL) or "http"
).strip().lower()

# Remote Resin subscription: PATCH proxies.txt after full batch success
# Example:
#   RESIN_SUBSCRIPTION_URL=https://resin.example.com/api/v1/subscriptions/<uuid>
#   RESIN_API_TOKEN=...
RESIN_SUBSCRIPTION_URL = os.getenv("RESIN_SUBSCRIPTION_URL", "").strip()
RESIN_API_TOKEN = os.getenv("RESIN_API_TOKEN", "").strip()
RESIN_NAME = os.getenv("RESIN_NAME", "proxyscrape").strip() or "proxyscrape"
RESIN_UPDATE_INTERVAL = os.getenv("RESIN_UPDATE_INTERVAL", "12h").strip() or "12h"
RESIN_EPHEMERAL_NODE_EVICT_DELAY = (
    os.getenv("RESIN_EPHEMERAL_NODE_EVICT_DELAY", "72h0m0s").strip() or "72h0m0s"
)
RESIN_ENABLED = os.getenv("RESIN_ENABLED", "true").strip().lower() not in (
    "0",
    "false",
    "no",
    "off",
)
RESIN_EPHEMERAL = os.getenv("RESIN_EPHEMERAL", "false").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
RESIN_INCREMENTAL_ALIVE_NODES = os.getenv(
    "RESIN_INCREMENTAL_ALIVE_NODES", "false"
).strip().lower() in ("1", "true", "yes", "on")

PROXIES = (
    {
        "http": os.getenv("PROXY"),
        "https": os.getenv("PROXY"),
    }
    if os.getenv("PROXY")
    else {}
)

last_register_time = 0.0
success_count = 0
start_time = time.time()
target_count = 100
stop_flag = False


def wait_register_interval():
    """按 .env 中 REGISTER_INTERVAL 控制两次注册之间的最小间隔"""
    global last_register_time
    if REGISTER_INTERVAL <= 0:
        return
    now = time.time()
    wait = REGISTER_INTERVAL - (now - last_register_time)
    if wait > 0:
        print(f"[*] 注册间隔等待 {wait:.1f}s（间隔 {REGISTER_INTERVAL}s）...")
        end = time.time() + wait
        while time.time() < end:
            if stop_flag:
                return
            time.sleep(min(0.5, end - time.time()))
    last_register_time = time.time()


def get_register_password() -> str:
    pwd = generate_register_password(REGISTER_PASSWORD)
    if not password_meets_rules(pwd):
        # Force a compliant random password if env value is invalid
        print(
            f"[!] REGISTER_PASSWORD 不符合 ProxyScrape 规则（需≥8位、大写、数字、特殊字符），改用随机密码"
        )
        pwd = generate_register_password("random")
    return pwd


def create_session():
    return requests.Session(impersonate=DEFAULT_IMPERSONATE, proxies=PROXIES)


def solve_turnstile(
    turnstile_service: TurnstileService,
    page_url: str | None = None,
) -> str | None:
    """Solve Cloudflare Turnstile for ProxyScrape (sign-up or login page)."""
    url = page_url or SIGNUP_URL
    try:
        task_id = turnstile_service.create_task(url, TURNSTILE_SITEKEY)
        token = turnstile_service.get_response(task_id)
        if not token or token == "CAPTCHA_FAIL":
            return None
        return token
    except Exception as e:
        print(f"[-] Turnstile 求解异常: {e}")
        return None


def login_http(session, email: str, password: str, turnstile_token: str) -> dict:
    """
    POST /v2/v4/account/auth/login with email + password + Turnstile.
    Returns {ok, data, status, message} — data matches extract_register_success.
    """
    fields = build_login_form_fields(email, password, turnstile_token)
    try:
        res = session.post(
            LOGIN_ENDPOINT,
            data=fields,
            headers={
                "origin": "https://dashboard.proxyscrape.com",
                "referer": LOGIN_URL,
                "accept": "application/json, text/plain, */*",
            },
            timeout=30,
        )
    except Exception as e:
        return {"ok": False, "data": None, "status": 0, "message": str(e)}

    try:
        body = res.json()
    except Exception:
        body = {"raw": res.text[:500]}

    if res.status_code == 200:
        parsed = extract_register_success(body)
        if parsed:
            return {
                "ok": True,
                "data": parsed,
                "status": res.status_code,
                "message": "ok",
            }

    message = ""
    if isinstance(body, dict):
        message = body.get("message") or body.get("error") or str(body)[:200]
    else:
        message = str(body)[:200]
    return {
        "ok": False,
        "data": body,
        "status": res.status_code,
        "message": message or "login failed",
    }


def re_login_account(
    session,
    email: str,
    password: str,
    turnstile_service: TurnstileService | None = None,
    persist: bool = True,
) -> dict:
    """
    Solve Turnstile + login; optionally write new access_token to accounts file.
    Returns {ok, access_token, message, status}.
    """
    email = (email or "").strip()
    password = (password or "").strip()
    if not email or not password:
        return {
            "ok": False,
            "access_token": "",
            "message": "缺少 email 或 password",
            "status": 0,
        }

    svc = turnstile_service or TurnstileService()
    ts_token = None
    for captcha_try in range(3):
        print(f"[*] {email} 登录 Turnstile ({captcha_try + 1}/3)...")
        ts_token = solve_turnstile(svc, LOGIN_URL)
        if ts_token:
            break
        time.sleep(1)
    if not ts_token:
        return {
            "ok": False,
            "access_token": "",
            "message": "Turnstile 求解失败（请确认 api_solver 已启动）",
            "status": 0,
        }

    try:
        session.get(LOGIN_URL, timeout=15)
    except Exception:
        pass

    result = login_http(session, email, password, ts_token)
    if not result.get("ok"):
        return {
            "ok": False,
            "access_token": "",
            "message": result.get("message") or "登录失败",
            "status": result.get("status") or 0,
        }

    access_token = (result.get("data") or {}).get("access_token") or ""
    if not access_token:
        return {
            "ok": False,
            "access_token": "",
            "message": "登录响应无 access_token",
            "status": result.get("status") or 200,
        }

    if persist:
        try:
            update_account_access_token(email, access_token)
            print(f"[+] {email} token 已续期并写入 accounts 文件")
        except Exception as e:
            print(f"[!] {email} token 写入失败: {e}")

    return {
        "ok": True,
        "access_token": access_token,
        "message": "ok",
        "status": result.get("status") or 200,
        "data": result.get("data"),
    }


def ensure_fresh_access_token(
    session,
    acc: dict,
    turnstile_service: TurnstileService | None = None,
    force: bool = False,
) -> dict:
    """
    Return a usable access_token for the account row.
    Re-logins when force=True, token missing/expired, or JWT past exp.
    """
    email = (acc.get("email") or "").strip()
    password = (acc.get("password") or "").strip()
    token = (acc.get("access_token") or "").strip()
    if not force and token and not is_access_token_expired(token):
        return {
            "ok": True,
            "access_token": token,
            "refreshed": False,
            "message": "ok",
        }
    if not password:
        return {
            "ok": False,
            "access_token": token,
            "refreshed": False,
            "message": "token 过期且无 password，无法重登",
        }
    lr = re_login_account(
        session, email, password, turnstile_service=turnstile_service, persist=True
    )
    if not lr.get("ok"):
        return {
            "ok": False,
            "access_token": token,
            "refreshed": False,
            "message": lr.get("message") or "重登失败",
        }
    return {
        "ok": True,
        "access_token": lr["access_token"],
        "refreshed": True,
        "message": "ok",
    }


def register_http(session, email: str, password: str, turnstile_token: str) -> dict:
    """
    POST ProxyScrape register endpoint with discovered form fields.
    Returns {ok, data, status, message}.
    """
    fields = build_register_form_fields(email, password, turnstile_token)
    try:
        # Browser uses FormData; multipart is accepted (MCP probe confirmed endpoint)
        res = session.post(
            REGISTER_ENDPOINT,
            data=fields,
            headers={
                "origin": "https://dashboard.proxyscrape.com",
                "referer": SIGNUP_URL,
                "accept": "application/json, text/plain, */*",
            },
            timeout=30,
        )
    except Exception as e:
        return {"ok": False, "data": None, "status": 0, "message": str(e)}

    try:
        body = res.json()
    except Exception:
        body = {"raw": res.text[:500]}

    if res.status_code == 200:
        parsed = extract_register_success(body)
        if parsed:
            return {
                "ok": True,
                "data": parsed,
                "status": res.status_code,
                "message": "ok",
            }

    message = ""
    if isinstance(body, dict):
        message = body.get("message") or body.get("error") or str(body)[:200]
    else:
        message = str(body)[:200]
    return {
        "ok": False,
        "data": body,
        "status": res.status_code,
        "message": message,
    }


def _auth_headers(access_token: str) -> dict:
    return {
        "Authorization": f"Bearer {access_token}",
        "origin": "https://dashboard.proxyscrape.com",
        "referer": "https://dashboard.proxyscrape.com/v2/verify",
        "accept": "application/json, text/plain, */*",
        "Content-Type": "application/x-www-form-urlencoded",
    }


def verify_email_http(session, access_token: str, code: str) -> dict:
    """POST /v2/v4/account/verify-email with Bearer token."""
    try:
        res = session.post(
            VERIFY_EMAIL_ENDPOINT,
            data={"verificationCode": code},
            headers=_auth_headers(access_token),
            timeout=30,
        )
    except Exception as e:
        return {"ok": False, "status": 0, "message": str(e)}

    try:
        body = res.json()
    except Exception:
        body = {"raw": res.text[:500]}

    ok = res.status_code == 200 and (
        body.get("success") is not False if isinstance(body, dict) else True
    )
    message = ""
    if isinstance(body, dict):
        message = body.get("message") or ("ok" if ok else str(body)[:200])
    return {"ok": ok, "status": res.status_code, "message": message, "data": body}


def resend_verification_code(session, access_token: str) -> dict:
    """
    POST /v2/v4/account/reset-verification-code

    Critical: register API does NOT always auto-send the verification email.
    Frontend verify page relies on this (or an initial server-side send).
    """
    try:
        res = session.post(
            RESEND_CODE_ENDPOINT,
            data={},
            headers=_auth_headers(access_token),
            timeout=30,
        )
    except Exception as e:
        return {"ok": False, "status": 0, "message": str(e)}

    try:
        body = res.json()
    except Exception:
        # Cloudflare 429 HTML etc.
        return {
            "ok": False,
            "status": res.status_code,
            "message": res.text[:200],
            "data": None,
        }

    ok = res.status_code == 200 and (
        body.get("success") is not False if isinstance(body, dict) else True
    )
    message = ""
    if isinstance(body, dict):
        message = body.get("message") or ("ok" if ok else str(body)[:200])
    # Rate-limit message is still "sent recently" — treat as soft-ok for polling
    if (
        isinstance(body, dict)
        and "once every 2 minutes" in str(body.get("message", "")).lower()
    ):
        ok = True
    return {"ok": ok, "status": res.status_code, "message": message, "data": body}


def fetch_account_me(session, access_token: str) -> dict | None:
    """POST /v2/v4/account/auth/me — EmailVerified + typeform onboarding flag."""
    try:
        res = session.post(
            ME_ENDPOINT,
            data={},
            headers=_auth_headers(access_token),
            timeout=20,
        )
        if res.status_code == 200:
            return res.json()
    except Exception as e:
        print(f"[-] /me 查询异常: {e}")
    return None


def download_premium_proxies(
    session,
    access_token: str,
    account_id: str,
    protocol: str | None = None,
) -> dict:
    """
    Download premium proxy list as protocol://user:pass@host:port lines.

    Dashboard page: /v2/services/premium/proxy-list/{accountId}
    API (MCP + live probe):
      GET /v2/v4/account/{accountId}/datacenter_shared/proxy-list
        ?type=getproxies&protocol=http&format=credentials&credential_format=3
    """
    proto = (protocol or PROXY_DOWNLOAD_PROTOCOL or "http").lower()
    params = build_proxy_download_params(
        protocol=proto,
        credential_format=CREDENTIAL_FORMAT_PROTOCOL_URL,
    )
    headers = _auth_headers(access_token)
    headers["referer"] = proxy_list_page_url(account_id)
    headers["accept"] = "*/*"
    url = proxy_list_download_url(account_id)
    try:
        res = session.get(url, params=params, headers=headers, timeout=60)
    except Exception as e:
        return {"ok": False, "status": 0, "message": str(e), "lines": []}

    if res.status_code != 200:
        msg = res.text[:300] if res.text else f"HTTP {res.status_code}"
        return {
            "ok": False,
            "status": res.status_code,
            "message": msg,
            "lines": [],
        }

    # curl_cffi Response: .text or .content
    try:
        body = res.text if isinstance(res.text, str) else res.content.decode(
            "utf-8", errors="replace"
        )
    except Exception:
        body = res.content.decode("utf-8", errors="replace")

    lines = parse_proxy_download_text(body)
    if not lines:
        return {
            "ok": False,
            "status": res.status_code,
            "message": f"empty proxy list body: {body[:200]!r}",
            "lines": [],
        }

    valid = [ln for ln in lines if is_protocol_url_proxy_line(ln)]
    if not valid:
        # still accept lines if format slightly differs
        valid = lines

    return {
        "ok": True,
        "status": res.status_code,
        "message": f"{len(valid)} proxies",
        "lines": valid,
        "sample": valid[0] if valid else "",
    }


def fetch_overview(session, access_token: str, account_id: str) -> dict | None:
    """GET services/overview — includes proxy_username / proxy_password."""
    try:
        res = session.get(
            overview_url(account_id),
            headers={
                **_auth_headers(access_token),
                "referer": proxy_list_page_url(account_id),
                "accept": "application/json",
            },
            timeout=30,
        )
        if res.status_code == 200:
            return res.json()
    except Exception as e:
        print(f"[-] overview 查询异常: {e}")
    return None


def fetch_proxy_list_meta(
    session,
    access_token: str,
    account_id: str,
    protocol: str | None = None,
) -> dict | None:
    """
    GET datacenter_shared/proxy-list?format=data&type=displayproxies&protocol=http

    Dashboard country breakdown, e.g.:
      {"countries":{"us":52,"de":11,...},"recordsTotal":100}
    """
    proto = (protocol or PROXY_DOWNLOAD_PROTOCOL or "http").lower()
    params = build_proxy_display_params(protocol=proto)
    try:
        res = session.get(
            proxy_list_download_url(account_id),
            params=params,
            headers={
                **_auth_headers(access_token),
                "referer": proxy_list_page_url(account_id),
                "accept": "application/json",
            },
            timeout=30,
        )
        if res.status_code == 200:
            data = res.json()
            if isinstance(data, dict):
                return data
    except Exception as e:
        print(f"[-] proxy-list meta 查询异常: {e}")
    return None


def complete_typeform_onboarding(session, access_token: str) -> dict:
    """
    Complete post-verify Typeform questionnaire gate.

    Live flow (chrome-devtools, account qmubgz71q@yjb.me):
      /me typeform=true → redirect /v2/typeform (embed form vnCgUn0n)
      Q1: Individual / Company
      Q2: What do you use proxies for?
      onSubmit → POST /v2/v4/account/typeform {form_id, response_id}
      typeform=false → real dashboard (e.g. /services/premium/overview/...)

    API accepts a synthetic response_id without filling the embed UI.
    """
    fields = build_typeform_complete_fields()
    headers = _auth_headers(access_token)
    headers["referer"] = "https://dashboard.proxyscrape.com/v2/typeform"
    try:
        res = session.post(
            TYPEFORM_ENDPOINT,
            data=fields,
            headers=headers,
            timeout=30,
        )
    except Exception as e:
        return {"ok": False, "status": 0, "message": str(e), "fields": fields}

    try:
        body = res.json()
    except Exception:
        body = {"raw": res.text[:500]}

    ok = res.status_code == 200 and (
        body.get("success") is not False if isinstance(body, dict) else True
    )
    # Idempotent: already submitted is success for our purposes
    if (
        isinstance(body, dict)
        and "already submitted" in str(body.get("error") or body.get("message") or "").lower()
    ):
        ok = True
    message = ""
    if isinstance(body, dict):
        message = (
            body.get("message")
            or body.get("error")
            or ("ok" if ok else str(body)[:200])
        )
    return {
        "ok": ok,
        "status": res.status_code,
        "message": message,
        "data": body,
        "fields": fields,
    }


def claim_premium_trial(session, access_token: str) -> dict:
    """Activate the eligible account's Premium free trial after onboarding."""
    headers = _auth_headers(access_token)
    headers.pop("Content-Type", None)
    headers["referer"] = "https://dashboard.proxyscrape.com/v2/overview"
    try:
        res = session.post(
            PREMIUM_TRIAL_CLAIM_ENDPOINT,
            headers=headers,
            timeout=30,
        )
    except Exception as e:
        return {"ok": False, "status": 0, "message": str(e), "data": None}

    try:
        body = res.json()
    except Exception:
        body = {"raw": res.text[:500]}

    ok = (
        200 <= res.status_code < 300
        and isinstance(body, dict)
        and body.get("success") is True
    )
    message = ""
    if isinstance(body, dict):
        message = body.get("message") or body.get("error") or (
            "ok" if ok else str(body)[:200]
        )
    return {
        "ok": ok,
        "status": res.status_code,
        "message": message or f"HTTP {res.status_code}",
        "data": body,
    }


def fetch_inbox_content(email_service, jwt, email: str, email_service_type: str):
    try:
        if email_service_type == "gptmail":
            return email_service.fetch_first_email(jwt, email=email)
        return email_service.fetch_first_email(jwt)
    except Exception as e:
        print(f"[-] 拉取邮件异常: {e}")
        return None


def poll_verification_code(
    email_service,
    jwt,
    email: str,
    email_service_type: str,
    session=None,
    access_token: str | None = None,
    max_rounds: int = 45,
):
    """轮询临时邮箱；首次发信后两分钟仍未获得验证码时补发一次。"""
    resend_due_at = time.monotonic() + 120
    resend_once = False

    if session is not None and access_token:
        print(f"[*] {email} 请求发送邮箱验证码 (reset-verification-code)...")
        rr = resend_verification_code(session, access_token)
        print(f"[*] {email} 发信结果 ({rr['status']}): {rr['message']}")
        resend_due_at = time.monotonic() + 120

    last_raw_len = 0
    for attempt in range(max_rounds):
        if stop_flag:
            return None

        time.sleep(5)

        content = fetch_inbox_content(email_service, jwt, email, email_service_type)
        if content:
            if len(content) != last_raw_len:
                last_raw_len = len(content)
                print(f"[*] {email} 收到邮件 (len={len(content)})，解析验证码...")

            code = parse_verification_code(content)
            if code:
                return code

            if attempt in (0, 5, 15, 30):
                snippet = re.sub(r"\s+", " ", content)[:180]
                print(f"[!] {email} 邮件未能解析验证码，snippet: {snippet!r}")
        elif attempt % 5 == 0:
            print(f"[*] {email} 等待验证邮件... ({attempt + 1}/{max_rounds})")

        # 首次发信满两分钟仍未获得验证码时，仅补发一次
        if (
            not resend_once
            and time.monotonic() >= resend_due_at
            and session is not None
            and access_token
        ):
            resend_once = True
            print(f"[*] {email} 两分钟仍未解析到验证码，再次请求发信...")
            rr = resend_verification_code(session, access_token)
            print(f"[*] {email} 再次发信 ({rr['status']}): {rr['message']}")

    return None


def register_accounts():
    """单线程 ProxyScrape 注册循环。"""
    global success_count, stop_flag

    EMAIL_SERVICE_TYPE = os.getenv("EMAIL_SERVICE_TYPE", "cloudflare")
    try:
        if EMAIL_SERVICE_TYPE == "gptmail":
            email_service = GPTMailService()
        else:
            email_service = EmailService()
        turnstile_service = TurnstileService()
    except Exception as e:
        print(f"[-] 服务初始化失败: {e}")
        return

    print(f"[*] 注册目标: {SIGNUP_URL}")
    print(f"[*] API: {REGISTER_ENDPOINT}")
    print(f"[*] Turnstile sitekey: {TURNSTILE_SITEKEY}")

    consecutive_captcha_fails = 0
    max_captcha_rounds = int(os.getenv("MAX_CAPTCHA_FAIL_ROUNDS", "3") or "3")

    while not stop_flag and success_count < target_count:
        try:
            with create_session() as session:
                try:
                    session.get(SIGNUP_URL, timeout=15)
                except Exception:
                    pass

                password = get_register_password()

                try:
                    jwt, email = email_service.create_email()
                except Exception as e:
                    print(f"[-] 邮箱服务抛出异常: {e}")
                    jwt, email = None, None

                if not email:
                    print("[-] 邮箱创建返回空，可能接口挂了或超时，等待 5s...")
                    time.sleep(5)
                    continue

                if stop_flag:
                    return

                wait_register_interval()
                if stop_flag:
                    return

                if EMAIL_SERVICE_TYPE == "gptmail":
                    quota_log = email_service.format_quota_log()
                    print(f"[*] 开始 ProxyScrape 注册: {email}{quota_log}")
                else:
                    print(f"[*] 开始 ProxyScrape 注册: {email}")

                # Step 1: Turnstile
                token = None
                for captcha_try in range(3):
                    if stop_flag:
                        return
                    print(f"[*] {email} 求解 Turnstile ({captcha_try + 1}/3)...")
                    token = solve_turnstile(turnstile_service)
                    if token:
                        break
                    print(f"[-] {email} CAPTCHA 失败，重试...")
                    time.sleep(1)

                if not token:
                    consecutive_captcha_fails += 1
                    print(
                        f"[-] {email} CAPTCHA 连续失败，换号 "
                        f"({consecutive_captcha_fails}/{max_captcha_rounds})"
                    )
                    if consecutive_captcha_fails >= max_captcha_rounds:
                        print(
                            "[-] 本地 Turnstile Solver 不可用或持续失败，"
                            "停止注册（请启动 api_solver 后重试）"
                        )
                        return
                    time.sleep(2)
                    continue

                consecutive_captcha_fails = 0

                # Step 2: Register
                result = register_http(session, email, password, token)
                if not result["ok"]:
                    print(
                        f"[-] {email} 注册失败 ({result['status']}): {result['message']}"
                    )
                    # Site-side reasons (captcha/email) are logged; not Grok config errors
                    time.sleep(3)
                    continue

                parsed = result["data"]
                access_token = parsed["access_token"]
                email_verified = bool(parsed.get("email_verified", False))
                print(
                    f"[+] {email} 注册 API 成功 | token={access_token[:16]}... | "
                    f"EmailVerified={email_verified}"
                )

                # Confirm with /me (register payload can lag; source of truth)
                me = fetch_account_me(session, access_token)
                if me is not None:
                    email_verified = bool(me.get("EmailVerified") or me.get("emailVerified"))
                    print(f"[*] {email} /me EmailVerified={email_verified}")

                # Step 3: Email verification — required when not verified.
                # Register does NOT reliably auto-send mail; we call resend endpoint.
                if not email_verified:
                    print(f"[*] {email} 开始邮箱验证流程...")
                    code = poll_verification_code(
                        email_service,
                        jwt,
                        email,
                        EMAIL_SERVICE_TYPE,
                        session=session,
                        access_token=access_token,
                    )
                    if not code:
                        print(
                            f"[-] {email} 未解析到验证码；已保存未验证账号（不计入成功）"
                        )
                        paths = save_account_credentials(
                            email, password, access_token, extra="UNVERIFIED"
                        )
                        print(f"[~] 未验证账号 -> {paths['accounts']}")
                        time.sleep(3)
                        continue

                    print(f"[*] {email} 验证码: {code}")
                    vres = verify_email_http(session, access_token, code)
                    if not vres["ok"]:
                        print(
                            f"[-] {email} 邮箱验证失败 ({vres['status']}): {vres['message']}"
                        )
                        paths = save_account_credentials(
                            email, password, access_token, extra="UNVERIFIED"
                        )
                        print(f"[~] 验证失败账号 -> {paths['accounts']}")
                        time.sleep(3)
                        continue
                    print(f"[+] {email} 邮箱验证成功")

                    me2 = fetch_account_me(session, access_token)
                    if me2 is not None:
                        print(
                            f"[*] {email} 验证后 /me EmailVerified="
                            f"{me2.get('EmailVerified')} typeform="
                            f"{me2.get('typeform')}"
                        )

                # Step 4: Typeform onboarding ("Let us know a little more about you")
                # Until typeform=false, dashboard redirects to /v2/typeform and blocks
                # real backend overview. Complete via API (same as embed onSubmit).
                me3 = fetch_account_me(session, access_token)
                if me3 is None or needs_typeform_onboarding(me3):
                    print(
                        f"[*] {email} 开始 onboarding 问卷 "
                        f"(typeform form_id={TYPEFORM_FORM_ID})..."
                    )
                    tres = complete_typeform_onboarding(session, access_token)
                    if not tres["ok"]:
                        print(
                            f"[-] {email} 问卷提交失败 ({tres['status']}): "
                            f"{tres['message']}"
                        )
                        paths = save_account_credentials(
                            email, password, access_token, extra="NO_TYPEFORM"
                        )
                        print(f"[~] 未完成问卷账号 -> {paths['accounts']}")
                        time.sleep(3)
                        continue
                    print(
                        f"[+] {email} 问卷完成: {tres['message']} "
                        f"(response_id={tres['fields'].get('response_id')})"
                    )
                    me4 = fetch_account_me(session, access_token)
                    if me4 is not None and needs_typeform_onboarding(me4):
                        print(
                            f"[-] {email} 问卷 API 成功但 /me typeform 仍为 true"
                        )
                        paths = save_account_credentials(
                            email, password, access_token, extra="NO_TYPEFORM"
                        )
                        print(f"[~] 问卷未生效账号 -> {paths['accounts']}")
                        time.sleep(3)
                        continue
                    if me4 is not None:
                        print(
                            f"[*] {email} 问卷后 /me typeform={me4.get('typeform')}"
                        )
                else:
                    print(f"[*] {email} onboarding 问卷已完成，跳过")

                # Step 5: Activate the supported Premium free-trial API.
                # This only runs after /me has confirmed onboarding is complete.
                print(f"[*] {email} 激活 Premium 免费试用...")
                cres = claim_premium_trial(session, access_token)
                if not cres["ok"]:
                    print(
                        f"[-] {email} 免费试用激活失败 ({cres['status']}): "
                        f"{cres['message']}"
                    )
                    paths = save_account_credentials(
                        email, password, access_token, extra="NO_PREMIUM_TRIAL"
                    )
                    print(f"[~] 未激活免费试用账号 -> {paths['accounts']}")
                    time.sleep(3)
                    continue
                print(f"[+] {email} Premium 免费试用已激活: {cres['message']}")

                # Step 6: Download premium proxy list (primary deliverable)
                # Page: /v2/services/premium/proxy-list/{accountId}
                # Format: protocol://user:pass@host:port  (credential_format=3)
                me_final = fetch_account_me(session, access_token) or {}
                account_id = pick_subaccount_id(me_final)
                if not account_id:
                    # fallback to register userData
                    account_id = pick_subaccount_id(parsed.get("user_data") or {})
                if not account_id:
                    print(f"[-] {email} 无 AccountID，无法下载 proxy-list")
                    save_account_credentials(
                        email, password, access_token, extra="NO_ACCOUNT_ID"
                    )
                    time.sleep(3)
                    continue

                print(
                    f"[*] {email} 下载 proxy-list | accountId={account_id} | "
                    f"protocol={PROXY_DOWNLOAD_PROTOCOL} | "
                    f"format=protocol://user:pass@host:port"
                )
                print(f"[*] 页面: {proxy_list_page_url(account_id)}")

                ov = fetch_overview(session, access_token, account_id)
                if ov and isinstance(ov.get("data"), dict):
                    dc = (
                        (ov["data"].get("services") or {})
                        .get("datacenter_shared")
                        or {}
                    )
                    pu = dc.get("proxy_username")
                    pp = dc.get("proxy_password")
                    n_proxies = dc.get("proxy_amount")
                    print(
                        f"[*] credentials user={pu} pass="
                        f"{(pp[:3] + '***') if pp else None} "
                        f"proxy_amount={n_proxies}"
                    )

                dres = download_premium_proxies(
                    session, access_token, account_id, PROXY_DOWNLOAD_PROTOCOL
                )
                if not dres["ok"] or not dres["lines"]:
                    print(
                        f"[-] {email} 代理下载失败 ({dres['status']}): "
                        f"{dres['message']}"
                    )
                    save_account_credentials(
                        email, password, access_token, extra="NO_PROXIES"
                    )
                    time.sleep(3)
                    continue

                proxy_paths = save_proxy_lines(
                    dres["lines"],
                    account_id=account_id,
                    email=email,
                )
                # Optional side log of account (not primary output)
                save_account_credentials(email, password, access_token)

                success_count += 1
                avg = (time.time() - start_time) / success_count
                print(
                    f"[✓] 代理下载成功: {email} | {proxy_paths['count']} 条 | "
                    f"样例: {dres['sample'][:60]}... | "
                    f"{success_count}/{target_count} | 平均: {avg:.1f}s"
                )
                print(
                    f"[*] 已写入 {proxy_paths['proxies']}"
                    + (
                        f" 与 {proxy_paths['account_proxies']}"
                        if proxy_paths.get("account_proxies")
                        else ""
                    )
                )
                if success_count >= target_count:
                    print(f"[*] 已达到目标数量: {success_count}/{target_count}")
                    return

        except KeyboardInterrupt:
            stop_flag = True
            print("\n[!] 检测到中断，正在停止...")
            return
        except Exception as e:
            print(f"[-] 异常: {str(e)[:120]}")
            time.sleep(5)


def _read_target_count() -> int:
    """Read registration count from env REGISTER_COUNT or stdin (TTY-friendly)."""
    env_count = os.getenv("REGISTER_COUNT", "").strip()
    if env_count:
        try:
            return max(1, int(env_count))
        except ValueError:
            pass
    if not sys.stdin.isatty():
        line = sys.stdin.readline()
        if line.strip():
            try:
                return max(1, int(line.strip()))
            except ValueError:
                return 100
        return 100
    try:
        total = int(input("注册数量 (默认100): ").strip() or 100)
        return max(1, total)
    except Exception:
        return 100


def upload_proxies_to_resin(
    proxies_file: str | None = None,
    subscription_url: str | None = None,
    api_token: str | None = None,
    content: str | None = None,
) -> dict:
    """
    PATCH all proxies to remote Resin subscription.

    content: if provided, upload this text directly; else read keys/proxies.txt
    (or proxies_file).

    curl equivalent:
      PATCH {RESIN_SUBSCRIPTION_URL}
      Authorization: Bearer {RESIN_API_TOKEN}
      Content-Type: application/json
      body: { name, update_interval, ..., content: "<proxy lines>" }
    """
    url = (subscription_url if subscription_url is not None else RESIN_SUBSCRIPTION_URL).strip()
    token = (api_token if api_token is not None else RESIN_API_TOKEN).strip()
    path = proxies_file or PROXIES_FILE

    if not url or not token:
        return {
            "ok": False,
            "skipped": True,
            "message": "未配置 RESIN_SUBSCRIPTION_URL / RESIN_API_TOKEN，跳过远程上传",
        }

    if content is None:
        content = load_proxies_file_content(path)
    elif not str(content).endswith("\n") and str(content).strip():
        content = str(content).rstrip() + "\n"

    if not (content or "").strip():
        return {
            "ok": False,
            "skipped": False,
            "message": f"代理内容为空（文件: {path}）",
        }

    line_count = len([ln for ln in content.splitlines() if ln.strip()])
    payload = build_resin_subscription_payload(
        content=content,
        name=RESIN_NAME,
        update_interval=RESIN_UPDATE_INTERVAL,
        ephemeral_node_evict_delay=RESIN_EPHEMERAL_NODE_EVICT_DELAY,
        enabled=RESIN_ENABLED,
        ephemeral=RESIN_EPHEMERAL,
        incremental_alive_nodes=RESIN_INCREMENTAL_ALIVE_NODES,
    )

    print(f"[*] 上传 proxies 到远程订阅 ({line_count} 行)...")
    print(f"[*] PATCH {url}")
    try:
        import requests as std_requests

        res = std_requests.patch(
            url,
            json=payload,
            headers={
                "accept": "*/*",
                "authorization": f"Bearer {token}",
                "content-type": "application/json; charset=utf-8",
                "origin": url.split("/api/")[0] if "/api/" in url else url,
                "user-agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/150.0.0.0 Safari/537.36"
                ),
            },
            timeout=60,
        )
    except Exception as e:
        return {"ok": False, "skipped": False, "message": str(e), "status": 0}

    ok = 200 <= res.status_code < 300
    body_preview = (res.text or "")[:300]
    return {
        "ok": ok,
        "skipped": False,
        "status": res.status_code,
        "message": body_preview if not ok else f"HTTP {res.status_code} 上传成功",
        "line_count": line_count,
        "url": url,
    }


def main():
    print("=" * 60)
    print("ProxyScrape 注册 + Premium 代理下载")
    print(f"注册: {SIGNUP_URL}")
    print("下载: /v2/services/premium/proxy-list/{accountId}")
    print(f"格式: protocol://user:pass@host:port  (protocol={PROXY_DOWNLOAD_PROTOCOL})")
    print("=" * 60)

    print("[*] 正在初始化...")
    print(f"[+] Register: {REGISTER_ENDPOINT}")
    print(f"[+] Turnstile sitekey: {TURNSTILE_SITEKEY}")
    print(f"[+] Proxy download credential_format={CREDENTIAL_FORMAT_PROTOCOL_URL}")
    if RESIN_SUBSCRIPTION_URL and RESIN_API_TOKEN:
        print(f"[+] 批量完成后上传: {RESIN_SUBSCRIPTION_URL}")
    else:
        print("[!] 未配置 RESIN_SUBSCRIPTION_URL/RESIN_API_TOKEN — 完成后不上传远程")

    global target_count, stop_flag, success_count, start_time
    target_count = _read_target_count()
    stop_flag = False
    success_count = 0
    start_time = time.time()

    interval_info = (
        f"，注册间隔 {REGISTER_INTERVAL}s" if REGISTER_INTERVAL > 0 else ""
    )
    email_type = os.getenv("EMAIL_SERVICE_TYPE", "cloudflare")
    print(f"[*] 邮箱服务: {email_type}")
    print(f"[*] Turnstile: 本地 Solver ({TURNSTILE_SITEKEY[:12]}...)")
    print(f"[*] 目标 {target_count} 个账号（注册→验证→问卷→下载代理）{interval_info}")
    print(f"[*] 主产物: keys/proxies.txt  (追加写入，不覆盖)")

    try:
        register_accounts()
    except KeyboardInterrupt:
        stop_flag = True
        print("\n[!] 检测到 Ctrl+C，已停止")

    print(f"[*] 结束，成功注册 {success_count}/{target_count}")

    # Only push remote when the full requested batch succeeded
    if success_count >= target_count and success_count > 0:
        print(f"[*] 目标数量已全部完成，开始上传 keys/proxies.txt ...")
        result = upload_proxies_to_resin()
        if result.get("skipped"):
            print(f"[*] {result['message']}")
        elif result.get("ok"):
            print(
                f"[✓] 远程上传成功: {result.get('line_count')} 行 | "
                f"{result.get('message')}"
            )
        else:
            print(
                f"[-] 远程上传失败"
                + (f" ({result.get('status')})" if result.get("status") else "")
                + f": {result.get('message')}"
            )
    elif success_count > 0:
        print(
            f"[*] 未达目标 ({success_count}/{target_count})，跳过远程上传"
        )


if __name__ == "__main__":
    main()
