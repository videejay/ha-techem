"""Unofficial client for the Techem tenant portal (mieter.techem.de).

The portal renders server-side (Next.js); its backend API needs a key only the
portal server has. So we read the same pages a browser does, with the user's
NextAuth session cookie, and pick the data objects out of the embedded React
Server Components ("flight") payload. The cookie is re-issued on every session
check, so polling keeps it alive.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import logging
import re
from urllib.parse import quote, urlsplit

import aiohttp

from .const import BASE_URL, COOKIE_PREFIX, USER_AGENT

_LOGGER = logging.getLogger(__name__)

_FLIGHT = re.compile(r'self\.__next_f\.push\(\[1,("(?:[^"\\]|\\.)*")\]\)')
_ROW = re.compile(r'\{"period":"\d{4}-\d{2}","service":"[^{}]*\}')
_AVERAGE = re.compile(r'"averageConsumption":(\{[^{}]*\})')
_AGREEMENTS = re.compile(r'"rentalAgreements":(\[[^\]]*\])')
_DETAIL = re.compile(r'/consumptions/([a-z_-]+)/(\d{4}-\d{2})"')


class TechemAuthError(Exception):
    """The session cookie is missing, expired or rejected."""


class TechemError(Exception):
    """The portal answered with something we don't understand."""


class TechemInteractionRequired(TechemError):
    """Login needs a manual step in the browser (e.g. accepting new terms).

    The credentials were accepted, but B2C showed another page instead of
    redirecting back to the portal, so no session cookie was issued.
    """


@dataclass
class ServiceData:
    """Consumption of one service (heating, hot water, ...) of one flat."""

    rows: list[dict] = field(default_factory=list)  # {period, unitOfMeasure, amount, ...}
    average: dict | None = None  # comparable households, latest month


def parse_cookies(text: str) -> dict[str, str]:
    """Accept a bare token, a 'Cookie:' header or a raw request dump."""
    text = text.strip()
    found = dict(re.findall(rf"({re.escape(COOKIE_PREFIX)}(?:\.\d+)?)=([^;\s]+)", text))
    if not found and re.fullmatch(r"[\w.-]+", text):
        found = {COOKIE_PREFIX: text}
    return found


def flight(html: str) -> str:
    return "".join(json.loads(m) for m in _FLIGHT.findall(html))


class TechemClient:
    def __init__(self, session: aiohttp.ClientSession, cookies: dict[str, str]) -> None:
        self._session = session
        self.cookies = dict(cookies)

    async def _get(self, path: str) -> aiohttp.ClientResponse:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept-Language": "de",
            "Cookie": "; ".join(f"{k}={v}" for k, v in sorted(self.cookies.items())),
        }
        resp = await self._session.get(
            BASE_URL + path, headers=headers, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=30)
        )
        # NextAuth rolls the session cookie (possibly split into .0/.1 chunks)
        rolled = {k: m.value for k, m in resp.cookies.items() if k.startswith(COOKIE_PREFIX)}
        if rolled:
            self.cookies = {k: v for k, v in rolled.items() if v}
        return resp

    async def _page(self, path: str) -> str:
        resp = await self._get(path)
        if resp.status in (301, 302, 303, 307, 308) and "auth" in resp.headers.get("location", ""):
            raise TechemAuthError("redirected to login")
        if resp.status != 200:
            raise TechemError(f"{path}: HTTP {resp.status}")
        return flight(await resp.text())

    async def session_user(self) -> str:
        """Check (and roll) the session; returns the account's subject id."""
        resp = await self._get("/api/auth/session")
        if resp.status != 200:
            raise TechemError(f"session check: HTTP {resp.status}")
        data = await resp.json(content_type=None)
        if not data or "user" not in data:
            raise TechemAuthError("session expired")
        return data.get("sub") or data["user"].get("email", "techem")

    async def units(self) -> list[str]:
        agreements = _AGREEMENTS.search(await self._page("/de"))
        if not agreements:
            raise TechemError("no rental agreements found")
        return [a["residentialUnitId"] for a in json.loads(agreements.group(1)) if a.get("residentialUnitId")]

    async def consumption(self, unit: str) -> dict[str, ServiceData]:
        base = f"/de/{quote(unit, safe=':')}/consumptions"
        services = dict(_DETAIL.findall(await self._page(base)))  # slug -> latest period
        result: dict[str, ServiceData] = {}
        for slug, period in services.items():
            page = await self._page(f"{base}/{slug}/{period}")
            data = ServiceData()
            for raw in _ROW.findall(page):
                row = json.loads(raw)
                if row.get("amount") is not None:
                    data.rows.append(row)
            if avg := _AVERAGE.search(page):
                data.average = json.loads(avg.group(1))
            # rows repeat across chart blocks: keep one per (period, unit)
            data.rows = sorted({(r["period"], r["unitOfMeasure"]): r for r in data.rows}.values(), key=lambda r: r["period"])
            service = data.rows[0]["service"] if data.rows else slug.upper()
            result[service] = data
        return result


# --- Interactive e-mail/password login (so no cookie has to be pasted) ---------
#
# The portal's login is NextAuth in front of an Azure AD B2C "CombinedSigninAndSignup"
# self-asserted page. We replay the browser flow:
#   1. get a NextAuth CSRF token and discover the OAuth provider id,
#   2. start the sign-in so NextAuth hands back the B2C authorize URL (and keeps
#      its PKCE/state in cookies),
#   3. load the B2C login page and read its embedded transaction settings,
#   4. POST the credentials to the B2C SelfAsserted endpoint,
#   5. follow the "confirmed" redirect back through the NextAuth callback, which
#      exchanges the code and sets `__Secure-next-auth.session-token`.
# The session MUST carry a real cookie jar (not DummyCookieJar), because every
# step above depends on cookies set by the previous one.

_B2C_SETTINGS = re.compile(r"var SETTINGS = (\{.*?\});", re.DOTALL)
_TIMEOUT = aiohttp.ClientTimeout(total=30)


def _session_cookies(jar: aiohttp.abc.AbstractCookieJar) -> dict[str, str]:
    """Pick the NextAuth session-token cookie(s) out of a cookie jar."""
    return {c.key: c.value for c in jar if c.key.startswith(COOKIE_PREFIX) and c.value}


async def login(session: aiohttp.ClientSession, username: str, password: str) -> dict[str, str]:
    """Log in to mieter.techem.de with e-mail and password.

    Returns the `__Secure-next-auth.session-token` cookie(s), ready to hand to
    `TechemClient`. `session` must use a real cookie jar.
    """
    headers = {"User-Agent": USER_AGENT, "Accept-Language": "de"}
    try:
        # 1. CSRF token (sets the csrf cookie) + provider discovery
        async with session.get(f"{BASE_URL}/api/auth/csrf", headers=headers, timeout=_TIMEOUT) as resp:
            csrf_body = (await resp.text()).strip()
            _LOGGER.debug("Techem csrf: HTTP %s, body starts: %.120r", resp.status, csrf_body)
            if resp.status != 200:
                raise TechemError(f"csrf: HTTP {resp.status}")
        try:
            csrf_token = json.loads(csrf_body).get("csrfToken")
        except ValueError as err:
            raise TechemError(f"csrf step returned a non-JSON body (starts: {csrf_body[:80]!r})") from err
        if not csrf_token:
            raise TechemError("portal did not return a CSRF token")

        async with session.get(f"{BASE_URL}/api/auth/providers", headers=headers, timeout=_TIMEOUT) as resp:
            prov_body = (await resp.text()).strip()
        try:
            providers = json.loads(prov_body)
        except ValueError:
            providers = {}
        provider_id = next(
            (p["id"] for p in (providers or {}).values() if p.get("type") in ("oauth", "oidc") and p.get("id")),
            "azure-ad-b2c",
        )
        _LOGGER.debug("Techem provider id: %s", provider_id)

        # 2. Begin sign-in -> NextAuth returns the B2C authorize URL
        async with session.post(
            f"{BASE_URL}/api/auth/signin/{provider_id}",
            data={"csrfToken": csrf_token, "callbackUrl": f"{BASE_URL}/de", "json": "true"},
            headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=False,
            timeout=_TIMEOUT,
        ) as resp:
            authorize_url = resp.headers.get("Location", "")
            if not authorize_url and resp.status == 200:
                try:
                    authorize_url = (await resp.json(content_type=None)).get("url", "")
                except (ValueError, aiohttp.ClientError):
                    authorize_url = ""
        _LOGGER.debug("Techem signin -> authorize url: %.120r", authorize_url)
        if "authorize" not in authorize_url and "b2clogin" not in authorize_url:
            raise TechemError("could not start the portal login")

        # 3. Load the B2C login page and read its transaction settings
        async with session.get(authorize_url, headers=headers, timeout=_TIMEOUT) as resp:
            if resp.status != 200:
                raise TechemError(f"login page: HTTP {resp.status}")
            login_page_url = str(resp.url)
            match = _B2C_SETTINGS.search(await resp.text())
        if not match:
            raise TechemError("unexpected login page")
        try:
            settings = json.loads(match.group(1))
            b2c_csrf = settings["csrf"]
            tx = settings["transId"]
            tenant = settings["hosts"]["tenant"]
            policy = settings["hosts"]["policy"]
            api = settings.get("api", "CombinedSigninAndSignup")
        except (KeyError, TypeError, ValueError) as err:
            raise TechemError("unexpected login page settings") from err

        parts = urlsplit(login_page_url)
        origin = f"{parts.scheme}://{parts.netloc}"
        base = f"{origin}{tenant}"
        query = {"tx": tx, "p": policy}

        _LOGGER.debug("Techem B2C page ok (policy=%s, api=%s); submitting credentials", policy, api)

        # 4. Submit the credentials. SelfAsserted answers with a small JSON
        #    {"status": "200"} on success; anything else we surface verbatim.
        async with session.post(
            f"{base}/SelfAsserted",
            params=query,
            data={"request_type": "RESPONSE", "signInName": username, "password": password},
            headers={
                **headers,
                "X-CSRF-TOKEN": b2c_csrf,
                "X-Requested-With": "XMLHttpRequest",
                "Origin": origin,
                "Referer": login_page_url,
            },
            allow_redirects=False,
            timeout=_TIMEOUT,
        ) as resp:
            body = (await resp.text()).strip()
            _LOGGER.debug("Techem SelfAsserted: HTTP %s, body starts: %.200r", resp.status, body)
        try:
            result = json.loads(body)
        except ValueError as err:
            raise TechemError(
                f"credential step returned HTTP {resp.status} with a non-JSON body "
                f"(starts: {body[:80]!r}); the portal login flow may have changed"
            ) from err
        if str(result.get("status")) != "200":
            raise TechemAuthError(result.get("message") or result.get("errorCode") or "login rejected")

        # 5. Follow the "confirmed" redirect chain; the NextAuth callback in it
        #    sets the session cookie in our jar.
        async with session.get(
            f"{base}/api/{api}/confirmed",
            params={"rememberMe": "false", "csrf_token": b2c_csrf, **query},
            headers={**headers, "Referer": login_page_url},
            allow_redirects=True,
            timeout=_TIMEOUT,
        ) as resp:
            await resp.read()
            _LOGGER.debug("Techem confirmed: ended at HTTP %s %s", resp.status, resp.url)
    except (aiohttp.ClientError, TimeoutError) as err:
        raise TechemError(f"login failed: {err}") from err

    cookies = _session_cookies(session.cookie_jar)
    _LOGGER.debug("Techem login produced %d session cookie(s): %s", len(cookies), list(cookies))
    if not cookies:
        raise TechemInteractionRequired(
            "the credentials were accepted but no session was issued; open "
            "mieter.techem.de once in a browser to clear any pending step "
            "(e.g. new terms to accept), then try again"
        )
    return cookies
