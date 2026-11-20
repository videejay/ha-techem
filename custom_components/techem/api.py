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
from urllib.parse import quote, urlencode, urljoin, urlsplit

import aiohttp

from .const import BASE_URL, COOKIE_PREFIX, USER_AGENT

_LOGGER = logging.getLogger(__name__)

_FLIGHT = re.compile(r'self\.__next_f\.push\(\[1,("(?:[^"\\]|\\.)*")\]\)')
# Detail links look like /consumptions/<slug>/<YYYY-MM>; the slug can be any
# token the portal chooses (letters, digits, dashes, ...), so match greedily.
_DETAIL = re.compile(r'/consumptions/([^/"]+)/(\d{4}-\d{2})"')


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


def _walk_dicts(obj: object):
    """Yield every dict nested anywhere inside obj (including obj itself)."""
    if isinstance(obj, dict):
        yield obj
        for value in obj.values():
            yield from _walk_dicts(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _walk_dicts(value)


def _find_objects(text: str, *keys: str):
    """Yield every JSON object embedded in `text` that has all of `keys`.

    The portal's flight payload is a stream of JSON fragments, not one valid
    document, and the objects we want can sit anywhere (standalone or nested in
    a parent). So we scan for each `{`, let the JSON decoder consume the whole
    object there, then walk it for matching sub-objects. This is independent of
    key order and survives nested braces, unlike a flat regex.
    """
    decoder = json.JSONDecoder()
    index = 0
    length = len(text)
    while index < length:
        start = text.find("{", index)
        if start < 0:
            return
        try:
            obj, end = decoder.raw_decode(text, start)
        except ValueError:
            index = start + 1
            continue
        for candidate in _walk_dicts(obj):
            if all(key in candidate for key in keys):
                yield candidate
        index = max(end, start + 1)


def _collect_rows(page: str) -> list[dict]:
    """Every consumption row on a page, whatever the service or key order."""
    return [
        row
        for row in _find_objects(page, "period", "unitOfMeasure", "amount")
        if row.get("amount") is not None
    ]


def _collect_average(page: str) -> dict | None:
    """The 'comparable households' average, if the page carries one."""
    for obj in _find_objects(page, "averageConsumption"):
        avg = obj["averageConsumption"]
        if isinstance(avg, dict) and avg.get("amount") is not None:
            return avg
    return None


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
        page = await self._page("/de")
        units: list[str] = []
        for agreement in _find_objects(page, "residentialUnitId"):
            uid = agreement.get("residentialUnitId")
            if uid and uid not in units:
                units.append(uid)
        if not units:
            raise TechemError("no rental agreements found")
        return units

    async def consumption(self, unit: str) -> dict[str, ServiceData]:
        """Every service, every month, every field the portal exposes for a unit.

        We read the consumptions index (which already carries rows) and, for
        each service it links to, the detail page with that service's full
        history and household average, then merge everything by service name.
        """
        base = f"/de/{quote(unit, safe=':')}/consumptions"
        index = await self._page(base)

        # slug -> newest linked period (the detail page of the newest period
        # carries the whole history, so one fetch per service is enough)
        latest: dict[str, str] = {}
        for slug, period in _DETAIL.findall(index):
            if period > latest.get(slug, ""):
                latest[slug] = period

        pages = [index]
        for slug, period in latest.items():
            try:
                pages.append(await self._page(f"{base}/{slug}/{period}"))
            except TechemError as err:
                _LOGGER.debug("Techem detail page %s/%s failed: %s", slug, period, err)

        result: dict[str, ServiceData] = {}
        for page in pages:
            rows_by_service: dict[str, list[dict]] = {}
            for row in _collect_rows(page):
                rows_by_service.setdefault(row.get("service") or "UNKNOWN", []).append(row)
            if not rows_by_service:
                continue
            average = _collect_average(page)
            for service, rows in rows_by_service.items():
                data = result.setdefault(service, ServiceData())
                data.rows.extend(rows)
                # a detail page is about one service, so its average is that
                # service's; skip the ambiguous index page (many services)
                if average and data.average is None and len(rows_by_service) == 1:
                    data.average = average

        # rows repeat across chart/table blocks: keep one per (period, unit)
        for data in result.values():
            data.rows = sorted(
                {(r["period"], r["unitOfMeasure"]): r for r in data.rows}.values(),
                key=lambda r: r["period"],
            )
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


class _Cookies:
    """Minimal cookie jar we drive by hand.

    aiohttp's own CookieJar mangles the Cookie header for this flow (Azure B2C
    sets a cache cookie whose *name* contains a '|', and the gateway then
    rejects the request with a plain "Bad Request" instead of the JSON the
    login expects). So, like TechemClient, we collect Set-Cookie values and
    send them back verbatim.
    """

    def __init__(self) -> None:
        self._c: dict[str, str] = {}

    def header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self._c.items())

    def absorb(self, resp: aiohttp.ClientResponse) -> None:
        for raw in resp.headers.getall("Set-Cookie", []):
            name_value = raw.split(";", 1)[0]
            if "=" not in name_value:
                continue
            key, _, value = name_value.partition("=")
            key, value = key.strip(), value.strip()
            if not value or value.lower() == "deleted":
                self._c.pop(key, None)
            else:
                self._c[key] = value

    def session_cookies(self) -> dict[str, str]:
        return {k: v for k, v in self._c.items() if k.startswith(COOKIE_PREFIX) and v}


async def _request(
    session: aiohttp.ClientSession,
    cookies: _Cookies,
    method: str,
    url: str,
    *,
    data: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
    extra: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    """One request, following redirects by hand so cookies survive every hop."""
    if params:
        url = url + ("&" if "?" in url else "?") + urlencode(params)
    for _ in range(12):
        headers = {"User-Agent": USER_AGENT, "Accept-Language": "de", **(extra or {})}
        if cookie_header := cookies.header():
            headers["Cookie"] = cookie_header
        async with session.request(
            method, url, data=data, headers=headers, allow_redirects=False, timeout=_TIMEOUT
        ) as resp:
            cookies.absorb(resp)
            body = await resp.read()
            location = resp.headers.get("Location")
            if resp.status in (301, 302, 303, 307, 308) and location:
                url = urljoin(str(resp.url), location)
                method, data, extra = "GET", None, None
                continue
            return resp.status, str(resp.url), body.decode("utf-8", "replace")
    raise TechemError("too many redirects during login")


async def login(session: aiohttp.ClientSession, username: str, password: str) -> dict[str, str]:
    """Log in to mieter.techem.de with e-mail and password.

    Replays the portal's NextAuth -> Azure AD B2C browser login and returns the
    resulting `__Secure-next-auth.session-token` cookie(s), ready for TechemClient.
    Cookies and redirects are handled manually (see `_Cookies`), so the session
    should use an aiohttp.DummyCookieJar.
    """
    cookies = _Cookies()
    try:
        # 1. CSRF token (sets the csrf cookie) + provider discovery
        status, _, body = await _request(session, cookies, "GET", f"{BASE_URL}/api/auth/csrf")
        _LOGGER.debug("Techem csrf: HTTP %s", status)
        try:
            csrf_token = json.loads(body).get("csrfToken")
        except ValueError as err:
            raise TechemError(f"csrf step returned a non-JSON body (starts: {body[:80]!r})") from err
        if not csrf_token:
            raise TechemError("portal did not return a CSRF token")

        _, _, prov_body = await _request(session, cookies, "GET", f"{BASE_URL}/api/auth/providers")
        try:
            providers = json.loads(prov_body)
        except ValueError:
            providers = {}
        provider_id = next(
            (p["id"] for p in (providers or {}).values() if p.get("type") in ("oauth", "oidc") and p.get("id")),
            "azure-b2c",
        )
        _LOGGER.debug("Techem provider id: %s", provider_id)

        # 2. Begin sign-in -> NextAuth returns the B2C authorize URL
        status, _, body = await _request(
            session, cookies, "POST", f"{BASE_URL}/api/auth/signin/{provider_id}",
            data={"csrfToken": csrf_token, "callbackUrl": f"{BASE_URL}/de", "json": "true"},
            extra={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            authorize_url = json.loads(body).get("url", "")
        except ValueError:
            authorize_url = ""
        _LOGGER.debug("Techem signin -> authorize url: %.120r", authorize_url)
        if "authorize" not in authorize_url and "b2clogin" not in authorize_url:
            raise TechemError("could not start the portal login")

        # 3. Load the B2C login page and read its transaction settings
        status, login_page_url, html = await _request(session, cookies, "GET", authorize_url)
        if status != 200:
            raise TechemError(f"login page: HTTP {status}")
        match = _B2C_SETTINGS.search(html)
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
        status, _, body = await _request(
            session, cookies, "POST", f"{base}/SelfAsserted", params=query,
            data={"request_type": "RESPONSE", "signInName": username, "password": password},
            extra={
                "X-CSRF-TOKEN": b2c_csrf,
                "X-Requested-With": "XMLHttpRequest",
                "Origin": origin,
                "Referer": login_page_url,
            },
        )
        _LOGGER.debug("Techem SelfAsserted: HTTP %s, body starts: %.200r", status, body)
        try:
            result = json.loads(body)
        except ValueError as err:
            raise TechemError(
                f"credential step returned HTTP {status} with a non-JSON body "
                f"(starts: {body[:80]!r}); the portal login flow may have changed"
            ) from err
        if str(result.get("status")) != "200":
            raise TechemAuthError(result.get("message") or result.get("errorCode") or "login rejected")

        # 5. Follow the "confirmed" redirect chain; the NextAuth callback in it
        #    sets the session cookie, which we collect in `cookies`.
        status, final_url, _ = await _request(
            session, cookies, "GET", f"{base}/api/{api}/confirmed",
            params={"rememberMe": "false", "csrf_token": b2c_csrf, **query},
            extra={"Referer": login_page_url},
        )
        _LOGGER.debug("Techem confirmed: ended at HTTP %s %s", status, final_url)
    except (aiohttp.ClientError, TimeoutError) as err:
        raise TechemError(f"login failed: {err}") from err

    session_cookies = cookies.session_cookies()
    _LOGGER.debug("Techem login produced %d session cookie(s): %s", len(session_cookies), list(session_cookies))
    if not session_cookies:
        raise TechemInteractionRequired(
            "the credentials were accepted but no session was issued; open "
            "mieter.techem.de once in a browser to clear any pending step "
            "(e.g. new terms to accept), then try again"
        )
    return session_cookies
