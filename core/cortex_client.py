import time
import hashlib
import secrets
import logging
import requests
from datetime import datetime, timezone
 
from config import CORTEX_FQDN, API_KEY, API_KEY_ID, AUTH_LEVEL
 
logger = logging.getLogger(__name__)
 
MAX_PAGE_SIZE = 100  # Cortex XDR-ın bir sorğuda qaytardığı maksimum sətir sayı
 
 
def _build_url() -> str:
    fqdn = CORTEX_FQDN
    # Bəzi tenant-larda "Copy URL" artıq "api-" prefiksi ilə gəlir, bəzilərində yox.
    if not fqdn.startswith("api-"):
        fqdn = f"api-{fqdn}"
    return f"https://{fqdn}/public_api/v1/alerts/get_alerts_multi_events/"
 
 
def _headers() -> dict:
    if AUTH_LEVEL.lower() == "standard":
        return {
            "x-xdr-auth-id": str(API_KEY_ID),
            "Authorization": API_KEY,
            "Content-Type": "application/json",
        }
 
    # Advanced security level
    nonce = "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(64))
    timestamp = str(int(time.time() * 1000))
    auth_str = f"{API_KEY}{nonce}{timestamp}".encode("utf-8")
    auth_hash = hashlib.sha256(auth_str).hexdigest()
    return {
        "x-xdr-timestamp": timestamp,
        "x-xdr-nonce": nonce,
        "x-xdr-auth-id": str(API_KEY_ID),
        "Authorization": auth_hash,
        "Content-Type": "application/json",
    }
 
 
def fetch_alerts(since_ms: int, until_ms: int = None, time_field: str = "server_creation_time",
                  page_size: int = MAX_PAGE_SIZE, max_pages: int = 100, severities: list = None,
                  sort_order: str = "asc") -> list:
    """
    Cortex XDR-dan verilmiş vaxt aralığındaki bütün alertləri (səhifələyərək) çəkir.
 
    since_ms / until_ms : epoch millisaniyə
    time_field          : "server_creation_time" (tövsiyə olunur, polling üçün) və ya "creation_time"
                          (Cortex API-nin qəbul etdiyi DƏQİQ adlar: alert_id_list, external_id_list,
                           alert_source, creation_time, last_modified_ts, server_creation_time, severity)
    severities          : məs. ["high", "medium"] - boş saxlasan hamısı gələr
    sort_order          : "asc" (ən köhnədən) və ya "desc" (ən yenidən) - diaqnostika üçün faydalıdır
 
    Qaytarır: hər biri bütöv (bütün field-ləri ilə) alert dict-i olan siyahı
    """
    url = _build_url()
    page_size = min(page_size, MAX_PAGE_SIZE)
    all_alerts = []
    search_from = 0
 
    for page in range(max_pages):
        filters = [{"field": time_field, "operator": "gte", "value": int(since_ms)}]
        if until_ms:
            filters.append({"field": time_field, "operator": "lte", "value": int(until_ms)})
        if severities:
            filters.append({"field": "severity", "operator": "in", "value": severities})
 
        payload = {
            "request_data": {
                "filters": filters,
                "search_from": search_from,
                "search_to": search_from + page_size,
                "sort": {"field": time_field, "keyword": sort_order},
            }
        }
 
        resp = requests.post(url, headers=_headers(), json=payload, timeout=60)
        if resp.status_code != 200:
            logger.error("Cortex XDR API xətası: %s - %s", resp.status_code, resp.text[:500])
            resp.raise_for_status()
 
        data = resp.json()
        alerts = data.get("reply", {}).get("alerts", [])
        if not alerts:
            break
 
        all_alerts.extend(alerts)
        logger.info("Səhifə %d: %d alert çəkildi (cəmi: %d)", page + 1, len(alerts), len(all_alerts))
 
        if len(alerts) < page_size:
            break
        search_from += page_size
        time.sleep(0.4)  # səhifələr arasında kiçik fasilə - rate-limit/bloklanmadan qorunmaq üçün
 
    return all_alerts
 
 
def _build_xql_url(path: str) -> str:
    fqdn = CORTEX_FQDN
    if not fqdn.startswith("api-"):
        fqdn = f"api-{fqdn}"
    return f"https://{fqdn}/public_api/v1/xql/{path}/"
 
 
def start_xql_query(query: str) -> str:
    """XQL sorğusunu başladır, query_id qaytarır (nəticələr hazır olana qədər gözləmək lazımdır)."""
    url = _build_xql_url("start_xql_query")
    payload = {"request_data": {"query": query}}
    resp = requests.post(url, headers=_headers(), json=payload, timeout=60)
    if resp.status_code != 200:
        logger.error("XQL start xətası: %s - %s", resp.status_code, resp.text[:500])
        resp.raise_for_status()
    data = resp.json()
    reply = data.get("reply")
    # Cortex bəzən reply-i birbaşa string (query_id) kimi, bəzən dict kimi qaytarır
    if isinstance(reply, dict):
        query_id = reply.get("query_id") or reply.get("queryId")
    else:
        query_id = reply
    if not query_id:
        raise RuntimeError(f"XQL query_id alına bilmədi, server cavabı: {data}")
    return query_id
 
 
def get_xql_results(query_id: str, limit: int = 1000, max_wait_seconds: int = 90) -> dict:
    """Nəticələr hazır olana qədər (status != PENDING) gözləyib qaytarır."""
    url = _build_xql_url("get_query_results")
    waited = 0
    poll_interval = 2
    while waited <= max_wait_seconds:
        payload = {"request_data": {"query_id": query_id, "pending_flag": True, "limit": limit, "format": "json"}}
        resp = requests.post(url, headers=_headers(), json=payload, timeout=60)
        if resp.status_code != 200:
            logger.error("XQL nəticə xətası: %s - %s", resp.status_code, resp.text[:500])
            resp.raise_for_status()
        data = resp.json()
        reply = data.get("reply", {})
        status = reply.get("status")
        if status == "SUCCESS":
            return reply
        if status in ("FAIL", "ERROR"):
            raise RuntimeError(f"XQL sorğusu uğursuz oldu: {reply}")
        # status == PENDING -> bir az gözlə, yenidən sor
        time.sleep(poll_interval)
        waited += poll_interval
    raise TimeoutError(f"XQL nəticələri {max_wait_seconds} saniyə ərzində hazır olmadı (query_id={query_id})")
 
 
def fetch_alerts_xql(since_ms: int, limit: int = 1000, dataset: str = "alerts") -> list:
    """
    XQL Query API ilə canlı 'alerts' dataset-indən alertləri çəkir.
    Bu, klassik get_alerts_multi_events-dən fərqli olaraq YENİ Cortex Platform-da
    canlı datanı görür (köhnə REST API yalnız dondurulmuş/köhnə datanı görürdü).
 
    Qeyd: bir sorğuda maksimum 1000 nəticə qayıdır (Cortex limiti). 1000-dən çox
    alert gözlənilirsə, since_ms aralığını kiçildib bir neçə dəfə çağırmaq lazımdır.
    """
    since_str = datetime.fromtimestamp(since_ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    query = f'dataset = {dataset} | filter _time >= "{since_str}" | limit {limit}'
    logger.info("XQL sorğusu: %s", query)
    query_id = start_xql_query(query)
    reply = get_xql_results(query_id, limit=limit)
    rows = reply.get("results", {}).get("data", []) or []
    rows.sort(key=lambda r: r.get("_time") or 0)  # Python tərəfində xronoloji sıralama
    n_total = reply.get("number_of_results", len(rows))
    SERVER_HARD_CAP = 1000  # Cortex XQL-in bir sorğuda qaytardığı maksimum nəticə sayı
    if n_total >= SERVER_HARD_CAP or len(rows) >= SERVER_HARD_CAP:
        logger.warning(
            "XQL nəticəsi server limitinə (%d) çatdı - bu pəncərədə daha çox alert ola bilər, "
            "since_ms aralığını kiçildib yenidən yoxlamaq tövsiyə olunur.", SERVER_HARD_CAP
        )
    return rows
 
 
if __name__ == "__main__":
    # Sürətli test: son 24 saatın alertlərini çəkib sayını çap edir
    logging.basicConfig(level=logging.INFO)
    now_ms = int(time.time() * 1000)
    since = now_ms - 24 * 60 * 60 * 1000
    result = fetch_alerts_xql(since_ms=since)
    print(f"Cəmi {len(result)} alert tapıldı.")
    if result:
        print("Nümunə alert field-ləri:", list(result[0].keys()))