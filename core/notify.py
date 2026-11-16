"""
Yüksək-risk anomaliyalar üçün bildiriş göndərmə modulu.

Hər ikisi (email, Telegram) opsionaldır - .env-də doldurulmamış olanı sakitcə
keçilir (xəta vermir). Heç biri doldurulmayıbsa, heç nə göndərilmir.

Konfiqurasiya .env-də:
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, NOTIFY_EMAIL_TO
  TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
"""

import logging
import smtplib
from email.mime.text import MIMEText

import requests

from config import (
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, NOTIFY_EMAIL_TO,
    TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID,
)

logger = logging.getLogger(__name__)


def _send_email(subject: str, body: str) -> bool:
    if not (SMTP_HOST and SMTP_USER and SMTP_PASSWORD and NOTIFY_EMAIL_TO):
        return False
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = SMTP_USER
        msg["To"] = NOTIFY_EMAIL_TO
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, [NOTIFY_EMAIL_TO], msg.as_string())
        logger.info("Email bildirişi göndərildi: %s", subject)
        return True
    except Exception:
        logger.exception("Email bildirişi göndərilərkən xəta baş verdi")
        return False


def _send_telegram(text: str) -> bool:
    if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
        return False
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        resp = requests.post(
            url, json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"}, timeout=15
        )
        if resp.status_code != 200:
            logger.error("Telegram bildiriş xətası: %s - %s", resp.status_code, resp.text[:300])
            return False
        logger.info("Telegram bildirişi göndərildi")
        return True
    except Exception:
        logger.exception("Telegram bildirişi göndərilərkən xəta baş verdi")
        return False


def notify_high_risk_anomalies(df_high_risk) -> None:
    """
    df_high_risk: yeni aşkarlanan, yüksək riskli (severity HIGH/CRITICAL + is_anomaly) alertlər.
    Heç bir kanal konfiqurasiya olunmayıbsa, sakitcə heç nə etmir.
    """
    if df_high_risk is None or len(df_high_risk) == 0:
        return

    lines = [f"⚠️ {len(df_high_risk)} yeni yüksək-risk anomaliya aşkarlandı:\n"]
    for _, row in df_high_risk.head(10).iterrows():
        lines.append(
            f"- [{row.get('severity')}] {row.get('alert_name')} "
            f"(host: {row.get('host_name') or '-'}, səbəb: {row.get('anomaly_reason')})"
        )
    if len(df_high_risk) > 10:
        lines.append(f"... və daha {len(df_high_risk) - 10} alert")
    body = "\n".join(lines)

    sent_email = _send_email("Cortex XDR - Yüksək risk anomaliya bildirişi", body)
    sent_tg = _send_telegram(body)

    if not sent_email and not sent_tg:
        logger.info("Bildiriş kanalları konfiqurasiya olunmayıb (.env boşdur) - bildiriş göndərilmədi")
