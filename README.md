# Cortex XDR – HDBSCAN Anomaly Detection

Cortex XDR alertlərini API ilə toplayır, HDBSCAN ilə klasterləşdirib anomaliyaları aşkarlayır, dashboard və e-poçt/Telegram bildirişləri təqdim edir.

## Struktur
- `core/` – API client, DB, feature engineering, train, scheduler, bildirişlər
- `dashboard/` – dashboard və hesabat generatoru
- `cortex_xdr_drawio.xml` – arxitektura diaqramı

## Quraşdırma
1. `python -m venv venv` və aktivləşdir
2. `pip install -r requirements.txt`
3. Kök qovluqda `.env` faylı yarat və aşağıdakı dəyişənləri doldur
4. Test datası üçün: `python core/generate_mock_data.py`
5. Train: `python core/train.py`, işə sal: `python core/scheduler.py`

`data/`, `logs/`, `model/` qovluqları avtomatik yaranır və git-ə daxil edilmir.

## Konfiqurasiya (`.env`)

Gizli dəyərlər repoda saxlanılmır. Yalnız dəyişən adları:

| Dəyişən | Təyinat |
|---|---|
| `CORTEX_FQDN` | Cortex XDR API ünvanı |
| `CORTEX_API_KEY_ID`, `CORTEX_API_KEY` | Cortex XDR API açarı |
| `CORTEX_AUTH_LEVEL` | `standard` və ya `advanced` |
| `POLL_INTERVAL_SECONDS` | Polling intervalı (standart 300) |
| `TRAIN_WINDOW_DAYS` | Train üçün data pəncərəsi (standart 180) |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `NOTIFY_EMAIL_TO` | E-poçt bildirişi (opsional) |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | Telegram bildirişi (opsional) |
