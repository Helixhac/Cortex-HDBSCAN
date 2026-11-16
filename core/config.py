import os
from pathlib import Path
from dotenv import load_dotenv
 
CORE_DIR = Path(__file__).resolve().parent
BASE_DIR = CORE_DIR.parent
 
load_dotenv(BASE_DIR / ".env")
 
# ---- Cortex XDR credential-ları (.env-dən gəlir) ----
CORTEX_FQDN = os.environ.get("CORTEX_FQDN", "api-xxxxx.xdr.eu.paloaltonetworks.com")
API_KEY_ID = os.environ.get("CORTEX_API_KEY_ID", "REPLACE_ME")
API_KEY = os.environ.get("CORTEX_API_KEY", "REPLACE_ME")
AUTH_LEVEL = os.environ.get("CORTEX_AUTH_LEVEL", "standard")
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", 5 * 60))
 
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "model"
LOGS_DIR = BASE_DIR / "logs"
for d in (DATA_DIR, MODEL_DIR, LOGS_DIR):
    d.mkdir(parents=True, exist_ok=True)
 
DB_PATH = str(DATA_DIR / "cortex_alerts.db")
MODEL_PATH = str(MODEL_DIR / "hdbscan_model.joblib")
LOG_PATH = str(LOGS_DIR / "scheduler.log")
 
# ---- Performans: train üçün məlumat pəncərəsi ----
# Data illərlə yığılsa belə, hər train zamanı YALNIZ son bu qədər günün datası
# istifadə olunur ki, hesablama vaxtı sabit qalsın (sonsuz böyüməsin).
TRAIN_WINDOW_DAYS = int(os.environ.get("TRAIN_WINDOW_DAYS", 180))
 
# ---- Bildiriş tənzimləmələri (hər ikisi də opsionaldır, .env-də doldurulmasa söndürülmüş olur) ----
# E-poçt (SMTP)
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
NOTIFY_EMAIL_TO = os.environ.get("NOTIFY_EMAIL_TO", "")
 
# Telegram bot
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")