"""Application-wide constants for the Cryptographic Security Layer for USB Storage."""

APP_NAME = "Cryptographic Security Layer for USB Storage"
APP_SHORT_NAME = "CryptoUSB"
APP_ORGANIZATION = "CryptoUSB Research Project"
APP_VERSION = "0.1.0"

DEFAULT_LOG_LEVEL = "INFO"
LOG_FILE_NAME = "app.log"
CONFIG_FILE_NAME = "config.json"
DATABASE_FILE_NAME = "crypto_usb.db"

SCHEMA_VERSION = 1

# Sender module: files above this size are rejected during queue validation.
MAX_QUEUE_FILE_SIZE_BYTES = 4 * 1024 ** 3  # 4 GiB

# Single local-machine account identity, until a multi-user identity system exists.
LOCAL_OWNER_ID = "local-user"
