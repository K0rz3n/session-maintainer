# helper/database_helper.py
from __future__ import annotations

import json
import pymysql
from typing import Any, Dict, Iterable, Optional

from environment.environ import environ
from helper.tools import compute_session_hash

class SessionDB:
    """
    MySQL 助手：
      - ensure_schema()：确保数据库/表存在（并在缺列时自动补列）
      - upsert_enriched_pages(pages)：批量 upsert（先 UPDATE，再 INSERT）
      - fetch_latest_sessions_by_hash(limit)：按 session_hash 去重取“最新一条”
      - update_check_state(session_hash, ok)：巡检时更新 checked_at / checked_state
      - has_any_sessions() / get_distinct_session_hashes()：供 maintainer 做首次/增量判定
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        user: str,
        password: str,
        database: str = "session_maintainer",
        connect_timeout: float = 5.0,
        charset: str = "utf8mb4",
    ) -> None:
        self._server_cfg = dict(
            host=host,
            port=port,
            user=user,
            password=password,
            connect_timeout=connect_timeout,
            charset=charset,
            autocommit=True,
            cursorclass=pymysql.cursors.DictCursor,
        )
        self._db_cfg = dict(**self._server_cfg, database=database)
        self._database = database

    # -------- 从 Environ 构造 --------
    @classmethod
    def from_environ(cls) -> "SessionDB":
        raw = None
        try:
            raw = environ.get_config("SESSION_DB")
        except Exception:
            pass
        if not isinstance(raw, dict):
            raise RuntimeError(
                "Config 'SESSION_DB' not found or not a dict. "
                "Please add it to configs/config.py"
            )

        required = ["host", "port", "user", "password", "database"]
        missing = [k for k in required if k not in raw]
        if missing:
            raise RuntimeError(f"SESSION_DB missing keys: {missing}")

        return cls(
            host=raw["host"],
            port=int(raw["port"]),
            user=raw["user"],
            password=raw["password"],
            database=raw.get("database", "session_maintainer"),
            connect_timeout=float(raw.get("connect_timeout", 5.0)),
            charset=raw.get("charset", "utf8mb4"),
        )

    # ---------- schema ----------
    def ensure_schema(self) -> None:
        self._create_database_if_not_exists()
        self._create_table_if_not_exists()
        self._ensure_json_column("sessions", "session_state_check", after="session_list")
        self._ensure_column("sessions", "checked_at", "TIMESTAMP NULL", after="updated_at")
        self._ensure_column("sessions", "checked_state", "TINYINT(1) NULL", after="checked_at")

    def _create_database_if_not_exists(self) -> None:
        conn = pymysql.connect(**self._server_cfg)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    f"CREATE DATABASE IF NOT EXISTS `{self._database}` "
                    "DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci"
                )
        finally:
            conn.close()

    def _create_table_if_not_exists(self) -> None:
        conn = pymysql.connect(**self._db_cfg)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS `sessions` (
                      `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                      `application_name` VARCHAR(255) NOT NULL,
                      `achieve_method` VARCHAR(32) NOT NULL DEFAULT 'simulation',
                      `session_page_name` VARCHAR(255) NULL,
                      `session_page_url` VARCHAR(1024) NULL,
                      `session_collection_url` VARCHAR(1024) NOT NULL,
                      `session_collection_url_query` VARCHAR(2048) NULL,
                      `session_collection_method` JSON NULL,
                      `session_collection_headers` JSON NULL,
                      `session_collection_cookies` JSON NULL,
                      `session_collection_data` JSON NULL,
                      `session_list` JSON NOT NULL,
                      `session_state_check` JSON NULL,
                      `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                      `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                      `checked_at` TIMESTAMP NULL,
                      `checked_state` TINYINT(1) NULL,
                      `session_hash` CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
                      PRIMARY KEY (`id`),
                      UNIQUE KEY `uk_session_hash` (`session_hash`)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                    """
                )
        finally:
            conn.close()

    def _ensure_json_column(self, table: str, column: str, *, after: str) -> None:
        self._ensure_column(table, column, "JSON NULL", after=after)

    def _ensure_column(self, table: str, column: str, col_def: str, *, after: str) -> None:
        conn = pymysql.connect(**self._db_cfg)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s AND COLUMN_NAME=%s
                    """,
                    (self._database, table, column),
                )
                row = cur.fetchone() or {}
                if int(row.get("cnt", 0)) == 0:
                    cur.execute(
                        f"ALTER TABLE `{table}` "
                        f"ADD COLUMN `{column}` {col_def} AFTER `{after}`"
                    )
        finally:
            conn.close()

    # ---------- 高层查询辅助 ----------
    def has_any_sessions(self) -> bool:
        # 用 EXISTS 避免返回列名奇怪导致的取值问题
        sql = "SELECT EXISTS(SELECT 1 FROM sessions LIMIT 1) AS has_any"
        conn = pymysql.connect(**self._db_cfg)
        try:
            with conn.cursor() as cur:
                cur.execute(sql)
                row = cur.fetchone() or {}
                if isinstance(row, dict):
                    return bool(int(row.get("has_any", 0)))
                # 普通 Cursor 的兜底
                (val,) = row
                return bool(int(val))
        finally:
            conn.close()

    def get_distinct_session_hashes(self) -> set[str]:
        sql = "SELECT DISTINCT session_hash FROM sessions"
        out: set[str] = set()
        conn = pymysql.connect(**self._db_cfg)
        try:
            with conn.cursor() as cur:
                cur.execute(sql)
                rows = cur.fetchall() or []
                for row in rows:
                    if isinstance(row, dict):        # DictCursor 的情况
                        h = row.get("session_hash")
                    else:                            # 普通 Cursor -> tuple
                        (h,) = row
                    if isinstance(h, str):
                        out.add(h)
        finally:
            conn.close()
        return out
    

    # ---------- upsert ----------
    def upsert_enriched_pages(self, pages: Iterable[Dict[str, Any]]) -> int:
        rows = [self._page_to_row(p) for p in (pages or [])]
        if not rows:
            return 0

        update_sql = """
        UPDATE `sessions` SET
            `application_name` = %(application_name)s,
            `achieve_method` = %(achieve_method)s,
            `session_page_name` = %(session_page_name)s,
            `session_page_url` = %(session_page_url)s,
            `session_collection_url` = %(session_collection_url)s,
            `session_collection_url_query` = %(session_collection_url_query)s,
            `session_collection_method` = %(session_collection_method)s,
            `session_collection_headers` = %(session_collection_headers)s,
            `session_collection_cookies` = %(session_collection_cookies)s,
            `session_collection_data` = %(session_collection_data)s,
            `session_list` = %(session_list)s,
            `session_state_check` = %(session_state_check)s,
            `updated_at` = CURRENT_TIMESTAMP
        WHERE `session_hash` = %(session_hash)s
        """

        insert_sql = """
        INSERT INTO `sessions` (
            `application_name`,
            `achieve_method`,
            `session_page_name`,
            `session_page_url`,
            `session_collection_url`,
            `session_collection_url_query`,
            `session_collection_method`,
            `session_collection_headers`,
            `session_collection_cookies`,
            `session_collection_data`,
            `session_list`,
            `session_state_check`,
            `session_hash`
        ) VALUES (
            %(application_name)s,
            %(achieve_method)s,
            %(session_page_name)s,
            %(session_page_url)s,
            %(session_collection_url)s,
            %(session_collection_url_query)s,
            %(session_collection_method)s,
            %(session_collection_headers)s,
            %(session_collection_cookies)s,
            %(session_collection_data)s,
            %(session_list)s,
            %(session_state_check)s,
            %(session_hash)s
        )
        """

        affected_total = 0
        conn = pymysql.connect(**self._db_cfg)
        try:
            with conn.cursor() as cur:
                for row in rows:
                    cur.execute(update_sql, row)
                    if cur.rowcount > 0:
                        affected_total += cur.rowcount
                        continue
                    try:
                        cur.execute(insert_sql, row)
                        affected_total += cur.rowcount
                    except pymysql.err.IntegrityError as e:
                        # 并发下 insert 可能撞唯一键；回退到 update
                        if getattr(e, "args", [None])[0] == 1062:
                            cur.execute(update_sql, row)
                            affected_total += cur.rowcount
                        else:
                            raise
            conn.commit()
            return int(affected_total or 0)
        finally:
            conn.close()

    # ---------- JSON 读写辅助 ----------
    @staticmethod
    def _to_json_or_sql_null(val: Any) -> Optional[str]:
        if val is None:
            return None
        return json.dumps(val, ensure_ascii=False)

    def _page_to_row(self, page: Dict[str, Any]) -> Dict[str, Any]:
        application_name = page.get("application_name")
        session_collection_url = page.get("session_collection_url")
        method_json = page.get("session_collection_method")
        headers = page.get("session_collection_headers") or {}
        cookies = page.get("session_collection_cookies") or {}
        data_val = page.get("session_collection_data")
        session_list = page.get("session_list") or []
        achieve_method = page.get("achieve_method") or "simulation"
        state_check = page.get("session_state_check")

        return {
            "application_name": application_name,
            "achieve_method": achieve_method,
            "session_page_name": page.get("session_page_name"),
            "session_page_url": page.get("session_page_url"),
            "session_collection_url": session_collection_url,
            "session_collection_url_query": page.get("session_collection_url_query"),
            "session_collection_method": self._to_json_or_sql_null(method_json),
            "session_collection_headers": self._to_json_or_sql_null(headers),
            "session_collection_cookies": self._to_json_or_sql_null(cookies),
            "session_collection_data": self._to_json_or_sql_null(data_val),
            "session_list": self._to_json_or_sql_null(session_list),
            "session_state_check": self._to_json_or_sql_null(state_check),
            "session_hash": compute_session_hash(application_name, session_collection_url),
        }

    def _maybe_json_load(self, val: Any) -> Any:
        if val is None:
            return None
        if isinstance(val, (dict, list)):
            return val
        if isinstance(val, (bytes, bytearray)):
            try:
                return json.loads(val.decode("utf-8"))
            except Exception:
                return val
        if isinstance(val, str):
            v = val.strip()
            if not v:
                return None
            try:
                return json.loads(v)
            except Exception:
                return val
        return val

    def _row_jsonify(self, row: Dict[str, Any]) -> Dict[str, Any]:
        jcols = [
            "session_collection_method",
            "session_collection_headers",
            "session_collection_cookies",
            "session_collection_data",
            "session_list",
            "session_state_check",
        ]
        out = dict(row or {})
        for k in jcols:
            if k in out:
                out[k] = self._maybe_json_load(out.get(k))
        return out

    # ---------- 查询：每个 session_hash 最新一条 ----------
    def fetch_latest_sessions_by_hash(self, limit: int = 10_000_000) -> Iterable[Dict[str, Any]]:
        sql = """
        SELECT s.*
        FROM sessions s
        JOIN (
            SELECT session_hash, MAX(updated_at) AS mx
            FROM sessions
            GROUP BY session_hash
        ) t
          ON s.session_hash = t.session_hash AND s.updated_at = t.mx
        ORDER BY s.updated_at DESC
        LIMIT %s
        """
        rows: list[dict] = []
        conn = pymysql.connect(**self._db_cfg)
        try:
            with conn.cursor() as cur:
                cur.execute(sql, (int(limit),))
                for r in cur.fetchall() or []:
                    rows.append(self._row_jsonify(r))
        finally:
            conn.close()
        return rows

    # ---------- 巡检结果更新 ----------
    def update_check_state(self, session_hash: str, ok: bool) -> int:
        sql = """
        UPDATE `sessions`
        SET `checked_at` = NOW(),
            `checked_state` = %s
        WHERE `session_hash` = %s
        """
        conn = pymysql.connect(**self._db_cfg)
        try:
            with conn.cursor() as cur:
                cur.execute(sql, (1 if ok else 0, session_hash))
                affected = cur.rowcount
            conn.commit()
            return int(affected or 0)
        finally:
            conn.close()