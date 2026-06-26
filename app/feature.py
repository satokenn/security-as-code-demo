"""機能追加（修正版）。脆弱性を取り除いた。SAST は緑になるはず。"""
import os
import sqlite3


def api_key():
    return os.environ["API_KEY"]   # 環境変数から（ハードコードしない）


def run(user_input, cursor):
    # eval を使わず、パラメータ化クエリで安全に
    cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))
    return cursor.fetchall()
