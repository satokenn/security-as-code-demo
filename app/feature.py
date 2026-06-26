"""わざと脆弱な機能追加（デモ用）。SAST が検出して CI を赤くするはず。"""
import sqlite3

API_KEY = "sk_live_AbCdEf123456789TOKEN"   # NG: 秘密のハードコード


def run(user_input, cursor):
    result = eval(user_input)                                            # NG: eval
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")   # NG: SQLi
    return result
