"""Security as Code デモ用の極小アプリ（安全版）。
このリポジトリは、生成プロジェクト側で security.yml（SAST・脅威モデル検証）が
実際に動くことを確かめるためのテスト用。"""
import os


def get_resource(current_user_id, resource_id, store):
    owner = store[resource_id]
    if owner != current_user_id:
        raise PermissionError("forbidden")
    return {"id": resource_id, "owner": owner}


def api_key():
    return os.environ["API_KEY"]   # 秘密は環境変数から（ハードコードしない）


if __name__ == "__main__":
    print("ok")
