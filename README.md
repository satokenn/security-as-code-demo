# security-as-code-demo

ai-company フレームワークの Security as Code を、生成プロジェクト側で実証するためのテスト用リポジトリ。

含まれるもの（フレームワークの雛形を持ち込んだだけ）:

- `security/policy.yaml` … セキュリティ方針（SEC-01..06）
- `security/threat-model.yaml` … 機械可読な脅威モデル（policy と鎖が閉じている）
- `security/semgrep-rules.yaml` … SAST ルール
- `security/scripts/validate_threat_model.py` … 脅威モデル検証
- `.github/workflows/security.yml` … セキュリティCI（PR/push で実行）

CI は PR ごとに走り、SAST（semgrep）と脅威モデル検証が実際に判定する。
わざと脆弱なコード（`eval` や秘密のハードコード）を入れると CI が赤くなる。
