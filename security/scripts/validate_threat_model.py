"""
脅威モデル（threat-model.yaml）を検証し、policy.yaml と相互整合を機械的に確認するスクリプト。
Threat Modeling as Code の検証本体。CI（threat-model-check）と各工程の品質ゲートが使う。

外部スキャナに依存しない自己完結の検証なので、スキャナ未有効化の現段階でも「実際に動くゲート」になる。

Usage:
  python security/scripts/validate_threat_model.py
  python security/scripts/validate_threat_model.py --threat-model security/threat-model.yaml --policy security/policy.yaml

終了コード: 0=OK / 1=検証NG / 2=ファイル不備（読込・パス・YAML不正）

検証ルール:
  1. threat-model.yaml / policy.yaml が存在し妥当な YAML である
  2. 各 threat に id（一意）・stride（許可語）・control（policy.controls のキー）・sec_id が揃う
  3. threat.assets / threat.boundary は assets / trust_boundaries で定義済みの ID を指す
  4. threat.sec_id は policy.sec_requirements に存在する SEC-ID である
  5. policy.sec_requirements の全 SEC-ID に、対応する threat が最低1つある（鎖が切れていない）
  6. residual_risk は none/accepted/deferred/manual のいずれか（accepted は policy.exceptions 推奨）

注: 空の雛形（assets/threats と sec_requirements がともに空）は「未記入＝整合」として OK にする。
    工程ごとの「中身が空でないか」は各 quality-gate が別途判定する。
"""

import argparse
import sys

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML が必要です（pip install pyyaml）", file=sys.stderr)
    sys.exit(2)

STRIDE = {
    "spoofing",
    "tampering",
    "repudiation",
    "information_disclosure",
    "denial_of_service",
    "elevation_of_privilege",
}
RESIDUAL = {"none", "accepted", "deferred", "manual"}


def load_yaml(path):
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        print(f"ERROR: ファイルが見つかりません: {path}", file=sys.stderr)
        sys.exit(2)
    except yaml.YAMLError as e:
        print(f"ERROR: YAML として不正です: {path}\n{e}", file=sys.stderr)
        sys.exit(2)


def main():
    parser = argparse.ArgumentParser(description="脅威モデルを検証し policy.yaml と相互整合を確認する")
    parser.add_argument("--threat-model", default="security/threat-model.yaml")
    parser.add_argument("--policy", default="security/policy.yaml")
    args = parser.parse_args()

    tm = load_yaml(args.threat_model)
    policy = load_yaml(args.policy)

    errors = []

    control_keys = set((policy.get("controls") or {}).keys())
    policy_sec_ids = {
        s.get("sec_id")
        for s in (policy.get("sec_requirements") or [])
        if isinstance(s, dict) and s.get("sec_id")
    }

    asset_ids = {a.get("id") for a in (tm.get("assets") or []) if isinstance(a, dict)}
    boundary_ids = {b.get("id") for b in (tm.get("trust_boundaries") or []) if isinstance(b, dict)}
    threats = tm.get("threats") or []

    assurance = (policy.get("assurance_level") or "ASVS-L1").upper()
    # 保証レベルが L2 以上なら「網羅の床」を満たさないと NG、L1 なら警告にとどめる。
    coverage_is_error = assurance not in ("ASVS-L1", "L1")

    seen_ids = set()
    threat_sec_ids = set()
    referenced_assets = set()
    referenced_boundaries = set()

    for i, t in enumerate(threats):
        if not isinstance(t, dict):
            errors.append(f"threats[{i}]: マッピングでない（id:... の形で書く）")
            continue
        tid = t.get("id") or f"(index {i})"

        if not t.get("id"):
            errors.append(f"threats[{i}]: id が無い")
        elif t["id"] in seen_ids:
            errors.append(f"{tid}: id が重複している")
        else:
            seen_ids.add(t["id"])

        stride = t.get("stride")
        if stride not in STRIDE:
            errors.append(f"{tid}: stride が不正（{stride!r}）。許可: {sorted(STRIDE)}")

        control = t.get("control")
        if not control:
            errors.append(f"{tid}: control が無い（policy.controls のキーを指定する）")
        elif control_keys and control not in control_keys:
            errors.append(f"{tid}: control '{control}' が policy.controls に存在しない")

        sec_id = t.get("sec_id")
        if not sec_id:
            errors.append(f"{tid}: sec_id が無い")
        else:
            threat_sec_ids.add(sec_id)
            if policy_sec_ids and sec_id not in policy_sec_ids:
                errors.append(f"{tid}: sec_id '{sec_id}' が policy.sec_requirements に存在しない")

        for a in t.get("assets") or []:
            referenced_assets.add(a)
            if asset_ids and a not in asset_ids:
                errors.append(f"{tid}: assets '{a}' が assets で未定義")

        b = t.get("boundary")
        if b:
            referenced_boundaries.add(b)
            if boundary_ids and b not in boundary_ids:
                errors.append(f"{tid}: boundary '{b}' が trust_boundaries で未定義")

        rr = t.get("residual_risk")
        if rr is not None and rr not in RESIDUAL:
            errors.append(f"{tid}: residual_risk が不正（{rr!r}）。許可: {sorted(RESIDUAL)}")

    # 鎖の検証：policy の全 SEC-ID に対応する threat があるか
    uncovered = policy_sec_ids - threat_sec_ids
    if uncovered:
        errors.append(
            "policy.sec_requirements の SEC-ID に対応する脅威が無い（鎖が切れている）: "
            + ", ".join(sorted(uncovered))
        )

    # 網羅の床：定義済みの信頼境界・資産が、最低1つの脅威に参照されているか
    # （参照ゼロ＝そこを誰も脅威分析していない＝盲点の候補）。
    # L2 以上では NG、L1 では警告（敵対的レビューで埋める前提）。
    coverage_msgs = []
    for b in sorted(boundary_ids - referenced_boundaries):
        coverage_msgs.append(f"信頼境界 '{b}' を参照する脅威が無い（未分析の境界）")
    for a in sorted(asset_ids - referenced_assets):
        coverage_msgs.append(f"資産 '{a}' を参照する脅威が無い（未分析の資産）")

    warnings = []
    if coverage_is_error:
        errors.extend(coverage_msgs)
    else:
        warnings.extend(coverage_msgs)

    if errors:
        print(f"THREAT-MODEL: NG（保証レベル {assurance}）")
        for e in errors:
            print(f"  - {e}")
        for w in warnings:
            print(f"  [警告] {w}")
        sys.exit(1)

    n = len(threats)
    print(f"THREAT-MODEL: OK（保証レベル {assurance}・脅威 {n} 件・SEC対応 {len(policy_sec_ids)} 件）")
    for w in warnings:
        print(f"  [警告] {w}（L2 以上では NG。敵対的レビューで埋めること）")
    sys.exit(0)


if __name__ == "__main__":
    main()
