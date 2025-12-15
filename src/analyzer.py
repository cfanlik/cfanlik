from dataclasses import dataclass
from typing import List

import pandas as pd


@dataclass
class TokenAccumulationScore:
    symbol: str
    name: str
    token_address: str
    score: float
    whales_only_buy: int
    whales_with_buy: int
    net_inflow_7d: float
    holder_cnt: int
    top10_ratio: float
    top100_ratio: float


def compute_scores(df: pd.DataFrame) -> List[TokenAccumulationScore]:
    """
    根据 Dune SQL 返回的行，计算 0-100 吸筹评分。
    评分逻辑可以根据你自己的喜好微调，这里给一个示例：
      - 40% 来自 net_inflow_7d（相对总余额）
      - 25% 来自 whales_only_buy 数量（等权计数，未按余额加权）
      - 20% 来自 top100_ratio 集中度
      - 15% 来自 whales_with_buy 数量

    想给地址“按筹码大小加权”时，可以在 SQL 中补充钱包层面的余额占比或 7 天净流入占比，
    然后在这里新增归一化项（例如 `score_whales_only_buy_weighted`），同时调整权重即可。
    """

    # 安全处理缺失值
    for col in [
        "whales_only_buy",
        "whales_with_buy",
        "net_inflow_7d",
        "total_balance",
        "top10_ratio",
        "top100_ratio",
        "holder_cnt",
    ]:
        if col not in df.columns:
            df[col] = 0
        df[col] = df[col].fillna(0)

    # 归一化函数（0~1）
    def norm(series):
        s = series.astype(float)
        max_v = s.max()
        min_v = s.min()
        if max_v == min_v:
            # 所有值相同，直接给 0.5
            return pd.Series([0.5] * len(s), index=s.index)
        return (s - min_v) / (max_v - min_v)

    # 相对净流入 = net_inflow_7d / total_balance
    df["rel_net_inflow"] = df.apply(
        lambda r: (r["net_inflow_7d"] / r["total_balance"]) if r["total_balance"] > 0 else 0,
        axis=1,
    )

    df["score_net_inflow"] = norm(df["rel_net_inflow"])
    df["score_whales_only_buy"] = norm(df["whales_only_buy"])
    df["score_whales_with_buy"] = norm(df["whales_with_buy"])
    df["score_top100_ratio"] = norm(df["top100_ratio"])

    # 综合评分
    df["accumulation_score"] = (
        df["score_net_inflow"] * 0.40
        + df["score_whales_only_buy"] * 0.25
        + df["score_top100_ratio"] * 0.20
        + df["score_whales_with_buy"] * 0.15
    ) * 100.0

    results: List[TokenAccumulationScore] = []
    for _, row in df.iterrows():
        results.append(
            TokenAccumulationScore(
                symbol=row.get("symbol") or "",
                name=row.get("name") or "",
                token_address=row.get("token_address") or "",
                score=float(row["accumulation_score"]),
                whales_only_buy=int(row["whales_only_buy"]),
                whales_with_buy=int(row["whales_with_buy"]),
                net_inflow_7d=float(row["net_inflow_7d"]),
                holder_cnt=int(row["holder_cnt"]),
                top10_ratio=float(row["top10_ratio"]),
                top100_ratio=float(row["top100_ratio"]),
            )
        )
    return results


def scores_to_dataframe(scores: List[TokenAccumulationScore]) -> pd.DataFrame:
    rows = []
    for s in scores:
        rows.append(
            {
                "Symbol": s.symbol,
                "Name": s.name,
                "Token": s.token_address,
                "Score": round(s.score, 2),
                "Whales Only Buy (7D)": s.whales_only_buy,
                "Whales With Buy (7D)": s.whales_with_buy,
                "Net Inflow 7D": round(s.net_inflow_7d, 4),
                "Holders": s.holder_cnt,
                "Top10 Ratio": round(s.top10_ratio * 100, 2),
                "Top100 Ratio": round(s.top100_ratio * 100, 2),
            }
        )
    df = pd.DataFrame(rows)
    return df.sort_values("Score", ascending=False).reset_index(drop=True)
