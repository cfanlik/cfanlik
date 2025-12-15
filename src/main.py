import json
import os
from pathlib import Path

import pandas as pd
from tabulate import tabulate

from analyzer import compute_scores, scores_to_dataframe
from dune_client import DuneClient


# 把你在 Dune 创建好的 Query ID 填这里
DUNE_QUERY_ID = int(os.getenv("DUNE_QUERY_ID", "123456"))  # TODO: 换成真实 ID


def load_tokens() -> dict:
    cfg_path = Path(__file__).resolve().parent.parent / "config" / "tokens_bsc.json"
    with cfg_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def main():
    tokens = load_tokens()
    print(f"加载代币 {len(tokens)} 个：{', '.join(tokens.keys())}")

    client = DuneClient()

    # 如果你把 SQL 改成使用参数（比如 ANY(:tokens)），可以在这里传参：
    # params = {"tokens": list(addr_list)}
    # 现在这个示例 SQL 没用参数，params 传空即可
    dune_result = client.run_query_sync(DUNE_QUERY_ID, params={})

    rows = dune_result["result"]["rows"]
    df_raw = pd.DataFrame(rows)

    # 打印原始字段方便对照
    print("\n[原始 Dune 字段预览]")
    print(df_raw.head())

    scores = compute_scores(df_raw)
    df_scores = scores_to_dataframe(scores)

    print("\n[按吸筹评分排序]")
    print(
        tabulate(
            df_scores,
            headers="keys",
            tablefmt="github",
            showindex=True,
        )
    )


if __name__ == "__main__":
    main()
