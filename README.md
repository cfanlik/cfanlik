# BSC 多代币吸筹监控

一套可以直接落地的吸筹监控小工具：

- ✅ Dune SQL：一次性分析多枚 BSC 代币的 Top100 持仓和近 7 天净流入。
- ✅ Python CLI：调用 Dune API 拉取结果，计算 0–100 的吸筹评分，并按分数排序输出。

## 目录结构
```
accumulation-monitor/
├─ config/
│  └─ tokens_bsc.json       # 你维护的 BSC 代币白名单
├─ src/
│  ├─ dune_client.py        # 调用 Dune API
│  ├─ analyzer.py           # 吸筹评分逻辑
│  └─ main.py               # CLI 入口
├─ requirements.txt
└─ README.md
```

## 1）Dune 吸筹分析 SQL
表名按 Dune 常用命名编写：`bsc.erc20_evt_Transfer` 和 `tokens.erc20`。如果你的环境表名略有不同（例如 `bsc_erc20.evt_Transfer`），改一下表名即可。

SQL 会输出每个代币的：
- 只买不卖的钱包数
- 净流入总量
- Top10/20/100 持仓集中度（当前）
- 持币地址数量

> 你可以把 `token_list` 改成 Dune 的参数（如 `ANY(:tokens)`），这样每次只传一串合约地址可以节省点数。

```sql
-- ============================
-- BSC 多代币吸筹监控 / 吸筹雷达
-- ============================

-- TODO：把下面 IN (...) 改成你自己的代币白名单
-- 例如: 0x..., 0x..., 0x...
WITH token_list AS (
    SELECT *
    FROM (VALUES
        -- 合约地址全部小写
        ('0x0000000000000000000000000000000000000001'::bytea), -- UAI
        ('0x0000000000000000000000000000000000000002'::bytea), -- TRUST
        ('0x0000000000000000000000000000000000000003'::bytea), -- KITE
        ('0x0000000000000000000000000000000000000004'::bytea), -- BEAT
        ('0x0000000000000000000000000000000000000005'::bytea), -- MMT
        ('0x0000000000000000000000000000000000000006'::bytea)  -- BANK
        -- ... 继续补
    ) AS t(contract_address)
),

-- 可选：过滤已知 bot / MEV bot 地址，避免被刷量干扰
-- 把列表改成你自己的地址，或改造成 ANY(:bot_addresses) 参数
bot_addresses AS (
    SELECT *
    FROM (VALUES
        ('0x00000000000000000000000000000000000000aa'::bytea),
        ('0x00000000000000000000000000000000000000bb'::bytea)
        -- ... 继续补
    ) AS t(wallet)
),

-- 全历史转账（只针对白名单代币）
all_transfers AS (
    SELECT
        evt.contract_address,
        evt."from" AS from_addr,
        evt."to"   AS to_addr,
        evt.value  AS raw_value,
        evt.evt_block_time
    FROM bsc.erc20_evt_Transfer evt
    JOIN token_list t ON evt.contract_address = t.contract_address
    WHERE evt."from" NOT IN (SELECT wallet FROM bot_addresses)
      AND evt."to"   NOT IN (SELECT wallet FROM bot_addresses)
),

-- 计算当前余额（所有地址）
balances AS (
    SELECT
        contract_address,
        wallet,
        SUM(amount_delta) AS balance
    FROM (
        -- 收到 = +
        SELECT
            contract_address,
            to_addr AS wallet,
            raw_value::numeric / 1e18 AS amount_delta
        FROM all_transfers
        UNION ALL
        -- 发送 = -
        SELECT
            contract_address,
            from_addr AS wallet,
            - raw_value::numeric / 1e18 AS amount_delta
        FROM all_transfers
    ) x
    GROUP BY 1,2
),

-- 去除余额为 0 的地址
non_zero_balances AS (
    SELECT *
    FROM balances
    WHERE balance > 0
),

-- 当前 Top100 持仓
top_holders AS (
    SELECT
        contract_address,
        wallet,
        balance,
        ROW_NUMBER() OVER (
            PARTITION BY contract_address
            ORDER BY balance DESC
        ) AS rk
    FROM non_zero_balances
),

top100 AS (
    SELECT *
    FROM top_holders
    WHERE rk <= 100
),

-- 过去 7 天的转账（只看最近 7 天用来算净流入）
last7d_transfers AS (
    SELECT
        evt.contract_address,
        evt."from" AS from_addr,
        evt."to"   AS to_addr,
        evt.value::numeric / 1e18 AS amount,
        evt.evt_block_time
    FROM bsc.erc20_evt_Transfer evt
    JOIN token_list t ON evt.contract_address = t.contract_address
    WHERE evt.evt_block_time > now() - interval '7 day'
),

-- 针对 Top100 钱包，计算最近 7 天的买卖情况
whale_flows_7d AS (
    SELECT
        t.contract_address,
        t.wallet,
        COALESCE(SUM(CASE WHEN l.to_addr   = t.wallet THEN l.amount END), 0) AS buy_7d,
        COALESCE(SUM(CASE WHEN l.from_addr = t.wallet THEN l.amount END), 0) AS sell_7d
    FROM top100 t
    LEFT JOIN last7d_transfers l
        ON t.contract_address = l.contract_address
       AND (t.wallet = l.to_addr OR t.wallet = l.from_addr)
    GROUP BY 1,2
),

whale_stats AS (
    SELECT
        contract_address,
        COUNT(*) FILTER (WHERE buy_7d > 0) AS whales_with_buy,
        COUNT(*) FILTER (WHERE buy_7d > 0 AND sell_7d = 0) AS whales_only_buy,
        SUM(buy_7d - sell_7d) AS net_inflow_7d,
        SUM(buy_7d) AS total_buy_7d,
        SUM(sell_7d) AS total_sell_7d
    FROM whale_flows_7d
    GROUP BY 1
),

-- 当前持币集中度（Top10/20/100）
concentration AS (
    SELECT
        contract_address,
        SUM(balance) AS total_balance,
        SUM(balance) FILTER (WHERE rk <= 10)  AS top10_balance,
        SUM(balance) FILTER (WHERE rk <= 20)  AS top20_balance,
        SUM(balance) FILTER (WHERE rk <= 100) AS top100_balance
    FROM top100
    GROUP BY 1
),

concentration_ratio AS (
    SELECT
        c.contract_address,
        c.total_balance,
        c.top10_balance  / NULLIF(c.total_balance,0) AS top10_ratio,
        c.top20_balance  / NULLIF(c.total_balance,0) AS top20_ratio,
        c.top100_balance / NULLIF(c.total_balance,0) AS top100_ratio
    FROM concentration c
),

-- 当前持币地址数量
holder_count AS (
    SELECT
        contract_address,
        COUNT(*) AS holder_cnt
    FROM non_zero_balances
    GROUP BY 1
),

-- 补充 token 元数据（符号、名称）
meta AS (
    SELECT
        e.contract_address,
        e.symbol,
        e.name
    FROM tokens.erc20 e
    WHERE e.chain_id = 56 -- BSC
      AND e.contract_address IN (SELECT contract_address FROM token_list)
)

SELECT
    encode(m.contract_address, 'hex') AS token_address,
    m.symbol,
    m.name,
    ws.whales_with_buy,
    ws.whales_only_buy,
    ws.net_inflow_7d,
    ws.total_buy_7d,
    ws.total_sell_7d,
    cr.total_balance,
    cr.top10_ratio,
    cr.top20_ratio,
    cr.top100_ratio,
    hc.holder_cnt
FROM meta m
LEFT JOIN whale_stats       ws ON m.contract_address = ws.contract_address
LEFT JOIN concentration_ratio cr ON m.contract_address = cr.contract_address
LEFT JOIN holder_count      hc ON m.contract_address = hc.contract_address
ORDER BY ws.net_inflow_7d DESC NULLS LAST;
```

### 在 Dune 上的步骤
1. 新建 Query 并粘贴上面的 SQL。
2. 把 `token_list` 里的合约地址改为你的白名单（或改成参数）。
3. 可选：在 `bot_addresses` 里填入常见的 MEV / bot 地址，或改造成参数 `ANY(:bot_addresses)` 以便快速覆盖更多地址。
4. 运行确认结果正常，记下 `query_id`。

> 直接在 Dune 查看结果 vs. 通过 Python 调用 API？
>
> - **直接在 Dune 控制台运行**：点 “Run” 后即可看到结果表，支持导出 CSV / JSON，适合临时查看或分享截图；如果最近跑过同一个 Query，会命中 Dune 缓存，通常比从本地反复调用 API 更快。要跑多个币种，只要在参数里传一批合约地址（或改 SQL 中的 `token_list`）就能一次跑完。
> - **Python + Dune API**：适合自动化、定时跑、二次计算（比如吸筹评分）。API 也能复用缓存，但还需要等待网络请求并在本地做数据处理。若只想看原始指标，不做评分，直接在 Dune 里运行并导出就足够了。

### DEX 成交 vs. 纯转账
- 上面的 SQL 以 `bsc.erc20_evt_Transfer` 为主，覆盖 CEX 出入金、链上转账以及 AMM 池的 token 份额变动（因 LP 迁移/添加会产生转账）。
- 如果你希望更精准地按“成交方向”来衡量买卖（例如区分 swap 方向、过滤路由器内部转账），可以将 `last7d_transfers` 换成基于交易的子查询，例如：

```sql
-- 可替换 last7d_transfers，使用 DEX 成交表
dex_swaps_7d AS (
    SELECT
        t.token_bought_address   AS contract_address,
        t.taker                  AS to_addr,   -- 买入方
        t.taker                  AS from_addr, -- 用于保持列名一致；卖出方向用 token_sold_address
        t.token_bought_amount    AS amount,
        t.block_time             AS evt_block_time
    FROM dex.trades t
    WHERE t.chain_id = 56
      AND t.token_bought_address IN (SELECT contract_address FROM token_list)
      AND t.block_time > now() - interval '7 day'
),
```

- 具体表名在 Dune 里可能是 `bsc.dex_trades`、`dex.trades` 等，可根据你的数据源调整；核心思路是用成交方向代替单纯的资金流转账，以避免 LP 移除/路由器内部跳转带来的噪音。

## 2）Python 端使用
### 环境准备
```bash
python -m venv venv
source venv/bin/activate  # Windows 用 venv\Scripts\activate
pip install -r requirements.txt
```

在项目根目录创建 `.env`，填好：
```
DUNE_API_KEY=你的_dune_api_key
DUNE_QUERY_ID=你在 Dune 保存好的 query_id
```

编辑 `config/tokens_bsc.json`，把代币符号 + 合约地址换成你要监控的真实 BSC 代币。
如需过滤已知 bot / MEV 地址，可在 `config/address_blocklist.json` 里维护一个本地备忘，方便同步到 Dune SQL 的 `bot_addresses`。

### 运行
```bash
python src/main.py
```

输出示例：
```
[原始 Dune 字段预览]
  ...

[按吸筹评分排序]
|   | Symbol   | Name   | Token   |   Score |   Whales Only Buy (7D) |   Whales With Buy (7D) |   Net Inflow 7D |   Holders |   Top10 Ratio |   Top100 Ratio |
|---|----------|--------|---------|---------|------------------------|------------------------|-----------------|-----------|---------------|----------------|
| 0 | UAI      | ...    | ...     |   88.12 |                      3 |                      7 |           123.4 |       987 |         45.67 |          90.12 |
```

按 Score 从高到低排序，直接关注前几名即可。

## 3）评分规则解读 & 地址权重说明
默认的评分逻辑偏向“趋势感知”，每个指标先做 0~1 归一化，再按权重加总（乘以 100）：

- 40% 来自 **近 7 天相对净流入**：`net_inflow_7d / total_balance`，刻画“资金流向”。
- 25% 来自 **只买不卖的 Top100 钱包数量**：越多说明“筹码锁定”意愿越强。
- 20% 来自 **Top100 持仓集中度**：集中度提升意味着“头部持有者吸筹”。
- 15% 来自 **过去 7 天有买入行为的钱包数量**：衡量活跃鲸鱼数量。

> 地址是否考虑权重？
>
> - 目前对地址的计数是“等权”的：无论某个 Top100 钱包持有 0.5% 还是 5% 的流通量，都会被当作 1 个地址计数。
> - 如果你希望按持仓权重或流入金额加权，可以在 SQL 层额外输出每个钱包的余额占比或 7 天净流入占比，然后在 `analyzer.compute_scores` 中新增一个归一化项（例如 `whales_only_buy_weighted`），并提升它的权重即可。
