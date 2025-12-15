import os
import time
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv

load_dotenv()


class DuneClient:
    """
    简单封装 Dune API v1。
    使用前请在 .env 文件里设置 DUNE_API_KEY。
    """

    def __init__(self, api_key: Optional[str] = None, base_url: str = "https://api.dune.com/api"):
        self.api_key = api_key or os.getenv("DUNE_API_KEY")
        if not self.api_key:
            raise RuntimeError("DUNE_API_KEY not set in environment or .env")
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({"X-DUNE-API-KEY": self.api_key})

    def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        resp = self.session.request(method, url, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def execute_query(self, query_id: int, params: Optional[Dict[str, Any]] = None) -> str:
        """
        提交一个 query，返回 execution_id
        """
        payload = {"parameters": params or {}}
        data = self._request("POST", f"/v1/query/{query_id}/execute", json=payload)
        return data["execution_id"]

    def get_execution_status(self, execution_id: str) -> Dict[str, Any]:
        return self._request("GET", f"/v1/execution/{execution_id}/status")

    def get_execution_results(self, execution_id: str) -> Dict[str, Any]:
        return self._request("GET", f"/v1/execution/{execution_id}/results")

    def run_query_sync(
        self,
        query_id: int,
        params: Optional[Dict[str, Any]] = None,
        poll_interval: float = 3.0,
        max_wait: float = 300.0,
    ) -> Dict[str, Any]:
        """
        提交 + 轮询直到结果返回
        """
        execution_id = self.execute_query(query_id, params=params)

        waited = 0.0
        while waited < max_wait:
            status = self.get_execution_status(execution_id)
            state = status.get("state")
            if state in ("QUERY_STATE_COMPLETED", "QUERY_STATE_FAILED"):
                break
            time.sleep(poll_interval)
            waited += poll_interval

        if state != "QUERY_STATE_COMPLETED":
            raise RuntimeError(f"Dune execution not completed: {status}")

        return self.get_execution_results(execution_id)
