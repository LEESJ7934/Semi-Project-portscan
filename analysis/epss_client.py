# analysis/epss_client.py
import random

def get_epss_score(cve_id: str) -> float:
    """
    EPSS 점수를 가져오는 mock 함수.
    나중에 실제 FIRST EPSS API 연동 예정.
    """
    if not cve_id or cve_id == "NONE":
        return 0.0

    # EPSS mock: 0.0 ~ 1.0 사이의 random score
    return round(random.uniform(0.0, 1.0), 3)
