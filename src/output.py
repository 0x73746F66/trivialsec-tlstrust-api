from datetime import datetime
from tlstrust import TrustStore


def to_json(trust_store: TrustStore, tlstrust_query: dict, **kwargs) -> dict:
    results = []
    for name, is_trusted in trust_store.all_results.items():
        result = {}
        result['name'] = name
        result['is_trusted'] = is_trusted
        results.append(result)
    return {
        '_metadata': {
            "fetch_time": datetime.utcnow().replace(microsecond=0).isoformat(),
            "certificate_not_valid_after": tlstrust_query.get('not_valid_after'),
            "certificate_issuer": tlstrust_query.get('certificate_issuer'),
            "certificate_issuer_ski": tlstrust_query.get('issuer_ski'),
        },
        '_query': {
            **kwargs,
            "peer_address": tlstrust_query.get('peer_address'),
        },
        'trust_stores': results
    }
