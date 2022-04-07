from datetime import datetime
from OpenSSL.crypto import X509
from tlstrust import TrustStore
from tlstrust.context import SOURCES, PLATFORMS, BROWSERS, LANGUAGES

contexts = {**SOURCES, **PLATFORMS, **BROWSERS, **LANGUAGES}

def to_json(trust_store: TrustStore, tlstrust_query: dict, **kwargs) -> dict:
    results = []
    for name, is_trusted in trust_store.all_results.items():
        ctx = None
        for _name, _ctx in contexts.items():
            if name == _name:
                ctx = _ctx
                break
        result = {}
        result['name'] = name
        result['is_trusted'] = is_trusted
        try:
            result['exists'] = isinstance(trust_store.get_certificate_from_store(ctx), X509)
            result['expired'] = trust_store.expired_in_store(ctx)
        except FileExistsError:
            result['exists'] = False
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
