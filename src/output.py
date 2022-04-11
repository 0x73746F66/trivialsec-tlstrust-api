from tlstrust import TrustStore

def to_json(trust_store: TrustStore, **kwargs) -> dict:
    result = trust_store.to_dict()
    result['_query'] = {**kwargs}
    return result
