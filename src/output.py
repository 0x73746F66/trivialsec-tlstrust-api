from datetime import datetime
from OpenSSL.crypto import X509
from cryptography import x509
from tlstrust import TrustStore
from tlstrust.context import SOURCES, PLATFORMS, BROWSERS, LANGUAGES

contexts = {**SOURCES, **PLATFORMS, **BROWSERS, **LANGUAGES}

def to_json(trust_store: TrustStore, **kwargs) -> dict:
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
            result['exists'] = isinstance(trust_store.certificate, X509)
            result['expired'] = trust_store.expired_in_store(ctx)
        except FileExistsError:
            result['exists'] = False
        results.append(result)
    subject_common_name = trust_store.certificate.to_cryptography().subject.get_attributes_for_oid(x509.OID_COMMON_NAME)[0]._value
    return {
        '_metadata': {
            "fetch_time": datetime.utcnow().replace(microsecond=0).isoformat(),
            "certificate_not_valid_after": trust_store.certificate.to_cryptography().not_valid_after,
            "certificate_issuer": subject_common_name,
            "certificate_issuer_ski": trust_store.key_identifier,
        },
        '_query': {**kwargs},
        'trust_stores': results
    }
