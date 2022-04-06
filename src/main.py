import socket
from typing import Optional
from datetime import datetime
import validators
from fastapi import FastAPI, Path, Query
from fastapi.responses import JSONResponse
from tlstrust import TrustStore
from tlstrust.cli import check

__version__ = "0.0.1"

app = FastAPI()
hostname = socket.gethostname()

errors = {
    403: {
        "description": "Insufficient privileges for this action"
    },
    404: {
        "description": "No response for this domain name",
    }
}


@app.get("/{host}",
         responses={
             **errors,
             200: {
                 "description": "Successfully retrieved information of the domain",
                 "content": {
                     "application/json": {
                         "example":  {"fetch_time": "2022-04-06T15:22:21", "host": "ssllabs.com", "port": 443, "peer_address": "64.41.200.100", "not_valid_after": "2031-04-13T23:59:59", "certificate_issuer": "DigiCert Global Root CA", "issuer_ski": "03de503556d14cbb66f0a3e21b1bc397b23dd155", "is_trusted": True, "results": {"Common Certificate Authority Database (CCADB)": True, "Java(TM) SE Runtime Environment": True, "Google Trust Services": True, "Linux (Arch)": True, "Certifi (Python module for Certificate Authority Certificates)": True, "MinTsifry Rossii": True, "Python 3.10": True, "Microsoft Windows": True, "Apple Devices": True, "Android": True, "latest Android build": True, "Android 2.2 (Froyo) 2010": True, "Android 2.3 (Gingerbread) 2010": True, "Android 3 (Honeycomb) 2011": True, "Android 4 (Ice Cream Sandwich) 2011": True, "Android 4.4 (KitKat) 2013": True, "Android 7 (Nougat) 2016": True, "Android 8 (Oreo) 2017": True, "Android 9 (Pie) 2018": True, "Android 10 (Q) 2019": True, "Android 11 2020": True, "Android 12 2021": True, "Mozilla Firefox": True, "Tor Web Browser": True, "Chromium Browser": True, "Google Chrome": True, "Microsoft Edge": True, "Brave Browser": True, "Opera Browser": True, "Vivaldi Browser": True, "Amazon Silk": True, "Samsung Internet": True, "Yandex": True, "Apple Safari": True, "Python built-in https module on Windows": True, "Python built-in https module on Linux": True, "Python built-in https module on Apple": True, "certifi (Python module)": True, "urllib (Python module)": True, "requests (Python module)": True, "Django (Python module)": True}}
                     }
                 },
             },
         })
async def query_host(host: str = Path(
        None,
        title="Domain Name",
        description="target domain name for the TLS Certificate to verify it's device and platform trust stores",
    ), port: Optional[int] = Query(
        443,
        title="Port number",
        ge=1,
        le=49151
    ), use_sni: Optional[bool] = Query(
        True,
        title="Control if SNI is utilised",
    )):
    if validators.domain(host) is not True:
        return JSONResponse(status_code=422, content={"detail": {"msg": "provided an invalid domain"}})
    query = check(host, port, use_sni=use_sni)
    store: TrustStore = query.get('trust_store')
    results = {}
    for name, is_trusted in store.all_results.items():
        results[name] = is_trusted
    return {
        "fetch_time": datetime.utcnow().replace(microsecond=0).isoformat(),
        "host": host,
        "port": port,
        "peer_address": query.get('peer_address'),
        "not_valid_after": query.get('not_valid_after'),
        "certificate_issuer": query.get('certificate_issuer'),
        "issuer_ski": query.get('issuer_ski'),
        "is_trusted": store.is_trusted,
        "results": results,
    }
