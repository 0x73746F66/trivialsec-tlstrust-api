import socket
from os import getenv
from typing import Optional
import validators
from fastapi import FastAPI, Path, Query, Header
from fastapi.responses import JSONResponse
from tlstrust import trust_stores_from_chain
from tlstrust.util import get_certificate_chain
import output

__version__ = "0.0.4"
hostname = socket.gethostname()
errors = {
    403: {
        "description": "Insufficient privileges for this action"
    },
    404: {
        "description": "No response for this domain name",
    }
}
servers = [
    {'url': "https://tlstrust-api.herokuapp.com"},
]
if getenv('APP_ENV') == 'development':
    servers.append({'url': "http://jager:8088"})

app = FastAPI(
    title='SSL/TLS Trust Verifier',
    version=__version__,
    servers=servers,
    generate_unique_id_function=lambda route: route.name,
)

@app.get("/v1/{host}",
        name='query_host',
        description='Provide a domain name as the target host to query the SSL/TLS configuration and verify root trust',
        responses={
        **errors,
            200: {
                "description": "Successfully retrieved information of the domain",
                "content": {
                    "application/json": {
                        "example": {"execution_date": "2022-04-11T03:12:15", "execution_duration_seconds": 1.275617, "generator": "2.4.0", "stores": [{"_metadata": {"certificate_issuer": "DigiCert Global Root CA", "certificate_issuer_ski": "03de503556d14cbb66f0a3e21b1bc397b23dd155", "certificate_not_valid_after": "2031-11-10 00:00:00", "last_updated": "2022-04-11T03:12:15"}, "_query": {"host_name": "ssllabs.com", "peer_address": "64.41.200.100", "port_number": 443, "use_sni": True}, "trust_stores": [{"description": "Root CA Certificate present in CCADB 2022.04.09 Trust Store (Mozilla, Microsoft, and Apple)", "exists": True, "expired": False, "is_trusted": True, "name": "Common Certificate Authority Database (CCADB)"}, {"description": "Root CA Certificate present in Java SE java 18 2022-03-22 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Java(TM) SE Runtime Environment"}, {"description": "Root CA Certificate present in Google latest Android build Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Google Trust Services"}, {"description": "Root CA Certificate present in Linux 5.17.1-arch1-1 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Linux (Arch)"}, {"description": "Root CA Certificate present in Certifi certifi==2021.10.8 Trust Store (Django, requests, urllib, and anything based from these)", "exists": True, "expired": False, "is_trusted": True, "name": "Certifi (Python module for Certificate Authority Certificates)"}, {"description": "No Root CA Certificate in the Russian Trust Store", "exists": False, "is_trusted": False, "name": "MinTsifry Rossii"}, {"description": "Root CA Certificate present in Python certifi==2021.10.8 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Python 3.10"}, {"description": "Root CA Certificate present in Windows 2022.04.09 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Microsoft Windows"}, {"description": "Root CA Certificate present in Apple 2022.04.09 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Apple devices"}, {"description": "Root CA Certificate present in Android FOSS latest Android build Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Android (open source)"}, {"description": "Root CA Certificate present in Android latest latest Android build Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Android (latest Google build)"}, {"description": "Root CA Certificate present in Android 2.2 Android 2.2 (Froyo) 2010 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Android 2.2 (Froyo) 2010"}, {"description": "Root CA Certificate present in Android 2.3 Android 2.3 (Gingerbread) 2010 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Android 2.3 (Gingerbread) 2010"}, {"description": "Root CA Certificate present in Android 3 Android 3 (Honeycomb) 2011 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Android 3 (Honeycomb) 2011"}, {"description": "Root CA Certificate present in Android 4 Android 4.4 (KitKat) 2013 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Android 4 (Ice Cream Sandwich) 2011"}, {"description": "Root CA Certificate present in Android 4.4 Android 4 (Ice Cream Sandwich) 2011 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Android 4.4 (KitKat) 2013"}, {"description": "Root CA Certificate present in Android 7 Android 7 (Nougat) 2016 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Android 7 (Nougat) 2016"}, {"description": "Root CA Certificate present in Android 8 Android 8 (Oreo) 2017 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Android 8 (Oreo) 2017"}, {"description": "Root CA Certificate present in Android 9 Android 9 (Pie) 2018 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Android 9 (Pie) 2018"}, {"description": "Root CA Certificate present in Android 10 Android 10 (Q) 2019 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Android 10 (Q) 2019"}, {"description": "Root CA Certificate present in Android 11 Android 11 2020 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Android 11 2020"}, {"description": "Root CA Certificate present in Android 12 Android 12 2021 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Android 12 2021"}, {"description": "Root CA Certificate present in Firefox 2022.04.09 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Mozilla Firefox"}, {"description": "Root CA Certificate present in Tor 2022.04.09 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Tor Web Browser"}, {"description": "Root CA Certificate present in Chromium 2022.04.09 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Chromium Browser"}, {"description": "Root CA Certificate present in Chrome 2022.04.09 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Google Chrome"}, {"description": "Root CA Certificate present in Edge 2022.04.09 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Microsoft Edge"}, {"description": "Root CA Certificate present in Brave 2022.04.09 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Brave Browser"}, {"description": "Root CA Certificate present in Opera 2022.04.09 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Opera Browser"}, {"description": "Root CA Certificate present in Vivaldi 2022.04.09 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Vivaldi Browser"}, {"description": "Root CA Certificate present in Silk 2022.04.09 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Amazon Silk"}, {"description": "Root CA Certificate present in Samsung 2022.04.09 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Samsung Internet"}, {"description": "No Root CA Certificate in the Yandex Trust Store", "exists": False, "is_trusted": False, "name": "Yandex"}, {"description": "Root CA Certificate present in Safari 2022.04.09 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Apple Safari"}, {"description": "Root CA Certificate present in Python on Windows 2022.04.09 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Python built-in https module on Windows"}, {"description": "Root CA Certificate present in Python on Linux 2022.04.09 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Python built-in https module on Linux"}, {"description": "Root CA Certificate present in Python on Apple 2022.04.09 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Python built-in https module on Apple"}, {"description": "Root CA Certificate present in certifi certifi==2021.10.8 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "certifi (Python module)"}, {"description": "Root CA Certificate present in urllib certifi==2021.10.8 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "urllib (Python module)"}, {"description": "Root CA Certificate present in requests certifi==2021.10.8 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "requests (Python module)"}, {"description": "Root CA Certificate present in Django certifi==2021.10.8 Trust Store", "exists": True, "expired": False, "is_trusted": True, "name": "Django (Python module)"}]}], "targets": ["ssllabs.com:443"]}
                    }
                },
            },
        })
async def query_host(
    host: str = Path(
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
    ), x_rapidapi_proxy_secret :Optional[str] = Header(
        None if getenv('APP_ENV') != 'development' else 'letmein',
        title='X-Rapidapi-Proxy-Secret',
        description='The secret key for blocking requests coming from outside the RapidAPI infrastructure',
        include_in_schema=getenv('APP_ENV') == 'development'
    )):
    if validators.domain(host) is not True:
        return JSONResponse(status_code=422, content={"detail": {"msg": "provided an invalid domain"}})
    rapidapi_secret = getenv('RAPIDAPI_SECRET', 'Y5WKR9FZKS6ZLPJ92S4XX8ZWZU' if getenv('APP_ENV') != 'development' else 'letmein')
    if x_rapidapi_proxy_secret != rapidapi_secret:
        return JSONResponse(status_code=401)
    chain, peer_addr = get_certificate_chain(host, port, use_sni=use_sni)
    results = []
    for store in trust_stores_from_chain(chain):
        results.append(output.to_json(store, peer_addr=peer_addr, host=host, port=port, use_sni=use_sni))
    return results
