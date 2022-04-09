import socket
from os import getenv
from typing import Optional
import validators
from fastapi import FastAPI, Path, Query, Header
from fastapi.responses import JSONResponse
from tlstrust import TrustStore, trust_stores_from_chain
from tlstrust.util import get_certificate_chain
import output

__version__ = "0.0.2"
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
                        "example": [{"_metadata":{"fetch_time":"2022-04-07T13:02:16","certificate_not_valid_after":"2031-04-13T23:59:59","certificate_issuer":"DigiCert Global Root CA","certificate_issuer_ski":"03de503556d14cbb66f0a3e21b1bc397b23dd155"},"_query":{"host":"ssllabs.com","port":443,"use_sni":True,"peer_address":"64.41.200.100"},"trust_stores":[{"name":"Common Certificate Authority Database (CCADB)","is_trusted":True,"exists":True,"expired":False},{"name":"Java(TM) SE Runtime Environment","is_trusted":True,"exists":True,"expired":False},{"name":"Google Trust Services","is_trusted":True,"exists":True,"expired":False},{"name":"Linux (Arch)","is_trusted":True,"exists":True,"expired":False},{"name":"Certifi (Python module for Certificate Authority Certificates)","is_trusted":True,"exists":True,"expired":False},{"name":"MinTsifry Rossii","is_trusted":True,"exists":False},{"name":"Python 3.10","is_trusted":True,"exists":True,"expired":False},{"name":"Microsoft Windows","is_trusted":True,"exists":True,"expired":False},{"name":"Apple Devices","is_trusted":True,"exists":True,"expired":False},{"name":"Android","is_trusted":True,"exists":True,"expired":False},{"name":"latest Android build","is_trusted":True,"exists":True,"expired":False},{"name":"Android 2.2 (Froyo) 2010","is_trusted":True,"exists":True,"expired":False},{"name":"Android 2.3 (Gingerbread) 2010","is_trusted":True,"exists":True,"expired":False},{"name":"Android 3 (Honeycomb) 2011","is_trusted":True,"exists":True,"expired":False},{"name":"Android 4 (Ice Cream Sandwich) 2011","is_trusted":True,"exists":True,"expired":False},{"name":"Android 4.4 (KitKat) 2013","is_trusted":True,"exists":True,"expired":False},{"name":"Android 7 (Nougat) 2016","is_trusted":True,"exists":True,"expired":False},{"name":"Android 8 (Oreo) 2017","is_trusted":True,"exists":True,"expired":False},{"name":"Android 9 (Pie) 2018","is_trusted":True,"exists":True,"expired":False},{"name":"Android 10 (Q) 2019","is_trusted":True,"exists":True,"expired":False},{"name":"Android 11 2020","is_trusted":True,"exists":True,"expired":False},{"name":"Android 12 2021","is_trusted":True,"exists":True,"expired":False},{"name":"Mozilla Firefox","is_trusted":True,"exists":True,"expired":False},{"name":"Tor Web Browser","is_trusted":True,"exists":True,"expired":False},{"name":"Chromium Browser","is_trusted":True,"exists":True,"expired":False},{"name":"Google Chrome","is_trusted":True,"exists":True,"expired":False},{"name":"Microsoft Edge","is_trusted":True,"exists":True,"expired":False},{"name":"Brave Browser","is_trusted":True,"exists":True,"expired":False},{"name":"Opera Browser","is_trusted":True,"exists":True,"expired":False},{"name":"Vivaldi Browser","is_trusted":True,"exists":True,"expired":False},{"name":"Amazon Silk","is_trusted":True,"exists":True,"expired":False},{"name":"Samsung Internet","is_trusted":True,"exists":True,"expired":False},{"name":"Yandex","is_trusted":True,"exists":False},{"name":"Apple Safari","is_trusted":True,"exists":True,"expired":False},{"name":"Python built-in https module on Windows","is_trusted":True,"exists":True,"expired":False},{"name":"Python built-in https module on Linux","is_trusted":True,"exists":True,"expired":False},{"name":"Python built-in https module on Apple","is_trusted":True,"exists":True,"expired":False},{"name":"certifi (Python module)","is_trusted":True,"exists":True,"expired":False},{"name":"urllib (Python module)","is_trusted":True,"exists":True,"expired":False},{"name":"requests (Python module)","is_trusted":True,"exists":True,"expired":False},{"name":"Django (Python module)","is_trusted":True,"exists":True,"expired":False}]}]
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
