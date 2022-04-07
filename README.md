# TLS Trust API

docs with testing: http://localhost:8088/docs

prettier docs (no testing) http://localhost:8088/redoc

## Deploy

install heroku cli, run `keroku login -i`

publish to heroku `git push heroku main`

ensure at least 1 dyno is running `heroku ps:scale web=1`

make sure everything is ok `heroku logs --tail`

upload openapi.json spec to https://rapidapi.com/provider/6216279/apis/ssl-tls-website-trust/definition/versions/apiversion_76cdf456-544b-4683-8bf0-23dbd5269414/settings
