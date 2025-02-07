SHELL := /bin/bash
-include .env
export $(shell sed 's/=.*//' .env)

.PHONY: help

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

run-local: ## start a hot reload local server on port 8088
	uvicorn main:app --workers 4 --host=0.0.0.0 --port=8088 --reload

deps: ## setup for development of this project
	pip install -U -e .

setup: deps ## setup for development of this project
	pip install -U -e .

check: ## check metadata
	python3 setup.py check -ms

test: check ## run unit tests with coverage
	coverage run -m pytest --nf -s
	coverage report -m

deploy: ## push to heroku
	git push heroku main

publish: check deploy ## upload to pypi.org
	git tag -f $(shell cat ./setup.py | grep 'version=' | sed 's/[version=", ]//g')
	git push -u origin --tags

test-local: ## Prettier test outputs
	pylint --exit-zero -f colorized --persistent=y -r y --jobs=0 src/**/*.py
	semgrep -q --strict --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

pylint-ci: ## run pylint for CI
	pylint --exit-zero --persistent=n -f json -r n --jobs=0 --errors-only src/**/*.py > pylint.json

semgrep-sast-ci: ## run core semgrep rules for CI
	semgrep --disable-version-check -q --strict --error -o semgrep-ci.json --json --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

test-all: semgrep-sast-ci pylint-ci ## Run all CI tests
