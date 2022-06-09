.PHONY: install qa lint tests spec coverage docs build clean deploy build_and_deploy


init:
	pipenv install --dev --three


# DEVELOPMENT
# ~~~~~~~~~~~
# The following rules can be used during development in order to compile staticfiles, generate
# locales, build documentation, etc.
# --------------------------------------------------------------------------------------------------

docs:
	cd docs && rm -rf _build && pipenv run make html

shell:
	pipenv run ipython


# QUALITY ASSURANCE
# ~~~~~~~~~~~~~~~~~
# The following rules can be used to check code quality, import sorting, etc.
# --------------------------------------------------------------------------------------------------

qa: lint isort

# Code quality checks (eg. flake8, eslint, etc).
lint:
	pipenv run flake8

# Import sort checks.
isort:
	pipenv run isort --check-only --recursive --diff oidc_rp tests


# TESTING
# ~~~~~~~
# The following rules can be used to trigger tests execution and produce coverage reports.
# --------------------------------------------------------------------------------------------------

# Just runs all the tests!
tests:
	pipenv run py.test

# Collects code coverage data.
coverage:
	pipenv run py.test --cov-report term-missing --cov oidc_rp

# Run the tests in "spec" mode.
spec:
	pipenv run py.test --spec

build:
	docker-compose run --entrypoint "sh /code/docker/build.sh" django-oidc-rp --rm

clean:
	docker-compose run --entrypoint "sh /code/docker/clean.sh" django-oidc-rp --rm

deploy:
	docker-compose run --entrypoint "sh /code/docker/upload.sh" django-oidc-rp --rm

build_and_deploy:
	make clean
	make build
	make deploy
