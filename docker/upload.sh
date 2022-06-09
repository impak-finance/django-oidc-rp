#!/bin/bash
export TWINE_USERNAME=$PYPI_USERNAME
export TWINE_PASSWORD=$PYPI_PASSWORD

cd /code
twine upload ./dist/* --repository-url=$PYPI_REPOSITORY_URL
