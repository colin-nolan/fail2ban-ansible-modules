#!/usr/bin/env bash

set -euf -o pipefail

# Remove old test coverage data
rm -f .coverage.*

# Run tests
PYTHONPATH=. python -m coverage run -m unittest discover -v -s tests

# Generate coverage reports
coverage combine -a
coverage report
