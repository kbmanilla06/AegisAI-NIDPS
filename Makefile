.PHONY: backend-check frontend-check test compose-config up down

backend-check:
	ruff check apps services tests
	ruff format --check apps services tests
	mypy
	bandit -c pyproject.toml -r apps services
	pytest
	python scripts/check_secrets.py
	python scripts/check_simulation_only.py

frontend-check:
	npm --prefix apps/dashboard run lint
	npm --prefix apps/dashboard run typecheck
	npm --prefix apps/dashboard run test
	npm --prefix apps/dashboard run build

test: backend-check frontend-check

compose-config:
	docker compose config --quiet

up:
	docker compose up --build --wait

down:
	docker compose down
