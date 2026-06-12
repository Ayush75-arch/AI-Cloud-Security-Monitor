.PHONY: help install dev test lint format clean build docker-up docker-down seed

help:
	@echo "CloudGuard-AI — Development Commands"
	@echo "===================================="
	@echo ""
	@echo "  make install     Install all dependencies (backend + frontend)"
	@echo "  make dev         Start both backend and frontend in dev mode"
	@echo "  make backend     Start backend only (uvicorn reload)"
	@echo "  make frontend    Start frontend only (vite dev)"
	@echo "  make test        Run backend tests"
	@echo "  make lint        Lint all Python files"
	@echo "  make format      Format all Python files with ruff"
	@echo "  make clean       Remove __pycache__, .pyc, build artifacts"
	@echo "  make build       Build frontend for production"
	@echo "  make docker-up   Start all services with Docker Compose"
	@echo "  make docker-down Stop all Docker services"
	@echo "  make seed        Seed demo data into the database"
	@echo ""

install:
	cd backend && pip install -r requirements.txt
	cd frontend && npm install

dev:
	@echo "Starting backend and frontend..."
	@echo "Backend: http://localhost:8000"
	@echo "Frontend: http://localhost:5173"
	@echo ""
	start powershell -NoExit "cd backend; uvicorn app.main:app --reload --port 8000"
	start powershell -NoExit "cd frontend; npm run dev"

backend:
	cd backend && uvicorn app.main:app --reload --port 8000

frontend:
	cd frontend && npm run dev

test:
	cd backend && python -m pytest tests/ -v --tb=short $(ARGS)

lint:
	cd backend && ruff check app/ tests/
	cd frontend && npm run lint

format:
	cd backend && ruff format app/ tests/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache .mypy_cache

build:
	cd frontend && npm run build

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

seed:
	cd backend && python seed_demo.py
