# Makefile for NetFlow Collector

.PHONY: help build run stop logs clean test

# Variables
DOCKER_COMPOSE = docker-compose
IMAGE_NAME = netflow-collector
VERSION = 1.0.0

help:  ## Show this help
	@echo 'NetFlow Collector Docker Management'
	@echo ''
	@echo 'Usage:'
	@echo '  make <target>'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build:  ## Build the Docker image
	@echo "Building Docker image..."
	$(DOCKER_COMPOSE) build

run:  ## Start the containers in background
	@echo "Starting NetFlow Collector..."
	$(DOCKER_COMPOSE) up -d

stop:  ## Stop all containers
	@echo "Stopping containers..."
	$(DOCKER_COMPOSE) down

logs:  ## View logs from netflow-collector
	@echo "Showing logs..."
	$(DOCKER_COMPOSE) logs -f netflow-collector

shell:  ## Open shell in the container
	@echo "Opening shell..."
	$(DOCKER_COMPOSE) exec netflow-collector /bin/bash

test:  ## Run tests
	@echo "Running tests..."
	$(DOCKER_COMPOSE) exec netflow-collector python -m pytest tests/

clean:  ## Remove all containers, images, and volumes
	@echo "Cleaning up..."
	$(DOCKER_COMPOSE) down -v --rmi all --remove-orphans

purge: clean  ## Complete cleanup including Docker cache
	@echo "Purging Docker cache..."
	docker system prune -a -f

status:  ## Show container status
	@echo "Container status:"
	$(DOCKER_COMPOSE) ps

backup:  ## Backup database
	@echo "Backing up database..."
	mkdir -p backups
	$(DOCKER_COMPOSE) exec postgres pg_dump -U netflow_user netflow_db > backups/netflow_backup_$(shell date +%Y%m%d_%H%M%S).sql

restore:  ## Restore database from latest backup
	@echo "Restoring database..."
	$(DOCKER_COMPOSE) exec -T postgres psql -U netflow_user netflow_db < backups/$$(ls -t backups/*.sql | head -1)

stats:  ## Show database statistics
	@echo "Database statistics:"
	$(DOCKER_COMPOSE) exec netflow-collector python cleanup_db.py --stats

cleanup:  ## Clean old data (30 days)
	@echo "Cleaning old data..."
	$(DOCKER_COMPOSE) exec netflow-collector python cleanup_db.py --days 30 --vacuum
