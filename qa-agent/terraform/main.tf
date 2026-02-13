# QA Agent - GCP Infrastructure
# Deploy with: terraform init && terraform apply

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

variable "project_id" {
  description = "GCP Project ID"
  default     = "project-a4673773-3949-4a02"
}

variable "region" {
  default = "us-central1"
}

variable "anthropic_api_key" {
  description = "Anthropic API Key"
  sensitive   = true
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Enable required APIs
resource "google_project_service" "apis" {
  for_each = toset([
    "run.googleapis.com",
    "cloudbuild.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudscheduler.googleapis.com",
    "artifactregistry.googleapis.com"
  ])
  service            = each.value
  disable_on_destroy = false
}

# Artifact Registry for Docker images
resource "google_artifact_registry_repository" "qa_agent" {
  location      = var.region
  repository_id = "qa-agent"
  format        = "DOCKER"
  depends_on    = [google_project_service.apis]
}

# Secret for API Key
resource "google_secret_manager_secret" "anthropic_key" {
  secret_id = "anthropic-api-key"
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "anthropic_key_version" {
  secret      = google_secret_manager_secret.anthropic_key.id
  secret_data = var.anthropic_api_key
}

# Cloud Run Service - Main API
resource "google_cloud_run_v2_service" "qa_agent_api" {
  name     = "qa-agent-api"
  location = var.region

  template {
    containers {
      image = "${var.region}-docker.pkg.dev/${var.project_id}/qa-agent/api:latest"

      resources {
        limits = {
          memory = "2Gi"
          cpu    = "2"
        }
      }

      env {
        name = "ANTHROPIC_API_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.anthropic_key.secret_id
            version = "latest"
          }
        }
      }

      ports {
        container_port = 8000
      }
    }

    scaling {
      min_instance_count = 0
      max_instance_count = 10
    }
  }

  depends_on = [google_project_service.apis]
}

# Make API publicly accessible
resource "google_cloud_run_v2_service_iam_member" "public_access" {
  name     = google_cloud_run_v2_service.qa_agent_api.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# Cloud Run Service - Landing Page
resource "google_cloud_run_v2_service" "landing_page" {
  name     = "qa-agent-landing"
  location = var.region

  template {
    containers {
      image = "${var.region}-docker.pkg.dev/${var.project_id}/qa-agent/landing:latest"

      resources {
        limits = {
          memory = "256Mi"
          cpu    = "1"
        }
      }

      ports {
        container_port = 80
      }
    }

    scaling {
      min_instance_count = 0
      max_instance_count = 5
    }
  }

  depends_on = [google_project_service.apis]
}

resource "google_cloud_run_v2_service_iam_member" "landing_public" {
  name     = google_cloud_run_v2_service.landing_page.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# Cloud Scheduler for Daily Tests
resource "google_cloud_scheduler_job" "daily_tests" {
  name        = "daily-qa-tests"
  description = "Run QA tests every morning at 6 AM"
  schedule    = "0 6 * * *"
  time_zone   = "America/New_York"

  http_target {
    uri         = "${google_cloud_run_v2_service.qa_agent_api.uri}/run-scheduled"
    http_method = "POST"
    headers = {
      "Content-Type" = "application/json"
    }
  }

  depends_on = [google_project_service.apis]
}

# Outputs
output "api_url" {
  value = google_cloud_run_v2_service.qa_agent_api.uri
}

output "landing_url" {
  value = google_cloud_run_v2_service.landing_page.uri
}

output "deploy_commands" {
  value = <<-EOT

    === DEPLOYMENT COMMANDS ===

    1. Build and push API:
       docker build -t ${var.region}-docker.pkg.dev/${var.project_id}/qa-agent/api:latest .
       docker push ${var.region}-docker.pkg.dev/${var.project_id}/qa-agent/api:latest

    2. Build and push Landing:
       docker build -t ${var.region}-docker.pkg.dev/${var.project_id}/qa-agent/landing:latest ./landing
       docker push ${var.region}-docker.pkg.dev/${var.project_id}/qa-agent/landing:latest

    3. Update services:
       gcloud run services update qa-agent-api --region ${var.region}
       gcloud run services update qa-agent-landing --region ${var.region}

  EOT
}
