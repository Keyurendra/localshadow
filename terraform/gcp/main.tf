locals {
  otel_collector_config = templatefile("${path.module}/otel-collector-config.yaml", {
    tenant_id = var.artifact_tenant_id
  })
  cloud_init_config = templatefile("${path.module}/cloud-init.yaml", {
    provider              = "gcp"
    artifact_token        = var.artifact_token
    artifact_endpoint     = var.artifact_endpoint
    artifact_label        = var.artifact_label
    artifact_tenant_id    = var.artifact_tenant_id
    omni_additional_flags = var.omni_additional_flags
    enable_telemetry      = var.enable_telemetry
    otel_collector_config = local.otel_collector_config
  })
}

resource "null_resource" "metadata_trigger" {
  triggers = {
    user_data = local.cloud_init_config
  }
}

resource "google_service_account" "omni" {
  account_id   = "accuknox-omni"
  display_name = "AccuKnox Omni"
  description  = "Service account for Omni host VM"
}

resource "google_project_iam_custom_role" "omni_compute_role" {
  role_id     = "accuknox_omni"
  title       = "AccuKnox Omni"
  description = "Minimal permissions for AccuKnox Omni"
  permissions = [
    "compute.instances.get",
    "compute.instances.attachDisk",
    "compute.instances.detachDisk",
    "compute.instances.list",
    "compute.disks.get",
    "compute.disks.list",
    "compute.disks.create",
    "compute.disks.delete",
    "compute.disks.use",
    "compute.disks.createSnapshot",
    "compute.snapshots.get",
    "compute.snapshots.list",
    "compute.snapshots.create",
    "compute.snapshots.delete",
    "compute.snapshots.useReadOnly",
    "compute.zones.get",
    "compute.projects.get",
    "compute.globalOperations.get",
    "compute.zoneOperations.get",
  ]
}

resource "google_project_iam_member" "omni_compute_permissions" {
  project = var.project_id
  role    = google_project_iam_custom_role.omni_compute_role.name
  member  = "serviceAccount:${google_service_account.omni.email}"
}

resource "google_service_account_iam_member" "allow_self_impersonation" {
  service_account_id = google_service_account.omni.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.omni.email}"
}

data "google_compute_image" "ubuntu_latest_lts" {
  family  = "ubuntu-minimal-2404-lts-amd64"
  project = "ubuntu-os-cloud"
}

resource "google_compute_network" "vpc" {
  name                    = "accuknox-omni"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "private_subnet" {
  name                     = "accuknox-omni-private"
  ip_cidr_range            = "10.0.1.0/24"
  region                   = var.region
  network                  = google_compute_network.vpc.id
  private_ip_google_access = true
}

resource "google_compute_router" "router" {
  name    = "nat-router"
  region  = var.region
  network = google_compute_network.vpc.id
}

resource "google_compute_router_nat" "nat" {
  name                               = "nat-gateway"
  router                             = google_compute_router.router.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

resource "google_compute_firewall" "allow_internal" {
  name    = "allow-ssh-via-console"
  network = google_compute_network.vpc.name
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["35.235.240.0/20"]
}

resource "google_compute_instance" "omni" {
  name         = "accuknox-omni"
  machine_type = var.machine_type
  tags         = ["accuknox", "accuknox-omni"]
  boot_disk {
    initialize_params {
      image = data.google_compute_image.ubuntu_latest_lts.self_link
      size  = 10
      type  = "pd-balanced"
    }
  }
  network_interface {
    network    = google_compute_network.vpc.id
    subnetwork = google_compute_subnetwork.private_subnet.id
  }
  service_account {
    email  = google_service_account.omni.email
    scopes = ["cloud-platform"]
  }
  metadata = {
    user-data = local.cloud_init_config
  }
  lifecycle {
    replace_triggered_by = [null_resource.metadata_trigger]
  }
}
