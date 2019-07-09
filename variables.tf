variable "client_name" {
  description = "Name of the organisation, used in the bucket name to ensure there are no conflicts"
}

variable "global_state_bucket" {
  description = "The name of the bucket containing the global module state"
}

variable "global_state_key" {
  description = "The key of the global module state as defined in the backend"
}

variable "global_state_region" {
  description = "The region of the bucket containing the global module state"
}

variable "global_state_profile" {
  description = "The profile to be used to access the global module state bucket"
}
