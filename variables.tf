variable "client_name" {
  description = "Name of the organisation, used in the bucket name to ensure there are no conflicts"
}

variable "account_ids" {
  description = "A list of account IDs permitted to send trails to the org master"
  type        = list(string)
}
