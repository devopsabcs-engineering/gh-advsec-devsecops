resource "random_integer" "rnd_int" {
  min     = 1
  max     = 10000
}

resource "random_password" "sql_admin_password" {
  length           = 24
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
  min_lower        = 1
  min_numeric      = 1
  min_upper        = 1
  min_special      = 1
}

resource "random_password" "postgresql_admin_password" {
  length           = 24
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
  min_lower        = 1
  min_numeric      = 1
  min_upper        = 1
  min_special      = 1
}