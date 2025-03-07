data "aws_ssm_parameter" "ses_email_identity_arn" { name = var.ssm_ses_email_identity_arn }

resource "aws_cognito_user_pool" "pool" {
  count                    = var.is_dmz ? 1 : 0
  name                     = var.user_pool_name
  mfa_configuration        = "ON"
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  software_token_mfa_configuration {
    enabled = true
  }
  email_configuration {
    email_sending_account  = "DEVELOPER"
    from_email_address     = "noreply@${var.frontend_domain}"
    reply_to_email_address = "vulnerability@cisa.dhs.gov"
    source_arn             = aws_ses_email_identity.default[0].arn
  }


  # Users can recover their accounts by verifying their email address (required mechanism)
  verification_message_template {
    email_subject = "Crossfeed verification code"
    email_message = "Your verification code is {####}. Please enter this code in when logging into Crossfeed to complete your account setup."
  }

  tags = {
    Project = var.project
    Owner   = "Crossfeed managed resource"
  }
}

resource "aws_cognito_user_pool" "lz_pool" {
  count                    = var.is_dmz ? 0 : 1
  provider                 = aws.other
  name                     = var.user_pool_name
  mfa_configuration        = "ON"
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  software_token_mfa_configuration {
    enabled = true
  }
  email_configuration {
    email_sending_account  = "DEVELOPER"
    from_email_address     = "noreply@${var.frontend_domain}"
    reply_to_email_address = "vulnerability@cisa.dhs.gov"
    source_arn             = data.aws_ssm_parameter.ses_email_identity_arn.value
  }


  # Users can recover their accounts by verifying their email address (required mechanism)
  verification_message_template {
    email_subject = "Crossfeed verification code"
    email_message = "Your verification code is {####}. Please enter this code in when logging into Crossfeed to complete your account setup."
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  tags = {
    Project = var.project
    Owner   = "Crossfeed managed resource"
  }
}

resource "aws_ses_email_identity" "default" {
  count = var.is_dmz ? 1 : 0
  email = var.ses_support_email_sender
}

resource "aws_cognito_user_pool_domain" "auth_domain" {
  count        = var.is_dmz ? 1 : 0
  domain       = var.user_pool_domain
  user_pool_id = aws_cognito_user_pool.pool[0].id
}

resource "aws_cognito_user_pool_domain" "auth_domain_lz" {
  count        = var.is_dmz ? 0 : 1
  provider     = aws.other
  domain       = var.user_pool_domain
  user_pool_id = aws_cognito_user_pool.lz_pool[0].id
}

resource "aws_cognito_user_pool_client" "client" {
  count                                = var.is_dmz ? 1 : 0
  name                                 = "crossfeed"
  user_pool_id                         = aws_cognito_user_pool.pool[0].id
  callback_urls                        = ["http://localhost"]
  supported_identity_providers         = ["COGNITO"]
  allowed_oauth_scopes                 = ["email", "openid"]
  allowed_oauth_flows                  = ["code"]
  explicit_auth_flows                  = ["ALLOW_CUSTOM_AUTH", "ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_SRP_AUTH"]
  allowed_oauth_flows_user_pool_client = true
  prevent_user_existence_errors        = "ENABLED"
}

resource "aws_cognito_user_pool_client" "client_lz" {
  count                                = var.is_dmz ? 0 : 1
  provider                             = aws.other
  name                                 = "crossfeed"
  user_pool_id                         = aws_cognito_user_pool.lz_pool[0].id
  callback_urls                        = ["http://localhost"]
  supported_identity_providers         = ["COGNITO"]
  allowed_oauth_scopes                 = ["email", "openid"]
  allowed_oauth_flows                  = ["code"]
  explicit_auth_flows                  = ["ALLOW_CUSTOM_AUTH", "ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_SRP_AUTH"]
  allowed_oauth_flows_user_pool_client = true
  prevent_user_existence_errors        = "ENABLED"
}

resource "aws_ssm_parameter" "user_pool_id" {
  count     = var.is_dmz ? 1 : 0
  name      = var.ssm_user_pool_id
  type      = "String"
  value     = aws_cognito_user_pool.pool[0].id
  overwrite = true

  tags = {
    Project = var.project
    Owner   = "Crossfeed managed resource"
  }
}

resource "aws_ssm_parameter" "user_pool_client_id" {
  count     = var.is_dmz ? 1 : 0
  name      = var.ssm_user_pool_client_id
  type      = "String"
  value     = aws_cognito_user_pool_client.client[0].id
  overwrite = true

  tags = {
    Project = var.project
    Owner   = "Crossfeed managed resource"
  }
}

resource "aws_ssm_parameter" "user_pool_id_lz" {
  count     = var.is_dmz ? 0 : 1
  name      = var.ssm_user_pool_id
  type      = "String"
  value     = aws_cognito_user_pool.lz_pool[0].id
  overwrite = true

  tags = {
    Project = var.project
    Owner   = "Crossfeed managed resource"
  }
}

resource "aws_ssm_parameter" "user_pool_client_id_lz" {
  count     = var.is_dmz ? 0 : 1
  name      = var.ssm_user_pool_client_id
  type      = "String"
  value     = aws_cognito_user_pool_client.client_lz[0].id
  overwrite = true

  tags = {
    Project = var.project
    Owner   = "Crossfeed managed resource"
  }
}
