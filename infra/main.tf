# =============================================================================
# infra/main.tf - corrigido a partir de main.insecure.tf (material da disciplina, Encontro 12).
#
# Uso: SOMENTE terraform validate e scanners (Checkov, Trivy config) - nada de "apply".
# O pipeline roda init -backend=false e validate, sem credencial AWS.
#
# Correspondência com as FALHAS da versão insegura:
#   FALHA 1 sem tags                -> default_tags no provider (todos os recursos)
#   FALHA 2 public access block off -> os quatro bloqueios ligados, nos dois buckets
#   FALHA 3 ACL public-read         -> sem ACL; BucketOwnerEnforced (ACLs desativadas)
#   FALHA 4 sem criptografia        -> SSE-KMS com chave do cliente (rotação anual)
#   FALHA 5 sem versionamento       -> versionamento ligado
#   FALHA 6 SSH de 0.0.0.0/0        -> SSH só da faixa em var.ip_permitido_ssh (validada)
#   FALHA 7 egress irrestrito       -> egress só HTTPS e só para var.cidr_saida_https (proxy/endpoints)
# Além do material de referência (achados do Checkov): logging de acesso do bucket em um
# bucket de logs dedicado, lifecycle, TLS obrigatório por bucket policy, key policy explícita.
# Todo "checkov:skip" tem a justificativa na mesma linha.
# =============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  # Em uso real: backend remoto cifrado com trava (S3 + DynamoDB). O state guarda valores
  # sensíveis em texto puro, por isso nunca é versionado (ver .gitignore).
}

provider "aws" {
  region = var.regiao
  default_tags {
    tags = {
      Projeto  = "taskflow-devsecops"
      Ambiente = "estudo"
      Owner    = "grupo-devsecops"
    }
  }
}

data "aws_caller_identity" "atual" {}

# --------------------------------------------------------------------------- variáveis
variable "regiao" {
  description = "Região AWS."
  type        = string
  default     = "us-east-1"
}

variable "ip_permitido_ssh" {
  description = "Faixa CIDR autorizada a SSH (VPN/bastion). Nunca 0.0.0.0/0."
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.ip_permitido_ssh, 0)) && var.ip_permitido_ssh != "0.0.0.0/0"
    error_message = "Informe um CIDR válido e diferente de 0.0.0.0/0."
  }
}

variable "cidr_saida_https" {
  description = "Destino permitido para HTTPS de saida: proxy de egress ou VPC endpoints. Nunca 0.0.0.0/0."
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.cidr_saida_https, 0)) && var.cidr_saida_https != "0.0.0.0/0"
    error_message = "Informe um CIDR valido e diferente de 0.0.0.0/0."
  }
}

variable "vpc_id" {
  description = "VPC onde o security group será criado."
  type        = string
  default     = "vpc-00000000000000000"
}

# --------------------------------------------------------------------------- KMS
resource "aws_kms_key" "relatorios" {
  description             = "Cifra os buckets de relatorios e de logs do TaskFlow"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  # Key policy explícita: só a própria conta administra a chave; o S3 usa via IAM.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AdministracaoPelaConta"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.atual.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}

# --------------------------------------------------------------------------- bucket de logs
# Destino dos logs de acesso do bucket de relatórios (não pode ser o próprio bucket).
resource "aws_s3_bucket" "logs" {
  #checkov:skip=CKV_AWS_18:este E o bucket de destino dos logs de acesso; logar nele mesmo cria laco
  #checkov:skip=CKV_AWS_144:replicacao entre regioes fora do escopo do lab (estudo, regiao unica)
  #checkov:skip=CKV2_AWS_62:notificacao de eventos exigiria SNS/SQS sem consumidor no lab
  bucket = "taskflow-logs-acesso-exemplo-devsecops"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.relatorios.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    id     = "expira-logs-de-acesso"
    status = "Enabled"
    filter {}
    expiration {
      days = 365
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# --------------------------------------------------------------------------- bucket de relatórios
resource "aws_s3_bucket" "relatorios_taskflow" {
  #checkov:skip=CKV_AWS_144:replicacao entre regioes fora do escopo do lab (estudo, regiao unica)
  #checkov:skip=CKV2_AWS_62:notificacao de eventos exigiria SNS/SQS sem consumidor no lab
  bucket = "taskflow-relatorios-exemplo-curso-devsecops"
}

resource "aws_s3_bucket_public_access_block" "relatorios_taskflow" {
  bucket                  = aws_s3_bucket.relatorios_taskflow.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Corrige a FALHA 3 de forma mais forte que trocar para ACL "private": ACLs desativadas.
resource "aws_s3_bucket_ownership_controls" "relatorios_taskflow" {
  bucket = aws_s3_bucket.relatorios_taskflow.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "relatorios_taskflow" {
  bucket = aws_s3_bucket.relatorios_taskflow.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.relatorios.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "relatorios_taskflow" {
  bucket = aws_s3_bucket.relatorios_taskflow.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "relatorios_taskflow" {
  bucket        = aws_s3_bucket.relatorios_taskflow.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "relatorios/"
}

resource "aws_s3_bucket_lifecycle_configuration" "relatorios_taskflow" {
  bucket = aws_s3_bucket.relatorios_taskflow.id
  rule {
    id     = "versoes-antigas"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Nega qualquer acesso que não use TLS (dados em trânsito).
resource "aws_s3_bucket_policy" "relatorios_somente_tls" {
  bucket = aws_s3_bucket.relatorios_taskflow.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "NegaSemTLS"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.relatorios_taskflow.arn,
        "${aws_s3_bucket.relatorios_taskflow.arn}/*",
      ]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.relatorios_taskflow]
}

# --------------------------------------------------------------------------- security group
resource "aws_security_group" "taskflow_app_sg" {
  #checkov:skip=CKV2_AWS_5:SG de exemplo do lab; nao ha instancia EC2 porque o lab nao faz apply
  name        = "taskflow-app-sg-corrigido"
  description = "TaskFlow: SSH so da faixa autorizada, saida so HTTPS"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH somente da faixa autorizada (var.ip_permitido_ssh)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.ip_permitido_ssh]
  }

  # Alem do main.fixed.tf de referencia (que deixava 443 para 0.0.0.0/0, acusado pelo Trivy
  # como AVD-AWS-0104): a instancia so sai por HTTPS para o proxy de egress/VPC endpoints.
  # Se for comprometida, nao alcanca a internet diretamente para exfiltrar dados.
  egress {
    description = "Saida HTTPS apenas para o proxy de egress ou VPC endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.cidr_saida_https]
  }
}

# --------------------------------------------------------------------------- saídas
output "nome_bucket_relatorios" {
  description = "Nome do bucket de relatorios"
  value       = aws_s3_bucket.relatorios_taskflow.bucket
}

output "id_security_group_app" {
  description = "ID do security group da aplicacao"
  value       = aws_security_group.taskflow_app_sg.id
}
