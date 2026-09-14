resource "aws_security_group" "scanner" {
  name        = "portscan-scanner-sg"
  description = "No inbound administration ports; use SSM Session Manager"
  vpc_id      = aws_vpc.lab.id
  tags        = { Name = "portscan-scanner-sg" }
}

resource "aws_vpc_security_group_egress_rule" "scanner_all_egress" {
  security_group_id = aws_security_group.scanner.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "Outbound access for SSM and package/repository access"
}

resource "aws_security_group" "target" {
  name        = "portscan-target-sg"
  description = "Lab service is reachable only from the scanner Security Group"
  vpc_id      = aws_vpc.lab.id
  tags        = { Name = "portscan-target-sg" }
}

resource "aws_vpc_security_group_ingress_rule" "target_http_from_scanner" {
  security_group_id            = aws_security_group.target.id
  referenced_security_group_id = aws_security_group.scanner.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
  description                  = "Authorized scanner to demo HTTP service"
}

resource "aws_vpc_security_group_egress_rule" "target_all_egress" {
  security_group_id = aws_security_group.target.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "No Internet route exists for the target subnet; VPC-local return traffic is permitted"
}

resource "aws_vpc_security_group_ingress_rule" "demo_broad_ssh" {
  count             = var.enable_demo_misconfiguration ? 1 : 0
  security_group_id = aws_security_group.target.id
  description       = "DEMO ONLY - broad SSH rule for configuration analyzer"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}
