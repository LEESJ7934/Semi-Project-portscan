output "aws_account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "aws_region" {
  value = var.aws_region
}

output "vpc_id" {
  value = aws_vpc.lab.id
}

output "scanner_instance_id" {
  value = aws_instance.scanner.id
}

output "scanner_public_ip" {
  value       = aws_instance.scanner.public_ip
  description = "Outbound/SSM management path only; scanner SG has no inbound rules."
}

output "scanner_private_ip" {
  value = aws_instance.scanner.private_ip
}

output "target_instance_id" {
  value = aws_instance.target.id
}

output "target_private_ip" {
  value = aws_instance.target.private_ip
}

output "target_security_group_id" {
  value = aws_security_group.target.id
}

output "flow_log_group" {
  value = aws_cloudwatch_log_group.flow.name
}
