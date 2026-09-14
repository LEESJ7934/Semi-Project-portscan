resource "aws_instance" "scanner" {
  ami                         = data.aws_ssm_parameter.al2023_ami.value
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.scanner.id
  vpc_security_group_ids      = [aws_security_group.scanner.id]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.scanner.name
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
  root_block_device {
    encrypted   = true
    volume_type = "gp3"
  }
  tags = { Name = "portscan-scanner" }
}

resource "aws_instance" "target" {
  ami                         = data.aws_ssm_parameter.al2023_ami.value
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.target.id
  vpc_security_group_ids      = [aws_security_group.target.id]
  associate_public_ip_address = false
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
  root_block_device {
    encrypted   = true
    volume_type = "gp3"
  }
  user_data = <<-EOF
    #!/bin/bash
    cat >/etc/systemd/system/portscan-demo.service <<'UNIT'
    [Unit]
    Description=Authorized port scanner demo HTTP service
    After=network.target
    [Service]
    ExecStart=/usr/bin/python3 -m http.server 8080 --bind 0.0.0.0 --directory /var/tmp
    Restart=always
    User=nobody
    [Install]
    WantedBy=multi-user.target
    UNIT
    echo 'Authorized AWS port scanner lab' >/var/tmp/index.html
    systemctl daemon-reload
    systemctl enable --now portscan-demo.service
  EOF
  tags      = { Name = "portscan-target" }
}
