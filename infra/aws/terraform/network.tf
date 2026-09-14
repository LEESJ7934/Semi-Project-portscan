resource "aws_vpc" "lab" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "portscan-lab-vpc" }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "portscan-lab-igw" }
}

resource "aws_subnet" "scanner" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = var.scanner_subnet_cidr
  map_public_ip_on_launch = true
  tags                    = { Name = "portscan-scanner-subnet" }
}

resource "aws_subnet" "target" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = var.target_subnet_cidr
  map_public_ip_on_launch = false
  tags                    = { Name = "portscan-target-subnet" }
}

resource "aws_route_table" "scanner" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }
  tags = { Name = "portscan-scanner-rt" }
}

resource "aws_route_table_association" "scanner" {
  subnet_id      = aws_subnet.scanner.id
  route_table_id = aws_route_table.scanner.id
}

# The target subnet intentionally has no default Internet route.
resource "aws_route_table" "target" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "portscan-target-rt" }
}

resource "aws_route_table_association" "target" {
  subnet_id      = aws_subnet.target.id
  route_table_id = aws_route_table.target.id
}
