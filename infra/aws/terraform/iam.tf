data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "scanner" {
  name               = "portscan-lab-scanner-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "scanner_ssm" {
  role       = aws_iam_role.scanner.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "scanner_inventory" {
  statement {
    sid = "ReadOnlyInventory"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeSecurityGroups"
    ]
    resources = ["*"]
  }
  statement {
    sid       = "CallerIdentity"
    actions   = ["sts:GetCallerIdentity"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "scanner_inventory" {
  name   = "portscan-readonly-inventory"
  role   = aws_iam_role.scanner.id
  policy = data.aws_iam_policy_document.scanner_inventory.json
}

resource "aws_iam_instance_profile" "scanner" {
  name = "portscan-lab-scanner-profile"
  role = aws_iam_role.scanner.name
}
