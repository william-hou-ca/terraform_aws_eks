output "endpoint" {
  value = aws_eks_cluster.this.endpoint
}
/*
output "kubeconfig-certificate-authority-data" {
  value = aws_eks_cluster.this.certificate_authority[0].data
}
*/
output "ec2-ip" {
  value = aws_instance.web.public_ip
}