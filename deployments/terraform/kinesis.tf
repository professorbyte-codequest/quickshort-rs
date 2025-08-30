resource "aws_kinesis_stream" "cf_rt_logs" {
  provider         = aws.use1
  name             = "qs-cf-rt-logs"
  shard_count      = 1
  retention_period = 24
  stream_mode_details { stream_mode = "PROVISIONED" }
  tags = { app = "quickshort" }
}