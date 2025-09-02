locals {
  project = "quickshort"
}


############################
# SNS for alerts
############################
resource "aws_sns_topic" "alerts" {
  name = "${local.project}-alerts"
}

resource "aws_sns_topic" "alerts_use1" {
  provider = aws.use1
  name     = "${local.project}-alerts"
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.sns_alerts.json
}

resource "aws_sns_topic_policy" "alerts_use1" {
  provider = aws.use1
  arn      = aws_sns_topic.alerts_use1.arn
  policy   = data.aws_iam_policy_document.sns_alerts_use1.json
}

data "aws_iam_policy_document" "sns_alerts" {
  statement {
    sid     = "AllowCloudWatchToPublish"
    actions = ["sns:Publish"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    resources = [aws_sns_topic.alerts.arn]
  }
}

data "aws_iam_policy_document" "sns_alerts_use1" {
  statement {
    sid     = "AllowCloudWatchToPublish"
    actions = ["sns:Publish"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    resources = [aws_sns_topic.alerts_use1.arn]
  }
}

resource "aws_sns_topic_subscription" "alerts_email_use1" {
  provider  = aws.use1
  topic_arn = aws_sns_topic.alerts_use1.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sns_topic_subscription" "alerts_email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

############################
# Lambda Alarms (API + Log Processor)
############################
# API Lambda
resource "aws_cloudwatch_metric_alarm" "api_lambda_errors" {
  alarm_name          = "${local.project}-api-lambda-errors"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "quickshort_api reported >=1 errors in the last minute"
  dimensions = {
    FunctionName = "quickshort_api"
  }
  treat_missing_data = "notBreaching"
  alarm_actions      = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "api_lambda_p95_latency" {
  alarm_name          = "${local.project}-api-lambda-p95-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 5
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = 60
  extended_statistic  = "p95"
  threshold           = 500
  alarm_description   = "quickshort_api p95 duration > 500ms over 5 minutes"
  dimensions          = { FunctionName = "quickshort_api" }
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "logproc_errors" {
  provider            = aws.use1
  alarm_name          = "${local.project}-logproc-errors"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "logproc Lambda had >=1 errors"
  dimensions = {
    FunctionName = "quickshort_cf_logproc"
  }
  treat_missing_data = "notBreaching"
  alarm_actions      = [aws_sns_topic.alerts_use1.arn]
}

resource "aws_cloudwatch_metric_alarm" "logproc_iterator_age" {
  provider            = aws.use1
  alarm_name          = "${local.project}-logproc-iterator-age"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "IteratorAge"
  namespace           = "AWS/Lambda"
  period              = 60
  statistic           = "Maximum"
  threshold           = 60
  alarm_description   = "Kinesis iterator age for logproc > 60s (falling behind)"
  dimensions = {
    FunctionName = "quickshort_cf_logproc"
  }
  treat_missing_data = "notBreaching"
  alarm_actions      = [aws_sns_topic.alerts_use1.arn]
}

resource "aws_cloudwatch_metric_alarm" "logproc_throttles" {
  provider            = aws.use1
  alarm_name          = "${local.project}-logproc-throttles"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Throttles"
  namespace           = "AWS/Lambda"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "logproc Lambda throttled (increase concurrency or check Kinesis shard limits)"
  dimensions = {
    FunctionName = "quickshort_cf_logproc"
  }
  treat_missing_data = "notBreaching"
  alarm_actions      = [aws_sns_topic.alerts_use1.arn]
}

############################
# Kinesis Stream Alarms (us-east-1)
############################
resource "aws_cloudwatch_metric_alarm" "kinesis_read_exceeded" {
  provider            = aws.use1
  alarm_name          = "${local.project}-kinesis-read-provisioned-exceeded"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ReadProvisionedThroughputExceeded"
  namespace           = "AWS/Kinesis"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Kinesis read throughput exceeded – add shards or slow consumer"
  dimensions          = { StreamName = aws_kinesis_stream.cf_rt_logs.name }
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts_use1.arn]
}

resource "aws_cloudwatch_metric_alarm" "kinesis_write_exceeded" {
  provider            = aws.use1
  alarm_name          = "${local.project}-kinesis-write-provisioned-exceeded"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "WriteProvisionedThroughputExceeded"
  namespace           = "AWS/Kinesis"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Kinesis write throughput exceeded – CloudFront pushing too hard"
  dimensions          = { StreamName = aws_kinesis_stream.cf_rt_logs.name }
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts_use1.arn]
}

############################
# DynamoDB Alarms
############################
resource "aws_cloudwatch_metric_alarm" "ddb_throttled" {
  alarm_name          = "${local.project}-ddb-throttled-requests"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ThrottledRequests"
  namespace           = "AWS/DynamoDB"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "DynamoDB throttling – consider on-demand or higher WCU/RCU"
  dimensions          = { TableName = aws_dynamodb_table.links.name }
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "ddb_system_errors" {
  alarm_name          = "${local.project}-ddb-system-errors"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "SystemErrors"
  namespace           = "AWS/DynamoDB"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "DynamoDB system errors observed"
  dimensions          = { TableName = aws_dynamodb_table.links.name }
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

############################
# API Gateway Alarms
############################
resource "aws_cloudwatch_metric_alarm" "apigw_5xx" {
  alarm_name          = "${local.project}-apigw-5xx"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "5XXError"
  namespace           = "AWS/ApiGateway"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "API Gateway 5XX errors"
  dimensions          = { ApiId = aws_apigatewayv2_api.http.id }
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "apigw_latency_p95" {
  alarm_name          = "${local.project}-apigw-p95-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 5
  metric_name         = "Latency"
  namespace           = "AWS/ApiGateway"
  period              = 60
  extended_statistic  = "p95"
  threshold           = 400
  alarm_description   = "API Gateway p95 latency > 400ms over 5 minutes"
  dimensions          = { ApiId = aws_apigatewayv2_api.http.id }
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

############################
# CloudFront + WAF Alarms (us-east-1)
############################
# CloudFront 5xx rate on default behavior
resource "aws_cloudwatch_metric_alarm" "cf_5xx_rate" {
  provider            = aws.use1
  alarm_name          = "${local.project}-cf-5xx-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  threshold           = 1
  metric_query {
    id          = "e5xx"
    label       = "5xx count"
    return_data = false
    metric {
      metric_name = "5xxErrorRate"
      namespace   = "AWS/CloudFront"
      period      = 60
      stat        = "Average"
      dimensions  = { DistributionId = aws_cloudfront_distribution.cdn.id, Region = "Global" }
    }
  }
  metric_query {
    id          = "an"
    label       = "5xx > 1%"
    return_data = true
    expression  = "e5xx"
  }
  alarm_description  = "CloudFront 5xx rate > 1% over 3 minutes"
  treat_missing_data = "notBreaching"
  alarm_actions      = [aws_sns_topic.alerts_use1.arn]
}

# WAF blocks spike
resource "aws_cloudwatch_metric_alarm" "waf_block_spike" {
  provider            = aws.use1
  alarm_name          = "${local.project}-waf-blocked-requests"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = 60
  statistic           = "Sum"
  threshold           = 50
  alarm_description   = "WAF blocked requests spike"
  dimensions = {
    WebACL = aws_wafv2_web_acl.cf_acl.name
    Region = "Global"
    Rule   = "ALL"
  }
  treat_missing_data = "notBreaching"
  alarm_actions      = [aws_sns_topic.alerts_use1.arn]
}

############################
# CloudWatch Dashboard (concise overview)
############################
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${local.project}-overview"
  dashboard_body = jsonencode({
    widgets = [
      {
        "type" : "text",
        "x" : 0, "y" : 0, "width" : 24, "height" : 2,
        "properties" : { "markdown" : "# QuickShort — Ops Dashboard" }
      },
      {
        "type" : "metric",
        "x" : 0, "y" : 2, "width" : 12, "height" : 6,
        "properties" : {
          "title" : "API Lambda — Errors & p95",
          "metrics" : [["AWS/Lambda", "Errors", "FunctionName", "quickshort_api", { "stat" : "Sum" }], [".", "Duration", ".", ".", { "stat" : "p95" }]],
          "period" : 60,
          "stacked" : false,
          "region" : var.aws_region_lambda
        }
      },
      {
        "type" : "metric",
        "x" : 12, "y" : 2, "width" : 12, "height" : 6,
        "properties" : {
          "title" : "APIGW — 5XX & p95 Latency",
          "metrics" : [["AWS/ApiGateway", "5XXError", "ApiId", aws_apigatewayv2_api.http.id, { "stat" : "Sum" }], [".", "Latency", ".", ".", { "stat" : "p95" }]],
          "period" : 60,
          "region" : var.aws_region_lambda
        }
      },
      {
        "type" : "metric",
        "x" : 0, "y" : 8, "width" : 12, "height" : 6,
        "properties" : {
          "title" : "LogProc — Errors & IteratorAge",
          "region" : "us-east-1",
          "metrics" : [
            ["AWS/Lambda", "Errors", "FunctionName", "quickshort_cf_logproc", { "stat" : "Sum" }],
            [".", "IteratorAge", ".", ".", { "stat" : "Maximum" }]
          ],
          "period" : 60
        }
      },
      {
        "type" : "metric",
        "x" : 12, "y" : 8, "width" : 12, "height" : 6,
        "properties" : {
          "title" : "Kinesis — Incoming & Throughput Exceeded",
          "region" : "us-east-1",
          "metrics" : [
            ["AWS/Kinesis", "IncomingRecords", "StreamName", jsonencode(aws_kinesis_stream.cf_rt_logs.name)],
            [".", "ReadProvisionedThroughputExceeded", ".", ".", { "stat" : "Sum" }],
            [".", "WriteProvisionedThroughputExceeded", ".", ".", { "stat" : "Sum" }]
          ],
          "period" : 60
        }
      },
      {
        "type" : "metric",
        "x" : 0, "y" : 14, "width" : 12, "height" : 6,
        "properties" : {
          "title" : "DynamoDB — Throttles & SystemErrors",
          "region" : jsonencode(var.aws_region_lambda),
          "metrics" : [
            ["AWS/DynamoDB", "ThrottledRequests", "TableName", jsonencode(aws_dynamodb_table.links.name), { "stat" : "Sum" }],
            [".", "SystemErrors", ".", ".", { "stat" : "Sum" }]
          ],
          "period" : 60
        }
      },
      {
        "type" : "metric",
        "x" : 12, "y" : 14, "width" : 12, "height" : 6,
        "properties" : {
          "title" : "CloudFront & WAF",
          "region" : "us-east-1",
          "metrics" : [
            ["AWS/CloudFront", "5xxErrorRate", "DistributionId", jsonencode(aws_cloudfront_distribution.cdn.id), "Region", "Global", { "stat" : "Average" }],
            ["AWS/WAFV2", "BlockedRequests", "WebACL", jsonencode(aws_wafv2_web_acl.cf_acl.name), "Region", "Global", "Rule", "ALL", { "stat" : "Sum" }]
          ],
          "period" : 60
        }
      }
    ]
  })
}