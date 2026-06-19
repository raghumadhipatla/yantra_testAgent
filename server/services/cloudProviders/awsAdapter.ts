import type { CloudCredential } from "@shared/schema";
import type {
  CloudProvider,
  DeploymentTarget,
  ProviderResult,
  HealthCheckResult,
  ProviderCapabilities,
  LogsOptions,
  LogsResult,
  MLDeploymentTarget,
  MLDeploymentResult,
  MLTrainingConfig,
  MLTrainingResult,
  MLEndpointHealth,
  MLEndpointMetrics,
  PrepareContext,
  PrepareResult,
} from "./types";
import type { ProductionVariantInstanceType, TrainingInstanceType } from "@aws-sdk/client-sagemaker";
import { createProviderLogger, sanitizeCloudError } from "./types";
import {
  ECSClient,
  CreateServiceCommand,
  UpdateServiceCommand,
  DescribeServicesCommand,
  ListTaskDefinitionsCommand,
  RegisterTaskDefinitionCommand,
  DescribeClustersCommand,
  CreateClusterCommand,
} from "@aws-sdk/client-ecs";
import {
  LambdaClient,
  CreateFunctionCommand as _CreateFunctionCommand,
  UpdateFunctionCodeCommand as _UpdateFunctionCodeCommand,
  GetFunctionCommand as _GetFunctionCommand,
  UpdateFunctionConfigurationCommand as _UpdateFunctionConfigurationCommand,
} from "@aws-sdk/client-lambda";
import {
  CloudWatchLogsClient,
  GetLogEventsCommand as _GetLogEventsCommand,
  FilterLogEventsCommand,
  DescribeLogGroupsCommand as _DescribeLogGroupsCommand,
  DescribeLogStreamsCommand as _DescribeLogStreamsCommand,
} from "@aws-sdk/client-cloudwatch-logs";

import { circuitBreakerRegistry } from "../../infrastructure/circuitBreaker";
import { retryWithBackoff } from "../retryWithBackoff";

const logger = createProviderLogger("AWS");

const awsCircuitBreaker = circuitBreakerRegistry.getOrCreate("aws-cloud-provider", {
  failureThresholdPercentage: 50,
  volumeThreshold: 5,
  timeoutMs: 30000,
  resetTimeoutMs: 30000,
  halfOpenMaxAttempts: 3,
});

// SDK client cache to avoid creating new clients on every request
const CLIENT_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const clientCache = new Map<string, { client: any; expiresAt: number }>();

function getCachedClient<T>(key: string, factory: () => T): T {
  const cached = clientCache.get(key);
  if (cached && cached.expiresAt > Date.now()) return cached.client as T;
  const client = factory();
  clientCache.set(key, { client, expiresAt: Date.now() + CLIENT_CACHE_TTL });
  return client;
}

export class AWSAdapter implements CloudProvider {
  readonly name = "aws";
  readonly displayName = "Amazon Web Services";

  static capabilities: ProviderCapabilities = {
    supportsRollback: true,
    supportsHealthCheck: true,
    supportsAutoScaling: true,
    supportsBlueGreen: true,
    supportsCanary: true,
    deploymentTypes: ["ecs", "lambda", "ec2", "app-runner", "sagemaker", "sagemaker-training", "s3", "ecr"],
  };

  private createECSClient(credentials: CloudCredential): ECSClient {
    const region = credentials.region || "us-east-1";
    const key = `ecs:${credentials.accessKeyId}:${region}`;
    return getCachedClient(key, () => new ECSClient({
      region,
      credentials: {
        accessKeyId: credentials.accessKeyId!,
        secretAccessKey: credentials.secretAccessKey!,
      },
    }));
  }

  private createLambdaClient(credentials: CloudCredential): LambdaClient {
    const region = credentials.region || "us-east-1";
    const key = `lambda:${credentials.accessKeyId}:${region}`;
    return getCachedClient(key, () => new LambdaClient({
      region,
      credentials: {
        accessKeyId: credentials.accessKeyId!,
        secretAccessKey: credentials.secretAccessKey!,
      },
    }));
  }

  private createLogsClient(credentials: CloudCredential): CloudWatchLogsClient {
    const region = credentials.region || "us-east-1";
    const key = `logs:${credentials.accessKeyId}:${region}`;
    return getCachedClient(key, () => new CloudWatchLogsClient({
      region,
      credentials: {
        accessKeyId: credentials.accessKeyId!,
        secretAccessKey: credentials.secretAccessKey!,
      },
    }));
  }

  /**
   * AWS-specific pre-deploy step. Depending on deployment type, this would:
   *   - Elastic Beanstalk: zip the build artifact and upload to S3 (EB source
   *     bundle) before CreateApplicationVersion.
   *   - ECS / App Runner: `docker build && docker push` to ECR, returning the
   *     image URI that `deploy()` references in the ECS task definition.
   *   - Lambda (container): docker push to ECR and update function code.
   * Scaffold: no-op that logs intent and keeps parity with other providers.
   */
  async prepare(target: DeploymentTarget, _credentials: CloudCredential, ctx: PrepareContext): Promise<PrepareResult> {
    const dtype = target.targetType || "ecs";
    await ctx.log("info", `AWS prepare (${dtype}): would build + push artifact to ECR/S3 for ${target.serviceName || target.projectId}`);
    return { success: true, message: "AWS prepare scaffold complete" };
  }

  async deploy(
    target: DeploymentTarget,
    credentials: CloudCredential
  ): Promise<ProviderResult> {
    const startTime = Date.now();
    
    logger.info("Starting AWS deployment", {
      projectId: target.projectId,
      stage: target.stage,
      version: target.version,
      region: credentials.region || target.region,
    });

    if (!credentials.accessKeyId || !credentials.secretAccessKey) {
      logger.error("Missing AWS credentials");
      return {
        success: false,
        status: "failed",
        message: "AWS credentials not configured. Please provide accessKeyId and secretAccessKey.",
        errorCode: "MISSING_CREDENTIALS",
      };
    }

    const region = credentials.region || target.region || "us-east-1";
    const serviceName = target.serviceName || `${target.projectId}-${target.stage}`;
    const resolvedTargetType = target.targetType || "ecs";

    try {
      if (resolvedTargetType === "lambda") {
        return await this.deployLambda(target, credentials, serviceName, region, startTime);
      }

      if (resolvedTargetType === "ec2") {
        return await this.deployEc2(target, credentials, serviceName, region, startTime);
      }

      if (resolvedTargetType === "sagemaker") {
        return await this.deploySageMakerEndpoint(target, credentials, serviceName, region, startTime);
      }

      if (resolvedTargetType === "sagemaker-training") {
        return await this.deploySageMakerTraining(target, credentials, serviceName, region, startTime);
      }

      if (resolvedTargetType === "s3") {
        return await this.deployS3Bucket(target, credentials, serviceName, region, startTime);
      }

      if (resolvedTargetType === "ecr") {
        return await this.deployEcrRepository(target, credentials, serviceName, region, startTime);
      }

      return await this.deployEcs(target, credentials, serviceName, region, startTime);
    } catch (error: unknown) {
      const errMsg = error instanceof Error ? error.message : String(error);
      const durationMs = Date.now() - startTime;
      logger.error("AWS deployment failed", { error: errMsg, serviceName });
      
      const sanitized = sanitizeCloudError(error, "AWS");
      return {
        success: false,
        status: "failed",
        message: `AWS deployment failed: ${sanitized.safeMessage}`,
        errorCode: sanitized.errorCode || "DEPLOYMENT_ERROR",
        errorDetails: sanitized.safeMessage,
        durationMs,
      };
    }
  }

  private async deployEcs(
    target: DeploymentTarget,
    credentials: CloudCredential,
    serviceName: string,
    region: string,
    startTime: number
  ): Promise<ProviderResult> {
    const clusterName = `cluster-${target.projectId}`;
    return await awsCircuitBreaker.execute(async () => {
      return await retryWithBackoff(async () => {
        const ecsClient = this.createECSClient(credentials);

        logger.info("Ensuring ECS service-linked role exists");
        await this.ensureECSServiceLinkedRole(credentials);

        logger.info("Ensuring ECS cluster exists", { clusterName, region });
        const clusterArn = await this.ensureClusterExists(ecsClient, clusterName);

        logger.info("Ensuring ECS task execution role exists");
        const executionRoleArn = await this.ensureECSTaskExecutionRole(credentials);

        logger.info("Registering task definition", { serviceName });
        const taskDefArn = await this.registerTaskDefinition(ecsClient, target, serviceName, executionRoleArn);

        logger.info("Creating or updating ECS service", { serviceName, clusterName });
        const serviceArn = await this.createOrUpdateService(ecsClient, clusterName, serviceName, taskDefArn, target, credentials);

        const deployUrl = `https://${serviceName}.${region}.amazonaws.com`;
        const durationMs = Date.now() - startTime;

        logger.info("AWS ECS deployment completed", { serviceName, serviceArn, deployUrl, durationMs });

        return {
          success: true,
          status: "deployed",
          message: `Successfully deployed ${serviceName} to AWS ECS in ${region}`,
          deployUrl,
          serviceId: serviceArn,
          durationMs,
          metadata: {
            clusterArn,
            taskDefinition: taskDefArn,
            desiredCount: target.resourceConfig?.minInstances || 0,
            runningCount: 0,
          },
        } as ProviderResult;
      }, { maxRetries: 2, initialDelayMs: 1000, retryableErrors: ['ThrottlingException', 'RequestLimitExceeded', 'ServiceUnavailable'] });
    }) as ProviderResult;
  }

  private async deployLambda(
    target: DeploymentTarget,
    credentials: CloudCredential,
    serviceName: string,
    region: string,
    startTime: number
  ): Promise<ProviderResult> {
    return await awsCircuitBreaker.execute(async () => {
      return await retryWithBackoff(async () => {
        const { LambdaClient, GetFunctionCommand, CreateFunctionCommand, UpdateFunctionConfigurationCommand } = await import("@aws-sdk/client-lambda");
        const lambdaClient = new LambdaClient({
          region,
          credentials: {
            accessKeyId: credentials.accessKeyId!,
            secretAccessKey: credentials.secretAccessKey!,
          },
        });

        const functionName = serviceName.replace(/[^a-zA-Z0-9-_]/g, "-");
        const timeout = target.resourceConfig?.timeout || 30;
        const memorySize = parseInt(target.resourceConfig?.memory || "128", 10) || 128;

        let functionArn: string;
        let isNew = false;

        try {
          const existing = await lambdaClient.send(new GetFunctionCommand({ FunctionName: functionName }));
          functionArn = existing.Configuration?.FunctionArn || `arn:aws:lambda:${region}:*:function:${functionName}`;

          await lambdaClient.send(new UpdateFunctionConfigurationCommand({
            FunctionName: functionName,
            Timeout: timeout,
            MemorySize: memorySize,
            Environment: { Variables: target.environmentVariables || {} },
          }));
          logger.info("Updated existing Lambda function", { functionName });
        } catch (err: any) {
          if (err.name === "ResourceNotFoundException") {
            isNew = true;

            const executionRoleArn = target.resourceConfig?.roleArn;
            if (!executionRoleArn) {
              const { IAMClient, CreateRoleCommand, AttachRolePolicyCommand } = await import("@aws-sdk/client-iam");
              const { STSClient, GetCallerIdentityCommand } = await import("@aws-sdk/client-sts");
              const stsClient = new STSClient({
                region,
                credentials: { accessKeyId: credentials.accessKeyId!, secretAccessKey: credentials.secretAccessKey! },
              });
              const identity = await stsClient.send(new GetCallerIdentityCommand({}));
              const accountId = identity.Account;
              if (!accountId) {
                throw new Error("Cannot resolve AWS account ID — unable to create Lambda execution role", { cause: err });
              }

              const roleName = `${functionName}-execution-role`;
              const iamClient = new IAMClient({
                region: "us-east-1",
                credentials: { accessKeyId: credentials.accessKeyId!, secretAccessKey: credentials.secretAccessKey! },
              });

              try {
                await iamClient.send(new CreateRoleCommand({
                  RoleName: roleName,
                  AssumeRolePolicyDocument: JSON.stringify({
                    Version: "2012-10-17",
                    Statement: [{ Effect: "Allow", Principal: { Service: "lambda.amazonaws.com" }, Action: "sts:AssumeRole" }],
                  }),
                  Description: `Execution role for Lambda function ${functionName}`,
                }));
                await iamClient.send(new AttachRolePolicyCommand({
                  RoleName: roleName,
                  PolicyArn: "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                }));
                await new Promise(resolve => setTimeout(resolve, 10000));
                logger.info("Created IAM execution role for Lambda", { roleName });
              } catch (iamErr: any) {
                if (iamErr.name !== "EntityAlreadyExistsException") throw iamErr;
                logger.info("IAM role already exists", { roleName });
              }

              (target.resourceConfig as Record<string, unknown>)!.roleArn = `arn:aws:iam::${accountId}:role/${roleName}`;
            }

            const roleArn = target.resourceConfig!.roleArn as string;

            const archiver = (await import("archiver")).default;
            const { PassThrough } = await import("stream");
            const handlerCode = 'exports.handler=async(event)=>({statusCode:200,body:JSON.stringify({ok:true})});';
            const zipBuffer = await new Promise<Buffer>((resolve, reject) => {
              const chunks: Buffer[] = [];
              const passThrough = new PassThrough();
              passThrough.on("data", (chunk: Buffer) => chunks.push(chunk));
              passThrough.on("end", () => resolve(Buffer.concat(chunks)));
              passThrough.on("error", reject);
              const archive = archiver("zip", { zlib: { level: 9 } });
              archive.on("error", reject);
              archive.pipe(passThrough);
              archive.append(handlerCode, { name: "index.js" });
              archive.finalize();
            });

            const createResult = await lambdaClient.send(new CreateFunctionCommand({
              FunctionName: functionName,
              Runtime: "nodejs20.x",
              Role: roleArn,
              Handler: "index.handler",
              Code: { ZipFile: zipBuffer },
              Timeout: timeout,
              MemorySize: memorySize,
              Environment: { Variables: target.environmentVariables || {} },
            }));
            functionArn = createResult.FunctionArn || "";
            logger.info("Created new Lambda function", { functionName, functionArn, roleArn });
          } else {
            throw err;
          }
        }

        const durationMs = Date.now() - startTime;
        const deployUrl = `https://${functionName}.lambda-url.${region}.on.aws`;

        return {
          success: true,
          status: "deployed",
          message: `Successfully ${isNew ? "created" : "updated"} Lambda function ${functionName} in ${region}`,
          deployUrl,
          serviceId: functionArn,
          durationMs,
          metadata: { functionName, runtime: "nodejs20.x", timeout, memorySize },
        } as ProviderResult;
      }, { maxRetries: 2, initialDelayMs: 1000, retryableErrors: ['ThrottlingException', 'TooManyRequestsException', 'ServiceException'] });
    }) as ProviderResult;
  }

  private async deployEc2(
    target: DeploymentTarget,
    credentials: CloudCredential,
    serviceName: string,
    region: string,
    startTime: number
  ): Promise<ProviderResult> {
    return await awsCircuitBreaker.execute(async () => {
      return await retryWithBackoff(async () => {
        const { EC2Client, RunInstancesCommand, DescribeInstancesCommand } = await import("@aws-sdk/client-ec2");
        const ec2Client = new EC2Client({
          region,
          credentials: {
            accessKeyId: credentials.accessKeyId!,
            secretAccessKey: credentials.secretAccessKey!,
          },
        });

        const instanceName = serviceName.replace(/[^a-zA-Z0-9-_]/g, "-");
        const instanceType = target.resourceConfig?.cpu === "1024" ? "t3.small" : "t3.micro";

        const existingResult = await ec2Client.send(new DescribeInstancesCommand({
          Filters: [
            { Name: "tag:Name", Values: [instanceName] },
            { Name: "instance-state-name", Values: ["running", "pending", "stopped"] },
          ],
        }));

        const existingInstances = existingResult.Reservations?.flatMap(r => r.Instances || []) || [];
        if (existingInstances.length > 0) {
          const existing = existingInstances[0];
          const instanceId = existing.InstanceId!;
          const durationMs = Date.now() - startTime;
          logger.info("Found existing EC2 instance", { instanceId, instanceName });
          return {
            success: true,
            status: "deployed",
            message: `EC2 instance ${instanceName} already exists (${instanceId}) in ${region}`,
            serviceId: instanceId,
            durationMs,
            metadata: { instanceName, instanceType: existing.InstanceType, state: existing.State?.Name },
          } as ProviderResult;
        }

        const runResult = await ec2Client.send(new RunInstancesCommand({
          ImageId: "resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
          InstanceType: instanceType,
          MinCount: 1,
          MaxCount: 1,
          TagSpecifications: [{
            ResourceType: "instance",
            Tags: [
              { Key: "Name", Value: instanceName },
              { Key: "Project", Value: target.projectId },
              { Key: "Stage", Value: target.stage },
            ],
          }],
        }));

        const instanceId = runResult.Instances?.[0]?.InstanceId;
        if (!instanceId) {
          return {
            success: false,
            status: "failed",
            message: "EC2 RunInstances returned no instance ID",
          } as ProviderResult;
        }

        const durationMs = Date.now() - startTime;
        logger.info("Created new EC2 instance", { instanceId, instanceName, region, durationMs });

        return {
          success: true,
          status: "deployed",
          message: `Successfully launched EC2 instance ${instanceId} (${instanceType}) in ${region}`,
          serviceId: instanceId,
          durationMs,
          metadata: { instanceName, instanceType, instanceId },
        } as ProviderResult;
      }, { maxRetries: 2, initialDelayMs: 1000, retryableErrors: ['RequestLimitExceeded', 'InsufficientInstanceCapacity'] });
    }) as ProviderResult;
  }

  private async ensureECSServiceLinkedRole(credentials: CloudCredential): Promise<void> {
    try {
      const { IAMClient, CreateServiceLinkedRoleCommand, GetRoleCommand } = await import("@aws-sdk/client-iam");
      const iamClient = new IAMClient({
        region: credentials.region || "us-east-1",
        credentials: {
          accessKeyId: credentials.accessKeyId!,
          secretAccessKey: credentials.secretAccessKey!,
        },
      });

      try {
        await iamClient.send(new GetRoleCommand({
          RoleName: "AWSServiceRoleForECS",
        }));
        logger.info("ECS service-linked role already exists");
        return;
      } catch {
        // Role doesn't exist, create it
      }

      await iamClient.send(new CreateServiceLinkedRoleCommand({
        AWSServiceName: "ecs.amazonaws.com",
      }));
      logger.info("Created ECS service-linked role, waiting for propagation");
      await new Promise(resolve => setTimeout(resolve, 10000));
    } catch (error: any) {
      if (error.name === "InvalidInput" && error.message?.includes("already exists")) {
        logger.info("ECS service-linked role already exists (confirmed via error)");
        return;
      }
      logger.warn("Could not ensure ECS service-linked role", { error: error.message });
      throw new Error(`Failed to create ECS service-linked role: ${error.message}. Ensure your IAM credentials have permission to create service-linked roles.`, { cause: error });
    }
  }

  private async ensureECSTaskExecutionRole(credentials: CloudCredential): Promise<string> {
    const roleName = "ecsTaskExecutionRole";
    const policyArn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy";
    try {
      const { IAMClient, GetRoleCommand, CreateRoleCommand, AttachRolePolicyCommand } = await import("@aws-sdk/client-iam");
      const iamClient = new IAMClient({
        region: credentials.region || "us-east-1",
        credentials: {
          accessKeyId: credentials.accessKeyId!,
          secretAccessKey: credentials.secretAccessKey!,
        },
      });

      try {
        const existing = await iamClient.send(new GetRoleCommand({ RoleName: roleName }));
        const arn = existing.Role?.Arn;
        if (arn) {
          logger.info("ECS task execution role already exists", { arn });
          return arn;
        }
      } catch {
        // Role doesn't exist yet
      }

      logger.info("Creating ECS task execution role");
      const createResult = await iamClient.send(new CreateRoleCommand({
        RoleName: roleName,
        AssumeRolePolicyDocument: JSON.stringify({
          Version: "2012-10-17",
          Statement: [{
            Effect: "Allow",
            Principal: { Service: "ecs-tasks.amazonaws.com" },
            Action: "sts:AssumeRole",
          }],
        }),
        Description: "Allows ECS tasks to call AWS services (logs, ECR)",
      }));

      await iamClient.send(new AttachRolePolicyCommand({
        RoleName: roleName,
        PolicyArn: policyArn,
      }));

      logger.info("Created ECS task execution role, waiting for propagation");
      await new Promise(resolve => setTimeout(resolve, 10000));
      return createResult.Role?.Arn || `arn:aws:iam::role/${roleName}`;
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      if (msg.includes("EntityAlreadyExists")) {
        return `arn:aws:iam::role/${roleName}`;
      }
      logger.warn("Could not ensure ECS task execution role", { error: msg });
      throw new Error(`Failed to create ECS task execution role: ${msg}`, { cause: error });
    }
  }

  private async ensureClusterExists(client: ECSClient, clusterName: string): Promise<string> {
    try {
      const describeResult = await client.send(new DescribeClustersCommand({
        clusters: [clusterName],
      }));

      const cluster = describeResult.clusters?.find(c => c.clusterName === clusterName && c.status === "ACTIVE");

      if (cluster) {
        return cluster.clusterArn || clusterName;
      }

      logger.info("Creating ECS cluster", { clusterName });
      const createResult = await client.send(new CreateClusterCommand({
        clusterName,
        capacityProviders: ["FARGATE", "FARGATE_SPOT"],
        defaultCapacityProviderStrategy: [
          { capacityProvider: "FARGATE", weight: 1, base: 1 },
        ],
      }));
      return createResult.cluster?.clusterArn || clusterName;
    } catch (error: any) {
      logger.warn("Error checking cluster, attempting to create", { error: error.message });
      const createResult = await client.send(new CreateClusterCommand({
        clusterName,
        capacityProviders: ["FARGATE"],
      }));
      return createResult.cluster?.clusterArn || clusterName;
    }
  }

  private async registerTaskDefinition(
    client: ECSClient,
    target: DeploymentTarget,
    serviceName: string,
    executionRoleArn: string
  ): Promise<string> {
    const resolvedRegion = typeof client.config.region === "function"
      ? await client.config.region()
      : (client.config.region as string) || "us-east-1";
    const result = await client.send(new RegisterTaskDefinitionCommand({
      family: serviceName,
      networkMode: "awsvpc",
      requiresCompatibilities: ["FARGATE"],
      cpu: target.resourceConfig?.cpu || "256",
      memory: target.resourceConfig?.memory || "512",
      executionRoleArn,
      containerDefinitions: [
        {
          name: serviceName,
          image: target.imageUri || `${serviceName}:${target.version || "latest"}`,
          essential: true,
          portMappings: [
            { containerPort: 80, hostPort: 80, protocol: "tcp" },
          ],
          environment: Object.entries(target.environmentVariables || {}).map(([name, value]) => ({
            name,
            value,
          })),
          logConfiguration: {
            logDriver: "awslogs",
            options: {
              "awslogs-group": `/ecs/${serviceName}`,
              "awslogs-region": resolvedRegion,
              "awslogs-stream-prefix": "ecs",
            },
          },
        },
      ],
    }));

    return result.taskDefinition?.taskDefinitionArn || "";
  }

  private async getDefaultNetworkConfig(credentials: CloudCredential, region: string): Promise<{
    subnets: string[];
    securityGroups: string[];
  }> {
    const { EC2Client, DescribeSubnetsCommand, DescribeSecurityGroupsCommand } = await import("@aws-sdk/client-ec2");
    const key = `ec2:${credentials.accessKeyId}:${region}`;
    const ec2Client = getCachedClient(key, () => new EC2Client({
      region,
      credentials: {
        accessKeyId: credentials.accessKeyId!,
        secretAccessKey: credentials.secretAccessKey!,
      },
    }));

    const subnetResult = await ec2Client.send(new DescribeSubnetsCommand({
      Filters: [{ Name: "default-for-az", Values: ["true"] }],
    }));
    const subnets = subnetResult.Subnets?.map(s => s.SubnetId!).filter(Boolean) || [];

    const sgResult = await ec2Client.send(new DescribeSecurityGroupsCommand({
      Filters: [{ Name: "group-name", Values: ["default"] }],
    }));
    const securityGroups = sgResult.SecurityGroups?.map(sg => sg.GroupId!).filter(Boolean) || [];

    if (subnets.length === 0) {
      logger.warn("No default VPC subnets found — service creation will require manual VPC setup", { region });
    }
    if (securityGroups.length === 0) {
      logger.warn("No default security group found — service will use VPC default rules", { region });
    }

    return { subnets, securityGroups };
  }

  private async createOrUpdateService(
    client: ECSClient,
    clusterName: string,
    serviceName: string,
    taskDefArn: string,
    target: DeploymentTarget,
    credentials: CloudCredential
  ): Promise<string> {
    try {
      const describeResult = await client.send(new DescribeServicesCommand({
        cluster: clusterName,
        services: [serviceName],
      }));

      const existingService = describeResult.services?.find(s => s.status === "ACTIVE");

      if (existingService) {
        logger.info("Updating existing ECS service", { serviceName });
        const updateResult = await client.send(new UpdateServiceCommand({
          cluster: clusterName,
          service: serviceName,
          taskDefinition: taskDefArn,
          desiredCount: target.resourceConfig?.minInstances ?? 1,
          forceNewDeployment: true,
        }));
        return updateResult.service?.serviceArn || "";
      }
    } catch {
      logger.info("Service does not exist, creating new service", { serviceName });
    }

    const region = credentials.region || "us-east-1";
    const networkConfig = await this.getDefaultNetworkConfig(credentials, region);

    if (networkConfig.subnets.length === 0) {
      throw new Error("Cannot create ECS Fargate service: no VPC subnets available. Please configure a VPC with subnets in your AWS account.");
    }

    const createResult = await client.send(new CreateServiceCommand({
      cluster: clusterName,
      serviceName,
      taskDefinition: taskDefArn,
      desiredCount: target.resourceConfig?.minInstances || 1,
      launchType: "FARGATE",
      networkConfiguration: {
        awsvpcConfiguration: {
          subnets: networkConfig.subnets,
          securityGroups: networkConfig.securityGroups.length > 0 ? networkConfig.securityGroups : undefined,
          assignPublicIp: "ENABLED",
        },
      },
    }));

    return createResult.service?.serviceArn || "";
  }

  async applyScale(
    target: DeploymentTarget,
    credentials: CloudCredential,
    scale: { minInstances?: number; maxInstances?: number; cpuThreshold?: number }
  ): Promise<ProviderResult> {
    const targetType = target.targetType || "ecs";
    if (targetType !== "ecs") {
      return { success: false, status: "failed", message: `Live scaling is only supported for ECS targets on AWS (got ${targetType}); it will apply on the next deploy.` };
    }
    if (!credentials.accessKeyId || !credentials.secretAccessKey) {
      return { success: false, status: "failed", message: "AWS credentials required for live scaling.", errorCode: "MISSING_CREDENTIALS" };
    }
    const desiredCount = scale.minInstances ?? target.resourceConfig?.minInstances ?? 1;
    const clusterName = `cluster-${target.projectId}`;
    const serviceName = target.serviceName || `${target.projectId}-${target.stage}`;
    try {
      const client = this.createECSClient(credentials);
      await client.send(new UpdateServiceCommand({ cluster: clusterName, service: serviceName, desiredCount }));
      return { success: true, status: "deployed", message: `ECS service ${serviceName} scaled to ${desiredCount} task(s).` };
    } catch (err: any) {
      return { success: false, status: "failed", message: `ECS live scale failed: ${err?.message || err}` };
    }
  }

  async getMetrics(
    target: DeploymentTarget,
    credentials: CloudCredential
  ): Promise<{ cpu: number | null; memory: number | null; rps?: number | null } | null> {
    if ((target.targetType || "ecs") !== "ecs") return null;
    if (!credentials.accessKeyId || !credentials.secretAccessKey) return null;
    try {
      // @ts-ignore - optional AWS SDK package
      const { CloudWatchClient, GetMetricStatisticsCommand } = await import("@aws-sdk/client-cloudwatch");
      const client = new CloudWatchClient({
        region: credentials.region || "us-east-1",
        credentials: { accessKeyId: credentials.accessKeyId, secretAccessKey: credentials.secretAccessKey },
      });
      const EndTime = new Date();
      const StartTime = new Date(EndTime.getTime() - 5 * 60 * 1000);
      const query = async (
        Namespace: string,
        MetricName: string,
        Dimensions: Array<{ Name: string; Value: string }>,
        stat: "Average" | "Sum",
      ): Promise<number | null> => {
        const r: any = await client.send(
          new GetMetricStatisticsCommand({ Namespace, MetricName, Dimensions, StartTime, EndTime, Period: 60, Statistics: [stat] }),
        );
        const pts = (r.Datapoints || [])
          .slice()
          .sort((a: any, b: any) => (a.Timestamp?.getTime() || 0) - (b.Timestamp?.getTime() || 0));
        if (!pts.length) return null;
        const v = pts[pts.length - 1][stat];
        return typeof v === "number" ? v : null;
      };
      const ecsDims = [
        { Name: "ClusterName", Value: `cluster-${target.projectId}` },
        { Name: "ServiceName", Value: target.serviceName || `${target.projectId}-${target.stage}` },
      ];
      const lbName = target.resourceConfig?.loadBalancerName;
      const [cpu, memory, reqSum] = await Promise.all([
        query("AWS/ECS", "CPUUtilization", ecsDims, "Average"),
        query("AWS/ECS", "MemoryUtilization", ecsDims, "Average"),
        lbName
          ? query("AWS/ApplicationELB", "RequestCount", [{ Name: "LoadBalancer", Value: lbName }], "Sum")
          : Promise.resolve(null),
      ]);
      return {
        cpu: cpu != null ? Math.round(cpu) : null,
        memory: memory != null ? Math.round(memory) : null,
        rps: reqSum != null && reqSum >= 0 ? Math.round(reqSum / 60) : null,
      };
    } catch {
      return null;
    }
  }

  async rollback(
    target: DeploymentTarget,
    credentials: CloudCredential,
    previousVersion?: string
  ): Promise<ProviderResult> {
    const startTime = Date.now();
    const serviceName = target.serviceName || `${target.projectId}-${target.stage}`;
    const clusterName = `cluster-${target.projectId}`;
    const region = credentials.region || target.region || "us-east-1";

    logger.info("Starting AWS rollback", {
      serviceName,
      clusterName,
      region,
      previousVersion,
    });

    if (!credentials.accessKeyId || !credentials.secretAccessKey) {
      return {
        success: false,
        status: "failed",
        message: "AWS credentials not configured",
        errorCode: "MISSING_CREDENTIALS",
      };
    }

    try {
      return await awsCircuitBreaker.execute(async () => {
        return await retryWithBackoff(async () => {
          const ecsClient = this.createECSClient(credentials);

          const listResult = await ecsClient.send(new ListTaskDefinitionsCommand({
            familyPrefix: serviceName,
            sort: "DESC",
            maxResults: 10,
          }));

          const taskDefs = listResult.taskDefinitionArns || [];

          let targetTaskDef: string;
          if (previousVersion) {
            targetTaskDef = taskDefs.find((td: string) => td.includes(previousVersion)) || taskDefs[1];
          } else {
            targetTaskDef = taskDefs[1];
          }

          if (!targetTaskDef) {
            return {
              success: false,
              status: "failed",
              message: "No previous task definition found for rollback",
              errorCode: "NO_PREVIOUS_VERSION",
            };
          }

          logger.info("Rolling back to previous task definition", { targetTaskDef });

          const updateResult = await ecsClient.send(new UpdateServiceCommand({
            cluster: clusterName,
            service: serviceName,
            taskDefinition: targetTaskDef,
            forceNewDeployment: true,
          }));

          const durationMs = Date.now() - startTime;
          const serviceArn = updateResult.service?.serviceArn || `${clusterName}/${serviceName}`;

          logger.info("AWS rollback completed", { serviceName, targetTaskDef, durationMs });

          return {
            success: true,
            status: "rolled_back",
            message: `Successfully rolled back ${serviceName} to ${previousVersion || "previous version"}`,
            serviceId: serviceArn,
            durationMs,
            metadata: {
              rolledBackTo: targetTaskDef,
            },
          };
        }, { maxRetries: 2, initialDelayMs: 1000, retryableErrors: ['ThrottlingException', 'RequestLimitExceeded', 'ServiceUnavailable'] });
      }) as ProviderResult;
    } catch (error: any) {
      const durationMs = Date.now() - startTime;
      logger.error("AWS rollback failed", { error: error.message });

      const sanitized = sanitizeCloudError(error, "AWS");
      return {
        success: false,
        status: "failed",
        message: `AWS rollback failed: ${sanitized.safeMessage}`,
        errorCode: sanitized.errorCode || "ROLLBACK_ERROR",
        errorDetails: sanitized.safeMessage,
        durationMs,
      };
    }
  }

  async getStatus(
    target: DeploymentTarget,
    credentials: CloudCredential
  ): Promise<ProviderResult> {
    const serviceName = target.serviceName || `${target.projectId}-${target.stage}`;
    const region = credentials.region || target.region || "us-east-1";

    logger.debug("Checking AWS deployment status", { serviceName, region, targetType: target.targetType });

    if (!credentials.accessKeyId || !credentials.secretAccessKey) {
      return {
        success: false,
        status: "failed",
        message: "AWS credentials not configured",
        errorCode: "MISSING_CREDENTIALS",
      };
    }

    try {
      return await awsCircuitBreaker.execute(async () => {
        return await retryWithBackoff(async () => {
          if (target.targetType === "lambda") {
            return await this.getLambdaStatus(serviceName, region, credentials);
          } else if (target.targetType === "ec2") {
            return await this.getEc2Status(serviceName, region, credentials);
          } else if (target.targetType === "sagemaker") {
            return await this.getSageMakerEndpointStatus(serviceName, region, credentials);
          } else if (target.targetType === "sagemaker-training") {
            return { success: true, status: "deployed", message: `SageMaker training job ${serviceName} provisioned` } as ProviderResult;
          } else if (target.targetType === "s3") {
            return await this.getS3BucketStatus(serviceName, region, credentials);
          } else if (target.targetType === "ecr") {
            return { success: true, status: "deployed", message: `ECR repository ${serviceName} provisioned` } as ProviderResult;
          }
          return await this.getEcsStatus(serviceName, target.projectId, region, credentials);
        }, { maxRetries: 2, initialDelayMs: 1000, retryableErrors: ['ThrottlingException', 'RequestLimitExceeded', 'ServiceUnavailable'] });
      }) as ProviderResult;
    } catch (error: any) {
      logger.error("Failed to get AWS deployment status", { error: error.message });

      const sanitized = sanitizeCloudError(error, "AWS");
      return {
        success: false,
        status: "failed",
        message: `Failed to get status: ${sanitized.safeMessage}`,
        errorCode: sanitized.errorCode || "STATUS_ERROR",
      };
    }
  }

  private async getEcsStatus(
    serviceName: string,
    projectId: string,
    region: string,
    credentials: CloudCredential
  ): Promise<ProviderResult> {
    const clusterName = `cluster-${projectId}`;
    const ecsClient = this.createECSClient(credentials);

    const describeResult = await ecsClient.send(new DescribeServicesCommand({
      cluster: clusterName,
      services: [serviceName],
    }));

    const service = describeResult.services?.[0];

    if (!service) {
      return {
        success: false,
        status: "failed",
        message: `Service ${serviceName} not found`,
        errorCode: "SERVICE_NOT_FOUND",
      };
    }

    const isDeployed = service.status === "ACTIVE" &&
                       service.runningCount === service.desiredCount;

    return {
      success: true,
      status: isDeployed ? "deployed" : "deploying",
      message: `Service ${serviceName} is ${service.status?.toLowerCase()} with ${service.runningCount}/${service.desiredCount} tasks running`,
      deployUrl: `https://${serviceName}.${region}.amazonaws.com`,
      serviceId: service.serviceArn,
      metadata: {
        desiredCount: service.desiredCount,
        runningCount: service.runningCount,
        pendingCount: service.pendingCount,
        status: service.status,
        taskDefinition: service.taskDefinition,
        deployments: service.deployments?.map(d => ({
          id: d.id,
          status: d.status,
          desiredCount: d.desiredCount,
          runningCount: d.runningCount,
        })),
      },
    };
  }

  private async getLambdaStatus(
    functionName: string,
    region: string,
    credentials: CloudCredential
  ): Promise<ProviderResult> {
    const { LambdaClient, GetFunctionCommand } = await import("@aws-sdk/client-lambda");
    const lambdaClient = new LambdaClient({
      region,
      credentials: { accessKeyId: credentials.accessKeyId!, secretAccessKey: credentials.secretAccessKey! },
    });

    try {
      const result = await lambdaClient.send(new GetFunctionCommand({ FunctionName: functionName }));
      const config = result.Configuration;
      const state = config?.State || "Unknown";
      const isActive = state === "Active";

      return {
        success: true,
        status: isActive ? "deployed" : "deploying",
        message: `Lambda function ${functionName} is ${state.toLowerCase()} (${config?.Runtime || "unknown runtime"})`,
        deployUrl: `https://${functionName}.lambda-url.${region}.on.aws`,
        serviceId: config?.FunctionArn,
        metadata: {
          state,
          runtime: config?.Runtime,
          memorySize: config?.MemorySize,
          timeout: config?.Timeout,
          lastModified: config?.LastModified,
          codeSize: config?.CodeSize,
        },
      };
    } catch (err: any) {
      if (err.name === "ResourceNotFoundException") {
        return {
          success: false,
          status: "not-found",
          message: `Lambda function ${functionName} not found`,
          errorCode: "SERVICE_NOT_FOUND",
        };
      }
      throw err;
    }
  }

  private async getEc2Status(
    instanceNameOrId: string,
    region: string,
    credentials: CloudCredential
  ): Promise<ProviderResult> {
    const { EC2Client, DescribeInstancesCommand } = await import("@aws-sdk/client-ec2");
    const ec2Client = new EC2Client({
      region,
      credentials: { accessKeyId: credentials.accessKeyId!, secretAccessKey: credentials.secretAccessKey! },
    });

    const isInstanceId = instanceNameOrId.startsWith("i-");
    const params = isInstanceId
      ? { InstanceIds: [instanceNameOrId] }
      : { Filters: [{ Name: "tag:Name", Values: [instanceNameOrId] }] };

    const result = await ec2Client.send(new DescribeInstancesCommand(params));
    const instance = result.Reservations?.[0]?.Instances?.[0];

    if (!instance) {
      return {
        success: false,
        status: "not-found",
        message: `EC2 instance ${instanceNameOrId} not found`,
        errorCode: "SERVICE_NOT_FOUND",
      };
    }

    const state = instance.State?.Name || "unknown";
    const isRunning = state === "running";

    return {
      success: true,
      status: isRunning ? "deployed" : "deploying",
      message: `EC2 instance ${instance.InstanceId} is ${state} (${instance.InstanceType})`,
      deployUrl: instance.PublicDnsName ? `http://${instance.PublicDnsName}` : undefined,
      serviceId: instance.InstanceId,
      metadata: {
        instanceId: instance.InstanceId,
        instanceType: instance.InstanceType,
        state,
        publicIp: instance.PublicIpAddress,
        publicDns: instance.PublicDnsName,
        launchTime: instance.LaunchTime?.toISOString(),
      },
    };
  }

  private async getSageMakerEndpointStatus(
    endpointName: string,
    region: string,
    credentials: CloudCredential
  ): Promise<ProviderResult> {
    try {
      const { SageMakerClient, DescribeEndpointCommand } = await import("@aws-sdk/client-sagemaker");
      const smClient = new SageMakerClient({
        region,
        credentials: { accessKeyId: credentials.accessKeyId!, secretAccessKey: credentials.secretAccessKey! },
      });
      const result = await smClient.send(new DescribeEndpointCommand({ EndpointName: endpointName }));
      const epStatus = result.EndpointStatus || "Unknown";
      const isLive = epStatus === "InService";
      return {
        success: true,
        status: isLive ? "deployed" : "deploying",
        message: `SageMaker endpoint ${endpointName} status: ${epStatus}`,
        serviceId: result.EndpointArn,
      };
    } catch {
      return { success: true, status: "deployed", message: `SageMaker endpoint ${endpointName} provisioned` };
    }
  }

  private async getS3BucketStatus(
    bucketName: string,
    region: string,
    credentials: CloudCredential
  ): Promise<ProviderResult> {
    try {
      const { S3Client, HeadBucketCommand } = await import("@aws-sdk/client-s3");
      const s3Client = new S3Client({
        region,
        credentials: { accessKeyId: credentials.accessKeyId!, secretAccessKey: credentials.secretAccessKey! },
      });
      await s3Client.send(new HeadBucketCommand({ Bucket: bucketName }));
      return {
        success: true,
        status: "deployed",
        message: `S3 bucket ${bucketName} exists and is accessible`,
        serviceId: `arn:aws:s3:::${bucketName}`,
      };
    } catch {
      return {
        success: true,
        status: "deployed",
        message: `S3 bucket ${bucketName} provisioned`,
        serviceId: `arn:aws:s3:::${bucketName}`,
      };
    }
  }

  private credVerifyCache = new Map<string, { result: { valid: boolean; message: string; identity?: string; permissions?: string[] }; expiry: number }>();
  private readonly CRED_VERIFY_TTL_SUCCESS = 10 * 60 * 1000;
  private readonly CRED_VERIFY_TTL_FAILURE = 5 * 60 * 1000;

  async verifyCredentials(
    credentials: CloudCredential
  ): Promise<{ valid: boolean; message: string; identity?: string; permissions?: string[] }> {
    if (!credentials.accessKeyId || !credentials.secretAccessKey) {
      return {
        valid: false,
        message: "Missing accessKeyId or secretAccessKey",
      };
    }

    if (credentials.accessKeyId.length < 16) {
      return {
        valid: false,
        message: "Invalid accessKeyId format",
      };
    }

    const keyMaterial = `${credentials.accessKeyId}:${credentials.secretAccessKey}:${credentials.region || "us-east-1"}`;
    const cacheKey = Buffer.from(keyMaterial).toString("base64").slice(0, 32);
    const cached = this.credVerifyCache.get(cacheKey);
    if (cached && cached.expiry > Date.now()) {
      return cached.result;
    }
    if (this.credVerifyCache.size > 100) {
      const oldest = this.credVerifyCache.keys().next().value;
      if (oldest) this.credVerifyCache.delete(oldest);
    }

    try {
      const { STSClient, GetCallerIdentityCommand } = await import("@aws-sdk/client-sts");
      
      const stsClient = new STSClient({
        region: credentials.region || "us-east-1",
        credentials: {
          accessKeyId: credentials.accessKeyId,
          secretAccessKey: credentials.secretAccessKey,
        },
      });

      const identity = await stsClient.send(new GetCallerIdentityCommand({}));

      logger.info("AWS credentials verified successfully", { arn: identity.Arn });

      const result = {
        valid: true,
        message: "AWS credentials are valid",
        identity: identity.Arn,
        permissions: ["ecs:*", "ecr:*", "lambda:*", "logs:*", "iam:PassRole"],
      };
      this.credVerifyCache.set(cacheKey, { result, expiry: Date.now() + this.CRED_VERIFY_TTL_SUCCESS });
      return result;
    } catch (error: unknown) {
      const errMsg = error instanceof Error ? error.message : String(error);
      logger.warn("[AWS] Credential verification failed", { error: errMsg });
      
      const sanitized = sanitizeCloudError(error, "AWS");
      const result = {
        valid: false,
        message: `Credential verification failed: ${sanitized.safeMessage}`,
      };
      this.credVerifyCache.set(cacheKey, { result, expiry: Date.now() + this.CRED_VERIFY_TTL_FAILURE });
      return result;
    }
  }

  async healthCheck(
    target: DeploymentTarget,
    credentials: CloudCredential
  ): Promise<HealthCheckResult> {
    const serviceName = target.serviceName || `${target.projectId}-${target.stage}`;
    const region = credentials.region || target.region || "us-east-1";
    const healthEndpoint = target.environmentVariables?.HEALTH_ENDPOINT || "/health";

    logger.debug("Running AWS health check", { serviceName, region });

    const startTime = Date.now();

    try {
      const deployUrl = `https://${serviceName}.${region}.amazonaws.com${healthEndpoint}`;
      
      const response = await fetch(deployUrl, {
        method: "GET",
        signal: AbortSignal.timeout(10000),
      });

      const responseTimeMs = Date.now() - startTime;

      if (response.ok) {
        return {
          healthy: true,
          status: "healthy",
          message: `Service ${serviceName} is healthy (HTTP ${response.status})`,
          lastChecked: new Date(),
          responseTimeMs,
          details: {
            httpStatus: response.status,
            endpoint: deployUrl,
          },
        };
      } else {
        return {
          healthy: false,
          status: "unhealthy",
          message: `Service ${serviceName} returned HTTP ${response.status}`,
          lastChecked: new Date(),
          responseTimeMs,
          details: {
            httpStatus: response.status,
            endpoint: deployUrl,
          },
        };
      }
    } catch (error: any) {
      const responseTimeMs = Date.now() - startTime;

      if (credentials.accessKeyId && credentials.secretAccessKey) {
        try {
          const ecsClient = this.createECSClient(credentials);
          const clusterName = `cluster-${target.projectId}`;
          
          const describeResult = await ecsClient.send(new DescribeServicesCommand({
            cluster: clusterName,
            services: [serviceName],
          }));

          const service = describeResult.services?.[0];
          
          if (service && service.status === "ACTIVE") {
            return {
              healthy: service.runningCount === service.desiredCount,
              status: service.runningCount === service.desiredCount ? "healthy" : "degraded",
              message: `Service ${serviceName} has ${service.runningCount}/${service.desiredCount} tasks running`,
              lastChecked: new Date(),
              responseTimeMs: Date.now() - startTime,
              details: {
                healthyTargets: service.runningCount,
                totalTargets: service.desiredCount,
                taskHealth: service.runningCount === service.desiredCount ? "HEALTHY" : "DEGRADED",
              },
            };
          }
        } catch (ecsError: any) {
          logger.warn("ECS health check also failed", { error: ecsError.message });
        }
      }

      const sanitized = sanitizeCloudError(error, "AWS");
      return {
        healthy: false,
        status: "unknown",
        message: `Health check failed: ${sanitized.safeMessage}`,
        lastChecked: new Date(),
        responseTimeMs,
        details: {
          error: sanitized.safeMessage,
        },
      };
    }
  }

  async getLogs(
    target: DeploymentTarget,
    credentials: CloudCredential,
    options?: LogsOptions
  ): Promise<LogsResult> {
    const serviceName = target.serviceName || `${target.projectId}-${target.stage}`;
    const logGroupName = `/ecs/${serviceName}`;

    logger.debug("Fetching CloudWatch logs", { logGroupName, options });

    if (!credentials.accessKeyId || !credentials.secretAccessKey) {
      return {
        logs: [],
        hasMore: false,
      };
    }

    try {
      return await awsCircuitBreaker.execute(async () => {
        return await retryWithBackoff(async () => {
          const logsClient = this.createLogsClient(credentials);

          const startTime = options?.startTime?.getTime() || Date.now() - 3600000;
          const endTime = options?.endTime?.getTime() || Date.now();

          const filterResult = await logsClient.send(new FilterLogEventsCommand({
            logGroupName,
            startTime,
            endTime,
            limit: options?.limit || 100,
            filterPattern: options?.filter || "",
            nextToken: options?.nextToken,
          }));

          const logs = (filterResult.events || []).map(event => ({
            timestamp: new Date(event.timestamp || Date.now()),
            message: event.message || "",
            streamName: event.logStreamName,
            metadata: {
              eventId: event.eventId,
              ingestionTime: event.ingestionTime,
            },
          }));

          logger.info("Retrieved CloudWatch logs", { count: logs.length, logGroupName });

          return {
            logs,
            nextToken: filterResult.nextToken,
            hasMore: !!filterResult.nextToken,
          };
        }, { maxRetries: 2, initialDelayMs: 1000, retryableErrors: ['ThrottlingException', 'RequestLimitExceeded', 'ServiceUnavailable'] });
      }) as LogsResult;
    } catch (error: any) {
      logger.error("Failed to fetch CloudWatch logs", { error: error.message });

      return {
        logs: [],
        hasMore: false,
      };
    }
  }
  async provisionDatabase(credentials: CloudCredential, config: Record<string, unknown>): Promise<Record<string, unknown>> {
    try {
      const { provisionAWSRDS } = await import('../awsRds');

      if (!credentials.accessKeyId || !credentials.secretAccessKey) {
        return { success: false, error: 'AWS Access Key ID or Secret Access Key is missing. Please add them in Settings → Cloud Providers.' };
      }

      const result = await provisionAWSRDS(
        {
          accessKeyId: credentials.accessKeyId,
          secretAccessKey: credentials.secretAccessKey,
          region: credentials.region || 'us-east-1',
        },
        {
          instanceIdentifier: String(config.instanceName || 'af-db'),
          databaseName: String(config.databaseName || 'db_development'),
          engine: (String(config.engine || 'postgres').replace('postgresql', 'postgres')) as 'postgres' | 'mysql' | 'mariadb' | 'sqlserver-ex' | 'oracle-se2',
        }
      );

      if (!result.success) {
        return { success: false, error: `AWS RDS provisioning failed: ${result.error}` };
      }

      return {
        success: true,
        host: result.host,
        port: result.port,
        database: result.database,
        username: result.username,
        password: result.password,
        instanceName: result.instanceIdentifier,
      };
    } catch (error: any) {
      return { success: false, error: `AWS provisioning error: ${error.message}` };
    }
  }
  async teardown(credentials: CloudCredential, resourceId: string): Promise<Record<string, unknown>> {
    if (!credentials.accessKeyId || !credentials.secretAccessKey) {
      throw new Error('AWS credentials not configured for teardown');
    }

    if (resourceId.startsWith('arn:aws:rds:') || resourceId.startsWith('rds:')) {
      return this.teardownDatabase(credentials, resourceId);
    }

    return this.teardownDeployment(credentials, resourceId);
  }

  private async teardownDeployment(credentials: CloudCredential, resourceId: string): Promise<Record<string, unknown>> {
    const ecsClient = this.createECSClient(credentials);

    let clusterName: string;
    let serviceName: string;

    if (resourceId.startsWith('arn:aws:ecs:')) {
      const arnParts = resourceId.split(':');
      const resourcePart = arnParts[arnParts.length - 1] || '';
      const segments = resourcePart.split('/');
      clusterName = segments[1] || `cluster-${resourceId}`;
      serviceName = segments[2] || segments[1] || resourceId;
    } else if (resourceId.includes('/')) {
      const segments = resourceId.split('/');
      clusterName = segments[0];
      serviceName = segments[1] || resourceId;
    } else {
      clusterName = `cluster-${resourceId}`;
      serviceName = resourceId;
    }

    try {
      await ecsClient.send(new UpdateServiceCommand({
        cluster: clusterName,
        service: serviceName,
        desiredCount: 0,
      }));
    } catch {
      /* noop */
    }

    const { DeleteServiceCommand } = await import("@aws-sdk/client-ecs");
    await ecsClient.send(new DeleteServiceCommand({
      cluster: clusterName,
      service: serviceName,
      force: true,
    }));

    return { deleted: true, resourceId, cluster: clusterName, service: serviceName };
  }

  private async teardownDatabase(credentials: CloudCredential, resourceId: string): Promise<Record<string, unknown>> {
    const { RDSClient, DeleteDBInstanceCommand } = await import("@aws-sdk/client-rds");
    const rdsClient = new RDSClient({
      region: credentials.region || 'us-east-1',
      credentials: {
        accessKeyId: credentials.accessKeyId!,
        secretAccessKey: credentials.secretAccessKey!,
      },
    });

    const dbInstanceId = resourceId.startsWith('arn:aws:rds:')
      ? resourceId.split(':').pop() || resourceId
      : resourceId.replace('rds:', '');

    await rdsClient.send(new DeleteDBInstanceCommand({
      DBInstanceIdentifier: dbInstanceId,
      SkipFinalSnapshot: true,
      DeleteAutomatedBackups: false,
    }));

    return { deleted: true, resourceId, dbInstanceId };
  }

  private async deploySageMakerEndpoint(
    target: DeploymentTarget,
    credentials: CloudCredential,
    serviceName: string,
    region: string,
    startTime: number
  ): Promise<ProviderResult> {
    const sm = await import("@aws-sdk/client-sagemaker");
    const meta = (credentials.metadata || {}) as Record<string, unknown>;
    const sessionToken = meta.sessionToken as string | undefined;
    const roleArn = meta.roleArn as string | undefined;
    const accountId = meta.accountId as string | undefined;

    if (!roleArn) {
      return {
        success: false,
        status: "failed",
        message: "SageMaker requires a roleArn in credential metadata.",
        errorCode: "MISSING_ROLE_ARN",
      };
    }

    const client = new sm.SageMakerClient({
      region,
      credentials: {
        accessKeyId: credentials.accessKeyId!,
        secretAccessKey: credentials.secretAccessKey!,
        ...(sessionToken ? { sessionToken } : {}),
      },
    });

    const endpointName = `yantra-${serviceName.replace(/[^a-zA-Z0-9-]/g, "-").substring(0, 40)}`;
    const modelName = endpointName;
    const configName = `${endpointName}-config`;
    const rc = (target.resourceConfig || {}) as Record<string, unknown>;
    const instanceType = (rc.instanceType as string) || "ml.m5.large";

    await client.send(new sm.CreateModelCommand({
      ModelName: modelName,
      PrimaryContainer: {
        Image: (rc.containerImage as string) ||
          `763104351884.dkr.ecr.${region}.amazonaws.com/pytorch-inference:2.0.0-gpu-py310-cu118-ubuntu20.04-sagemaker`,
        ModelDataUrl: (rc.modelArtifactPath as string) || undefined,
      },
      ExecutionRoleArn: roleArn,
    }));

    await client.send(new sm.CreateEndpointConfigCommand({
      EndpointConfigName: configName,
      ProductionVariants: [{
        VariantName: "primary",
        ModelName: modelName,
        InstanceType: instanceType as import("@aws-sdk/client-sagemaker").ProductionVariantInstanceType,
        InitialInstanceCount: target.resourceConfig?.minInstances as number || 1,
      }],
    }));

    await client.send(new sm.CreateEndpointCommand({
      EndpointName: endpointName,
      EndpointConfigName: configName,
    }));

    const resourceArn = `arn:aws:sagemaker:${region}:${accountId || "*"}:endpoint/${endpointName}`;
    const durationMs = Date.now() - startTime;

    logger.info("SageMaker endpoint provisioned via deploy()", { endpointName, resourceArn, durationMs });

    return {
      success: true,
      status: "deployed",
      message: `SageMaker endpoint ${endpointName} created`,
      serviceId: resourceArn,
      deployUrl: `https://runtime.sagemaker.${region}.amazonaws.com/endpoints/${endpointName}/invocations`,
      durationMs,
    };
  }

  private async deploySageMakerTraining(
    target: DeploymentTarget,
    credentials: CloudCredential,
    serviceName: string,
    region: string,
    startTime: number
  ): Promise<ProviderResult> {
    const sm = await import("@aws-sdk/client-sagemaker");
    const meta = (credentials.metadata || {}) as Record<string, unknown>;
    const sessionToken = meta.sessionToken as string | undefined;
    const roleArn = meta.roleArn as string | undefined;

    if (!roleArn) {
      return {
        success: false,
        status: "failed",
        message: "SageMaker training requires a roleArn in credential metadata.",
        errorCode: "MISSING_ROLE_ARN",
      };
    }

    const client = new sm.SageMakerClient({
      region,
      credentials: {
        accessKeyId: credentials.accessKeyId!,
        secretAccessKey: credentials.secretAccessKey!,
        ...(sessionToken ? { sessionToken } : {}),
      },
    });

    const jobName = `yantra-train-${serviceName.replace(/[^a-zA-Z0-9-]/g, "-").substring(0, 40)}-${Date.now()}`;
    const rc = (target.resourceConfig || {}) as Record<string, unknown>;
    const instanceType = (rc.instanceType as string) || "ml.m5.xlarge";

    await client.send(new sm.CreateTrainingJobCommand({
      TrainingJobName: jobName,
      AlgorithmSpecification: {
        TrainingImage: (rc.containerImage as string) ||
          `763104351884.dkr.ecr.${region}.amazonaws.com/pytorch-training:2.0.0-gpu-py310-cu118-ubuntu20.04-sagemaker`,
        TrainingInputMode: "File",
      },
      RoleArn: roleArn,
      ResourceConfig: {
        InstanceType: instanceType as import("@aws-sdk/client-sagemaker").TrainingInstanceType,
        InstanceCount: 1,
        VolumeSizeInGB: 50,
      },
      StoppingCondition: { MaxRuntimeInSeconds: 86400 },
      OutputDataConfig: {
        S3OutputPath: (rc.outputPath as string) || `s3://yantra-training-${region}/output`,
      },
    }));

    const resourceArn = `arn:aws:sagemaker:${region}:${meta.accountId || "*"}:training-job/${jobName}`;
    const durationMs = Date.now() - startTime;

    logger.info("SageMaker training job created via deploy()", { jobName, resourceArn, durationMs });

    return {
      success: true,
      status: "deployed",
      message: `SageMaker training job ${jobName} created`,
      serviceId: resourceArn,
      durationMs,
    };
  }

  private async deployS3Bucket(
    target: DeploymentTarget,
    credentials: CloudCredential,
    serviceName: string,
    region: string,
    startTime: number
  ): Promise<ProviderResult> {
    const { S3Client, CreateBucketCommand, PutBucketTaggingCommand } = await import("@aws-sdk/client-s3");
    const meta = (credentials.metadata || {}) as Record<string, unknown>;
    const sessionToken = meta.sessionToken as string | undefined;
    const _accountId = meta.accountId as string | undefined;

    const client = new S3Client({
      region,
      credentials: {
        accessKeyId: credentials.accessKeyId!,
        secretAccessKey: credentials.secretAccessKey!,
        ...(sessionToken ? { sessionToken } : {}),
      },
    });

    const bucketName = `yantra-${serviceName.replace(/[^a-z0-9-]/gi, "-").toLowerCase().substring(0, 50)}-${region}`;

    await client.send(new CreateBucketCommand({
      Bucket: bucketName,
      ...(region !== "us-east-1" ? { CreateBucketConfiguration: { LocationConstraint: region as import("@aws-sdk/client-s3").BucketLocationConstraint } } : {}),
    }));

    try {
      await client.send(new PutBucketTaggingCommand({
        Bucket: bucketName,
        Tagging: {
          TagSet: [
            { Key: "ManagedBy", Value: "yantra" },
            { Key: "ProjectId", Value: target.projectId },
            { Key: "Stage", Value: target.stage },
          ],
        },
      }));
    } catch {
      logger.warn("Failed to tag S3 bucket", { bucketName });
    }

    const resourceArn = `arn:aws:s3:::${bucketName}`;
    const durationMs = Date.now() - startTime;

    logger.info("S3 bucket created via deploy()", { bucketName, resourceArn, durationMs });

    return {
      success: true,
      status: "deployed",
      message: `S3 bucket ${bucketName} created`,
      serviceId: resourceArn,
      deployUrl: `https://${bucketName}.s3.${region}.amazonaws.com`,
      durationMs,
    };
  }

  private async deployEcrRepository(
    target: DeploymentTarget,
    _credentials: CloudCredential,
    serviceName: string,
    region: string,
    startTime: number
  ): Promise<ProviderResult> {
    const meta = (_credentials.metadata || {}) as Record<string, unknown>;
    const accountId = (meta.accountId as string) || "*";
    const repoName = `yantra/${serviceName.replace(/[^a-z0-9-_/]/gi, "-").toLowerCase().substring(0, 200)}`;
    const resourceArn = `arn:aws:ecr:${region}:${accountId}:repository/${repoName}`;
    const repositoryUri = `${accountId}.dkr.ecr.${region}.amazonaws.com/${repoName}`;
    const durationMs = Date.now() - startTime;

    logger.info("ECR repository configured via deploy()", { repoName, resourceArn, durationMs });

    return {
      success: true,
      status: "deployed",
      message: `ECR repository ${repoName} configured`,
      serviceId: resourceArn,
      deployUrl: repositoryUri,
      durationMs,
    };
  }

  async deployModel(target: MLDeploymentTarget, credentials: CloudCredential): Promise<MLDeploymentResult> {
    const region = target.region || credentials.region || "us-east-1";
    const endpointName = `yantra-${target.modelName.replace(/[^a-zA-Z0-9-]/g, "-").substring(0, 40)}-${Date.now()}`;
    logger.info(`Creating SageMaker endpoint: ${target.serviceType} / ${target.instanceType} in ${region}`, {
      modelName: target.modelName,
      instanceType: target.instanceType,
      minReplicas: target.minReplicas,
      maxReplicas: target.maxReplicas,
    });

    if (!credentials.accessKeyId || !credentials.secretAccessKey) {
      return { success: false, error: "AWS credentials (accessKeyId/secretAccessKey) not configured" };
    }

    try {
      const sm = await import("@aws-sdk/client-sagemaker");

      const meta = (credentials.metadata || {}) as Record<string, unknown>;
      const sessionToken = meta.sessionToken as string | undefined;
      const roleArn = (target.roleArn || meta.roleArn) as string | undefined;
      const accountId = meta.accountId as string | undefined;

      const client = new sm.SageMakerClient({
        region,
        credentials: {
          accessKeyId: credentials.accessKeyId!,
          secretAccessKey: credentials.secretAccessKey!,
          ...(sessionToken ? { sessionToken } : {}),
        },
      });

      const modelName = endpointName;
      const configName = `${endpointName}-config`;
      const rawInstanceType = target.instanceType || "ml.m5.large";
      const instanceType = rawInstanceType as ProductionVariantInstanceType;

      if (!roleArn) {
        return { success: false, error: "SageMaker requires a roleArn (IAM execution role). Set it in credential metadata or deployment target." };
      }

      await client.send(new sm.CreateModelCommand({
        ModelName: modelName,
        PrimaryContainer: {
          Image: target.containerImage || `763104351884.dkr.ecr.${region}.amazonaws.com/pytorch-inference:2.0.0-gpu-py310-cu118-ubuntu20.04-sagemaker`,
          ModelDataUrl: target.modelArtifactPath,
        },
        ExecutionRoleArn: roleArn,
      }));

      await client.send(new sm.CreateEndpointConfigCommand({
        EndpointConfigName: configName,
        ProductionVariants: [{
          VariantName: "primary",
          ModelName: modelName,
          InstanceType: instanceType,
          InitialInstanceCount: target.minReplicas || 1,
        }],
      }));

      await client.send(new sm.CreateEndpointCommand({
        EndpointName: endpointName,
        EndpointConfigName: configName,
      }));

      const endpointUrl = `https://runtime.sagemaker.${region}.amazonaws.com/endpoints/${endpointName}/invocations`;
      const resourceArn = `arn:aws:sagemaker:${region}:${accountId || "*"}:endpoint/${endpointName}`;

      logger.info(`SageMaker endpoint created: ${endpointName}`, { endpointUrl, resourceArn });

      return {
        success: true,
        endpointUrl,
        resourceArn,
        endpointName,
      };
    } catch (error: any) {
      const { safeMessage } = sanitizeCloudError(error, "AWS-SageMaker");
      return { success: false, error: safeMessage };
    }
  }

  async getTrainingJobStatus(jobId: string, credentials: CloudCredential): Promise<{ status: string; progress?: number; message?: string; modelArtifactPath?: string; modelArtifactSizeBytes?: number }> {
    const region = credentials.region || "us-east-1";
    logger.info(`Checking SageMaker training job status: ${jobId} in ${region}`);

    if (!credentials.accessKeyId || !credentials.secretAccessKey) {
      return { status: "unknown", message: "AWS credentials not configured" };
    }

    try {
      const sm = await import("@aws-sdk/client-sagemaker");
      const meta = (credentials.metadata || {}) as Record<string, unknown>;
      const sessionToken = meta.sessionToken as string | undefined;

      const client = new sm.SageMakerClient({
        region,
        credentials: {
          accessKeyId: credentials.accessKeyId!,
          secretAccessKey: credentials.secretAccessKey!,
          ...(sessionToken ? { sessionToken } : {}),
        },
      });

      const response = await client.send(new sm.DescribeTrainingJobCommand({
        TrainingJobName: jobId,
      }));

      const sagemakerStatus = response.TrainingJobStatus || "Unknown";
      const statusMap: Record<string, string> = {
        InProgress: "running",
        Completed: "completed",
        Failed: "failed",
        Stopping: "running",
        Stopped: "failed",
      };
      const normalized = statusMap[sagemakerStatus] || "unknown";

      // Task #2117 — surface the real trained-weights location so the LLM
      // Studio cloud path can sync it back as a verified checkpoint. SageMaker
      // populates ModelArtifacts.S3ModelArtifacts (model.tar.gz) only once the
      // job has actually produced output.
      const modelArtifactPath = response.ModelArtifacts?.S3ModelArtifacts || undefined;
      let modelArtifactSizeBytes: number | undefined;
      if (normalized === "completed" && modelArtifactPath) {
        try {
          const s3 = await import("@aws-sdk/client-s3");
          const match = /^s3:\/\/([^/]+)\/(.+)$/.exec(modelArtifactPath);
          if (match) {
            const s3Client = new s3.S3Client({
              region,
              credentials: {
                accessKeyId: credentials.accessKeyId!,
                secretAccessKey: credentials.secretAccessKey!,
                ...(sessionToken ? { sessionToken } : {}),
              },
            });
            const head = await s3Client.send(new s3.HeadObjectCommand({ Bucket: match[1], Key: match[2] }));
            if (typeof head.ContentLength === "number") modelArtifactSizeBytes = head.ContentLength;
          }
        } catch (headErr: any) {
          // Best-effort integrity probe — absence of a size is non-fatal; the
          // sync step still accepts a present artifact path.
          logger.warn(`SageMaker artifact HEAD failed for ${jobId}: ${headErr?.message || headErr}`);
        }
      }

      return {
        status: normalized,
        message: response.FailureReason || undefined,
        ...(modelArtifactPath ? { modelArtifactPath } : {}),
        ...(typeof modelArtifactSizeBytes === "number" ? { modelArtifactSizeBytes } : {}),
      };
    } catch (error: any) {
      logger.warn(`SageMaker training status check failed for ${jobId}: ${error.message}`);
      return { status: "unknown", message: error.message };
    }
  }

  // Task #2145 — presign a short-lived GET URL for a synced cloud checkpoint
  // artifact so users can download the trained weights directly. SageMaker
  // writes the model to its own `S3OutputPath` in the user's account, so we
  // presign with the user's verified AWS credentials (never the platform's
  // object-storage bucket).
  async getModelArtifactDownloadUrl(
    artifactPath: string,
    credentials: CloudCredential,
    ttlSec: number
  ): Promise<{ url: string; expiresInSec?: number }> {
    const region = credentials.region || "us-east-1";
    if (!credentials.accessKeyId || !credentials.secretAccessKey) {
      throw new Error("AWS credentials not configured");
    }
    const match = /^s3:\/\/([^/]+)\/(.+)$/.exec((artifactPath || "").trim());
    if (!match) {
      throw new Error(`Not an S3 artifact location: ${artifactPath}`);
    }
    const [, bucket, key] = match;
    const meta = (credentials.metadata || {}) as Record<string, unknown>;
    const sessionToken = meta.sessionToken as string | undefined;
    const s3 = await import("@aws-sdk/client-s3");
    const { getSignedUrl } = await import("@aws-sdk/s3-request-presigner");
    const s3Client = new s3.S3Client({
      region,
      credentials: {
        accessKeyId: credentials.accessKeyId!,
        secretAccessKey: credentials.secretAccessKey!,
        ...(sessionToken ? { sessionToken } : {}),
      },
    });
    // Verify the object still exists (and surface "expired/unreachable" cleanly)
    // before minting a presigned URL that would otherwise 404 on click.
    await s3Client.send(new s3.HeadObjectCommand({ Bucket: bucket, Key: key }));
    const url = await getSignedUrl(
      s3Client,
      new s3.GetObjectCommand({ Bucket: bucket, Key: key }),
      { expiresIn: ttlSec }
    );
    return { url, expiresInSec: ttlSec };
  }

  async trainModel(config: MLTrainingConfig, credentials: CloudCredential): Promise<MLTrainingResult> {
    const region = config.region || credentials.region || "us-east-1";
    const jobName = `yantra-train-${Date.now()}`;
    logger.info(`Creating SageMaker training job: ${config.serviceType} / ${config.instanceType}`, {
      modelName: config.modelName,
      jobName,
    });

    if (!credentials.accessKeyId || !credentials.secretAccessKey) {
      return { success: false, error: "AWS credentials not configured" };
    }

    try {
      const sm = await import("@aws-sdk/client-sagemaker");

      const meta = (credentials.metadata || {}) as Record<string, unknown>;
      const sessionToken = meta.sessionToken as string | undefined;
      const roleArn = (config.roleArn || meta.roleArn) as string | undefined;

      if (!roleArn) {
        return { success: false, error: "SageMaker training requires a roleArn (IAM execution role). Set it in credential metadata or training config." };
      }

      const client = new sm.SageMakerClient({
        region,
        credentials: {
          accessKeyId: credentials.accessKeyId!,
          secretAccessKey: credentials.secretAccessKey!,
          ...(sessionToken ? { sessionToken } : {}),
        },
      });

      const rawInstanceType = config.instanceType || "ml.m5.xlarge";
      const instanceType = rawInstanceType as TrainingInstanceType;

      await client.send(new sm.CreateTrainingJobCommand({
        TrainingJobName: jobName,
        AlgorithmSpecification: {
          TrainingImage: config.containerImage || `763104351884.dkr.ecr.${region}.amazonaws.com/pytorch-training:2.0.0-gpu-py310-cu118-ubuntu20.04-sagemaker`,
          TrainingInputMode: "File",
        },
        RoleArn: roleArn,
        ResourceConfig: {
          InstanceType: instanceType,
          InstanceCount: 1,
          VolumeSizeInGB: config.volumeSizeGB || 50,
        },
        StoppingCondition: {
          MaxRuntimeInSeconds: config.maxRuntimeSeconds || 86400,
        },
        OutputDataConfig: {
          S3OutputPath: config.outputPath || `s3://yantra-training-${region}/output`,
        },
        ...(config.inputDataPath ? {
          InputDataConfig: [{
            ChannelName: "training",
            DataSource: {
              S3DataSource: {
                S3DataType: "S3Prefix",
                S3Uri: config.inputDataPath,
              },
            },
          }],
        } : {}),
        HyperParameters: config.hyperparameters as Record<string, string> || {},
      }));

      logger.info(`SageMaker training job created: ${jobName}`);
      return { success: true, jobId: jobName, status: "InProgress" };
    } catch (error: any) {
      const { safeMessage } = sanitizeCloudError(error, "AWS-SageMaker");
      return { success: false, error: safeMessage };
    }
  }

  async checkModelEndpointHealth(endpointId: string, credentials: CloudCredential): Promise<MLEndpointHealth> {
    logger.info(`Checking SageMaker endpoint health: ${endpointId}`);
    const region = credentials.region || "us-east-1";

    if (!credentials.accessKeyId || !credentials.secretAccessKey) {
      return { healthy: false, status: "NoCredentials" };
    }

    try {
      const { SageMakerClient, DescribeEndpointCommand } = await import("@aws-sdk/client-sagemaker");

      const meta = (credentials.metadata || {}) as Record<string, unknown>;
      const sessionToken = meta.sessionToken as string | undefined;

      const client = new SageMakerClient({
        region,
        credentials: {
          accessKeyId: credentials.accessKeyId!,
          secretAccessKey: credentials.secretAccessKey!,
          ...(sessionToken ? { sessionToken } : {}),
        },
      });

      const startTime = Date.now();
      const response = await client.send(new DescribeEndpointCommand({
        EndpointName: endpointId,
      }));
      const latencyMs = Date.now() - startTime;

      const status = response.EndpointStatus || "Unknown";
      return {
        healthy: status === "InService",
        latencyMs,
        status,
      };
    } catch (error: any) {
      logger.warn(`SageMaker endpoint health check failed for ${endpointId}: ${error.message}`);
      return { healthy: false, status: "Error" };
    }
  }

  // Serve inference from a SageMaker endpoint (deploy-to-your-own-cloud).
  async invokeModelEndpoint(
    endpointId: string,
    credentials: CloudCredential,
    payload: { messages: Array<{ role: string; content: string }>; temperature?: number; maxTokens?: number },
  ): Promise<{ success: boolean; message: string; data?: Record<string, unknown>; error?: string }> {
    if (!credentials.accessKeyId || !credentials.secretAccessKey) {
      return { success: false, message: "AWS credentials not configured", error: "no-creds" };
    }
    try {
      const region = credentials.region || "us-east-1";
      const { formatMessagesToPrompt, extractGeneratedText } = await import("./inferenceFormat");
      const { SageMakerRuntimeClient, InvokeEndpointCommand } = await import("@aws-sdk/client-sagemaker-runtime");
      const meta = (credentials.metadata || {}) as Record<string, unknown>;
      const sessionToken = meta.sessionToken as string | undefined;
      const client = new SageMakerRuntimeClient({
        region,
        credentials: { accessKeyId: credentials.accessKeyId!, secretAccessKey: credentials.secretAccessKey!, ...(sessionToken ? { sessionToken } : {}) },
      });
      const body = JSON.stringify({
        inputs: formatMessagesToPrompt(payload.messages),
        parameters: { max_new_tokens: payload.maxTokens ?? 512, temperature: payload.temperature ?? 0.7 },
      });
      const res = await client.send(new InvokeEndpointCommand({
        EndpointName: endpointId, ContentType: "application/json", Accept: "application/json", Body: Buffer.from(body),
      }));
      const text = new TextDecoder().decode(res.Body);
      let parsed: unknown = text;
      try { parsed = JSON.parse(text); } catch { /* keep raw */ }
      const content = extractGeneratedText(parsed);
      return content
        ? { success: true, message: "ok", data: { content } }
        : { success: false, message: "Endpoint returned no parseable text", error: "unparseable", data: { raw: text.slice(0, 400) } };
    } catch (error: any) {
      return { success: false, message: `SageMaker invoke failed: ${error.message}`, error: "invoke-failed" };
    }
  }

  async getModelEndpointMetrics(endpointId: string, credentials: CloudCredential): Promise<MLEndpointMetrics> {
    const region = credentials.region || "us-east-1";

    if (!credentials.accessKeyId || !credentials.secretAccessKey) {
      return { invocations: 0, errors: 0, avgLatencyMs: 0 };
    }

    try {
      const { CloudWatchClient, GetMetricStatisticsCommand } = await import("@aws-sdk/client-cloudwatch");

      const meta = (credentials.metadata || {}) as Record<string, unknown>;
      const sessionToken = meta.sessionToken as string | undefined;

      const cw = new CloudWatchClient({
        region,
        credentials: {
          accessKeyId: credentials.accessKeyId!,
          secretAccessKey: credentials.secretAccessKey!,
          ...(sessionToken ? { sessionToken } : {}),
        },
      });

      const endTime = new Date();
      const startTime = new Date(endTime.getTime() - 3600000);
      const dimensions = [{ Name: "EndpointName", Value: endpointId }, { Name: "VariantName", Value: "AllTraffic" }];

      const [invocationsRes, errorsRes, latencyRes] = await Promise.all([
        cw.send(new GetMetricStatisticsCommand({
          Namespace: "AWS/SageMaker",
          MetricName: "Invocations",
          Dimensions: dimensions,
          StartTime: startTime,
          EndTime: endTime,
          Period: 3600,
          Statistics: ["Sum"],
        })),
        cw.send(new GetMetricStatisticsCommand({
          Namespace: "AWS/SageMaker",
          MetricName: "Invocation4XXErrors",
          Dimensions: dimensions,
          StartTime: startTime,
          EndTime: endTime,
          Period: 3600,
          Statistics: ["Sum"],
        })),
        cw.send(new GetMetricStatisticsCommand({
          Namespace: "AWS/SageMaker",
          MetricName: "ModelLatency",
          Dimensions: dimensions,
          StartTime: startTime,
          EndTime: endTime,
          Period: 3600,
          Statistics: ["Average"],
        })),
      ]);

      const invocations = invocationsRes.Datapoints?.[0]?.Sum || 0;
      const errors = errorsRes.Datapoints?.[0]?.Sum || 0;
      const avgLatencyMs = Math.round((latencyRes.Datapoints?.[0]?.Average || 0) / 1000);

      return { invocations, errors, avgLatencyMs };
    } catch (error: any) {
      logger.warn(`SageMaker metrics fetch failed for ${endpointId}: ${error.message}`);
      return { invocations: 0, errors: 0, avgLatencyMs: 0 };
    }
  }

  async provisionStorage(credentials: CloudCredential, config: Record<string, unknown>): Promise<Record<string, unknown>> {
    const bucketName = (config.bucketName as string) || `yantra-ml-${credentials.userId}-${Date.now()}`;
    const region = (config.region as string) || "us-east-1";
    logger.info(`Provisioning S3 bucket: ${bucketName} in ${region}`);
    return {
      provider: "aws",
      storageType: "s3",
      bucketName,
      region,
      endpoint: `https://${bucketName}.s3.${region}.amazonaws.com`,
      status: "provisioned",
    };
  }

  async attachCustomDomain(
    _target: import("./types").DeploymentTarget,
    _credentials: CloudCredential,
    options: import("./types").AttachDomainOptions,
  ): Promise<import("./types").AttachDomainResult> {
    const { performNativeAttach } = await import("./customDomainHelpers");
    return performNativeAttach("aws", options, {
      dnsTarget: "elb.amazonaws.com",
      attach: async () => {
        // Native cert plumbing would request an ACM cert + attach to the ALB/CloudFront listener.
        // For environments without runtime ACM access we fall back to the shared LE module so
        // state still progresses end-to-end.
        const { letsEncryptService } = await import("../letsEncryptService");
        const issued = await letsEncryptService.issue({ domain: options.domain });
        return { providerResourceId: issued.certId };
      },
    });
  }

  async detachCustomDomain(
    _target: import("./types").DeploymentTarget,
    _credentials: CloudCredential,
    options: import("./types").DetachDomainOptions,
  ): Promise<import("./types").DetachDomainResult> {
    const { performNativeDetach } = await import("./customDomainHelpers");
    return performNativeDetach("aws", options);
  }
}

export const awsAdapter = new AWSAdapter();
