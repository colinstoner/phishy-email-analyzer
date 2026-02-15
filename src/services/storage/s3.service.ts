/**
 * S3 Storage Service
 * Handles S3 operations for email storage and retrieval
 */

import {
  S3Client,
  GetObjectCommand,
  DeleteObjectCommand,
  PutObjectCommand,
} from '@aws-sdk/client-s3';
import { Readable } from 'stream';
import { createLogger } from '../../utils/logger';
import { withRetry, isRetryableHttpError } from '../../utils/retry';

const logger = createLogger('s3-service');

export class S3Service {
  private client: S3Client;
  private defaultBucket: string;

  constructor(region: string, defaultBucket: string) {
    this.client = new S3Client({ region });
    this.defaultBucket = defaultBucket;
  }

  /**
   * Get object from S3
   */
  async getObject(bucket: string, key: string): Promise<string> {
    logger.info('Retrieving object from S3', { bucket, key });

    return withRetry(
      async () => {
        const response = await this.client.send(
          new GetObjectCommand({
            Bucket: bucket,
            Key: key,
          })
        );

        if (!response.Body) {
          throw new Error('S3 returned empty response body');
        }

        const content = await this.streamToString(response.Body as Readable);
        logger.debug('Retrieved object from S3', { bucket, key, length: content.length });

        return content;
      },
      {
        maxRetries: 3,
        baseDelayMs: 500,
        shouldRetry: isRetryableHttpError,
      }
    );
  }

  /**
   * Delete object from S3
   */
  async deleteObject(bucket: string, key: string): Promise<boolean> {
    if (!bucket || !key) {
      logger.warn('Cannot delete object: missing bucket or key');
      return false;
    }

    logger.info('Deleting object from S3', { bucket, key });

    try {
      await withRetry(
        async () => {
          await this.client.send(
            new DeleteObjectCommand({
              Bucket: bucket,
              Key: key,
            })
          );
        },
        {
          maxRetries: 3,
          baseDelayMs: 500,
          shouldRetry: isRetryableHttpError,
        }
      );

      logger.info('Successfully deleted object from S3', { bucket, key });
      return true;
    } catch (error) {
      logger.error('Error deleting object from S3', {
        bucket,
        key,
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    }
  }

  /**
   * Put object to S3
   */
  async putObject(bucket: string, key: string, content: string, contentType?: string): Promise<void> {
    logger.info('Putting object to S3', { bucket, key, contentLength: content.length });

    await withRetry(
      async () => {
        await this.client.send(
          new PutObjectCommand({
            Bucket: bucket,
            Key: key,
            Body: content,
            ContentType: contentType ?? 'application/octet-stream',
          })
        );
      },
      {
        maxRetries: 3,
        baseDelayMs: 500,
        shouldRetry: isRetryableHttpError,
      }
    );

    logger.debug('Successfully put object to S3', { bucket, key });
  }

  /**
   * Get email from default bucket
   */
  async getEmail(key: string): Promise<string> {
    return this.getObject(this.defaultBucket, key);
  }

  /**
   * Delete email from default bucket
   */
  async deleteEmail(key: string): Promise<boolean> {
    return this.deleteObject(this.defaultBucket, key);
  }

  /**
   * Convert stream to string
   */
  private async streamToString(stream: Readable): Promise<string> {
    const chunks: Buffer[] = [];

    return new Promise((resolve, reject) => {
      stream.on('data', (chunk: Buffer) => chunks.push(chunk));
      stream.on('error', reject);
      stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    });
  }

  /**
   * Get the default bucket name
   */
  getDefaultBucket(): string {
    return this.defaultBucket;
  }
}
