# Immutable backups in Amazon S3

`backup-bucket.yaml` creates, in one stack:

- an S3 bucket with **Object Lock in compliance mode** (90 days by default): no one, including the account
  root user, can delete or overwrite a locked backup before the lock ends; versioning on, public access
  blocked, encryption on, HTTPS only, and copies expire 120 days after upload so cost stays bounded
- GitHub's **OIDC identity provider**, so GitHub Actions gets short-lived AWS credentials and no AWS keys are stored
- an **IAM role** that only the `main` branch of this repository can assume, allowed to write new backups and read
  their lock status: it cannot read, list or delete anything

## Deploy (about 10 minutes)

1. AWS console → **CloudFormation** → region **us-east-1** (N. Virginia) → **Create stack → With new resources**.
2. **Upload a template file** → choose `aws/backup-bucket.yaml` from this repository → Next.
3. Stack name `watchfloor-backup`. Leave the parameters as they are, except:
   **CreateOidcProvider = false** if IAM → Identity providers already lists `token.actions.githubusercontent.com`.
4. Next → Next → tick **"I acknowledge that AWS CloudFormation might create IAM resources"** → **Submit**.
5. When the status is **CREATE_COMPLETE**, open **Outputs** and copy `RoleArn` and `BucketName`.
6. GitHub → repository **Settings → Secrets and variables → Actions → New repository secret**:
   `AWS_BACKUP_ROLE_ARN` = RoleArn, `AWS_BACKUP_BUCKET` = BucketName.
   (Another region than us-east-1: also add a repository **variable** `AWS_BACKUP_REGION`.)
7. Actions → **Weekly backup** → Run workflow. The run summary should say the S3 copy is locked and that delete was refused.

## Good to know

- Compliance mode is strict by design: a locked backup cannot be removed early, even by you. With weekly
  backups of under 1 MB this costs cents a month; check your bill after the first month.
- Deleting the stack keeps the bucket (`DeletionPolicy: Retain`), so a mistake cannot wipe the backups.
- Restore: download a bundle in the S3 console and follow `mac/RESTORE.md`.
