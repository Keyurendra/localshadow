TL;DR:

```
# Download installer script
Invoke-WebRequest -Uri 'https://accuknox-omni.s3.us-east-1.amazonaws.com/v0.1.2/agent-install.ps1' -OutFile .\agent-install.ps1

# Run installation script to setup agent
.\agent-install.ps1 `
    -ArtifactEndpoint https://cspm.accuknox.com/api/v1/artifact/ `
    -TenantId 000 `
    -ArtifactLabel CHANGEME `
    -ArtifactApiToken "<REDACTED>" `
    -SkipMalwareScan $true
```

- Artifact API tokens can be created under Settings -> Tokens.
- Labels can be created under Settings -> Labels.

The installation script creates a Windows scheduled task.

## Air-gap Installation

1. Download & Extract all-in-one.zip from S3

```ps1
Invoke-WebRequest `
    -Uri "https://accuknox-omni.s3.us-east-1.amazonaws.com/latest/all-in-one.zip" `
    -OutFile all-in-one.zip `
    -UseBasicParsing
Expand-Archive -Path ".\all-in-one.zip" -DestinationPath .\ -Force
cd .\all-in-one\
```

2. Move ClamAV Database to its Appropriate Location

```ps1
New-Item -ItemType Directory -Path "C:\Program Files\ClamAV" -Force
Move-Item -Path .\database\clamav\ -Destination "C:\Program Files\ClamAV\database" -Force
```

3. Move MSRC Database to its Appropriate Location

```ps1
New-Item -ItemType Directory -Path "C:\ProgramData\Accuknox\Omni" -Force
Move-Item -Path .\database\msrc\ -Destination "C:\ProgramData\Accuknox\Omni" -Force
```

4. Install Omni Binary to its Appropriate Location

```ps1
New-Item -ItemType Directory -Path "C:\Program Files\AccuKnox\Omni\" -Force
Move-Item -Path .\omni.exe -Destination "C:\Program Files\AccuKnox\Omni\" -Force
```

5. Run the installation script

```ps1
.\agent-install.ps1 `
    -ArtifactEndpoint https://cspm.demo.accuknox.com/api/v1/artifact/ `
    -TenantId 000 `
    -ArtifactLabel CHANGEME `
    -ArtifactApiToken "<REDACTED>" `
    -ClamavMSIInstallerFile clamav.msi `
    -SkipOmniDownload $true `
    -SkipDatabaseDownload $true
```
