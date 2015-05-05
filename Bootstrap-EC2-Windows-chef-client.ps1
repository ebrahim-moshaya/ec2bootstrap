# Inject this as user-data of a Windows 2012 AMI, like this (edit the userPassword to your needs):
#
# <powershell>
# Set-ExecutionPolicy Unrestricted
# icm $executioncontext.InvokeCommand.NewScriptBlock((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/ebrahim-moshaya/ec2bootstrap/master/Bootstrap-EC2-Windows-chef-client.ps1')) -ArgumentList "AWSAccessKey", "AWSSecretKey"
# </powershell>
#

# Pass in the following Parameters
param(
  [Parameter(Mandatory=$true)]
  [string]
  $AWSAccessKey,
  
  [Parameter(Mandatory=$true)]
  [string]
  $AWSSecretKey
)

Start-Transcript -Path 'c:\bootstrap-transcript.txt' -append -Force 
Set-StrictMode -Version Latest
Set-ExecutionPolicy Unrestricted -force

$log = 'c:\Bootstrap.txt'
$client = new-object System.Net.WebClient
$shell_app = new-object -com shell.application


while (($AWSAccessKey -eq $null) -or ($AWSAccessKey -eq ''))
{
  $AWSAccessKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((Read-Host "Enter a non-null / non-empty AWS AccessKey" -AsSecureString)))
}

while (($AWSSecretKey -eq $null) -or ($AWSSecretKey -eq ''))
{
  $AWSSecretKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((Read-Host "Enter a non-null / non-empty AWS SecretKey" -AsSecureString)))
}


# - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
# Detect Processor Architecture and OperatingSystemSKU
# http://blogs.msdn.com/b/david.wang/archive/2006/03/26/howto-detect-process-bitness.aspx
# http://msdn.microsoft.com/en-us/library/ms724358.aspx
#
# - - - - - - - - - - - - - - - - - - - - - - - - - - -

$systemPath = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
$sysNative = [IO.Path]::Combine($env:windir, "sysnative")

$Is32Bit = (($Env:PROCESSOR_ARCHITECTURE -eq 'x86') -and ($Env:PROCESSOR_ARCHITEW6432 -eq $null))
Add-Content $log -value "Is 32-bit [$Is32Bit]"


$coreEditions = @(0x0c,0x27,0x0e,0x29,0x2a,0x0d,0x28,0x1d)
$IsCore = $coreEditions -contains (Get-WmiObject -Query "Select OperatingSystemSKU from Win32_OperatingSystem" | Select -ExpandProperty OperatingSystemSKU)
Add-Content $log -value "Is Core [$IsCore]"

# move to home, PS is incredibly complex :)
cd $Env:USERPROFILE
Set-Location -Path $Env:USERPROFILE
[Environment]::CurrentDirectory=(Get-Location -PSProvider FileSystem).ProviderPath


# - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Function: Download-Bucket-File
#
# Comments: This function is intended to download a specific file from S3.
#
#
# - - - - - - - - - - - - - - - - - - - - - - - - - - -
function Download-Bucket-File ($Filename, $Bucket, $Destination)
{
  $status = "Downloading " + $Filename + " from S3 [" + $Bucket + "]"
  
  Log_Status $status
  
  
  $FullPath = $Destination + "\" + $Filename
  
  Read-S3Object -BucketName $Bucket -Key $Filename -File $FullPath -AccessKey $AWSAccessKey -SecretKey $AWSSecretKey
  
  Wait-Until-Downloaded $FullPath
  
  $status = "Downloaded " + $Filename + " from S3 [" + $Bucket + "]"
  
  Log_Status $status
  
}
# - - - - - - - - - - - - - - - - - - - - - - - - - - -


# - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Function: Download-and-unzip-File
#
# Comments: This function is intended to download a specific file from S3 and then unzip it
#
# - - - - - - - - - - - - - - - - - - - - - - - - - - -

function unzip-File ($Filename, $Destination, $Unzipto)
{

$FullPath = $Destination + "\" + $Filename

$zip_file = $shell_app.namespace($fullpath)

$status = "Unzipping " + $Filename 

Log_Status $status


#set the destination directory for the extracts
$UnzipDirectory = $shell_app.namespace($Unzipto)

#unzip the file
$UnzipDirectory.Copyhere($zip_file.items())

$status = "Unzipped " + $Filename 

Log_Status $status

}


# - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Function: Wait-Until-Downloaded
#
# Comments: This function is intended to wait until a particular file has been downloaded.
#
# - - - - - - - - - - - - - - - - - - - - - - - - - - -
function Wait-Until-Downloaded ($Path)
{
  While (1 -eq 1) {
    IF (Test-Path $Path ) {
      #file exists. break loop
      break
    }
    #sleep for 60 seconds, then check again
    Start-Sleep -s 60
  }
}
# - - - - - - - - - - - - - - - - - - - - - - - - - - -


# - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
# Download and Install Chef Client
# https://opscode-omnibus-packages.s3.amazonaws.com/windows/2008r2/x86_64/chef-windows-11.16.2-1.windows.msi
#
# - - - - - - - - - - - - - - - - - - - - - - - - - - -

function CHEF
{
  $destchefDir = 'c:\\chef'
  $desttmpDir = 'c:\\tmp'
  If (!(Test-Path $destchefDir\\chef_bootstrap.pem))
  {
    Log_Status "Running Windows slavesetup script (cwd:  $(pwd) id: $(id))"
    If (Test-Path $destchefDir\\client.pem)
    {
     Log_Status "Removed Packer $destchefDir"
     Remove-Item -Recurse -Force $destchefDir
    }

    # Install chef-client if necessary
    if ( get-command chef-client )
    {
      Log_Status "Already Installed $(chef-client -v)"
    }
    Else
    {
      wget --no-check-certificate http://www.getchef.com/chef/install.msi
    }


    # Copy the files uploaded from the jenkins master into the /etc/chef directory
    If (!(Test-Path $destchefDir))
    {
      mkdir -path $destchefDir
    }
    Else
    {
      Log_Status "$destchefDir already exists"
    }

    If (!(Test-Path $destchefDir\\chefsolo.json))
    {
      Log_Status "Download bucket Chef bootstrap files onto $destchefDir"
      Download-Bucket-File "roles.json"  "chefbootstrap-jenkins/msbuildpackage" $destchefDir
      Download-Bucket-File "validation.pem"  "chefbootstrap-jenkins/msbuildpackage" $destchefDir
      Download-Bucket-File "solo.rb"  "chefbootstrap-jenkins/msbuildpackage" $destchefDir
      Download-Bucket-File "chefsolo.json"  "chefbootstrap-jenkins/msbuildpackage" $destchefDir
      Download-Bucket-File "chef_bootstrap.pem"  "chefbootstrap-jenkins/msbuildpackage" $destchefDir
    }
    Else
    {
      Log_Status "bootstrap files already in $destchefDir"
    }

    # Download the bootstrap cookbooks
    If (!(Test-Path $desttmpDir))
    {
      mkdir -path $desttmpDir
    }
    Else
    {
      Log_Status "$desttmpDir already exists"
    }

    If (!(Test-Path $desttmpDir\\nvm_bootstrap.zip))
    {
      Log_Status "downloading nvm_bootstrap.zip"
      Invoke-WebRequest -Verbose http://nvmchef-bootstrap.s3-website-eu-west-1.amazonaws.com/nvm_bootstrap.zip -OutFile $desttmpDir\\nvm_bootstrap.zip
      If (!(Test-Path $desttmpDir\\chef-solo))
      {
        mkdir -path $desttmpDir\\chef-solo
      }
      Else
      {
        Log_Status "$desttmpDir\\chef-solo already exists"
      }
    }
    Else
    {
      Log_Status "nvm_bootstrap.zip already exists"
    }

    If (!(Test-Path $desttmpDir\\chef-solo\\cookbooks))
    {
      $unzipdest = Join-Path $desttmpDir "chef-solo"
      unzip-File "nvm_bootstrap.zip" "c:\tmp" "c:\tmp\chef-solo"
    }
    Else
    {
      Log_Status "nvm_bootstrap.zip already extracted"
    }

    # Ensure the ohai ec2 hints file exists
    If (!(Test-Path $destchefDir\\ohai\\hints))
    {
      Log_Status "Creating hints folder"
      mkdir -path $destchefDir\\ohai\\hints
    }
    Else
    {
      Log_Status "hints folder already created"
    }

    If (!(Test-Path $destchefDir\\ohai\\hints\\ec2.json))
    {
      Log_Status "Creating hints file"
      Log_Status "{}" | Out-File $destchefDir\\ohai\\hints\\ec2.json -Encoding ASCII 
    }
    Else
    {
      Log_Status "hints file already created"
    }

    # Bootstrap with chef-solo if the first-boot
    If (!(Test-Path $destchefDir\\client.pem))
    {
      Log_Status "Running chef-solo to bootstrap client"
      chef-solo --config $destchefDir\\solo.rb --json-attributes $destchefDir\\chefsolo.json 2>&1 | tee $desttmpDir\\chef_solo.log
    }
    Else
    {
      Log_Status "Client already bootstrapped"
    }

    Log_Status "Running Chef-Client"
    chef-client --json-attributes $destchefDir\\roles.json --environment BuildServer-Testing-Cloud3 -l debug
  }
  Else
  {
      Log_Status "Client already bootstrapped"
  }
}


# - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Function: Log_Status
#
# Comments: This function is intended to write a status message to SQS queue and / or local log file
#
# - - - - - - - - - - - - - - - - - - - - - - - - - - -

function Log_Status ($message)
{
  Add-Content $log -value $message
  Write-Host $message -ForegroundColor Green
}


# - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
# Section : Script begins here
#
# - - - - - - - - - - - - - - - - - - - - - - - - - - -

Log_Status "Started bootstrapping EC2 Instance"


Log_Status "Configuring Chef Client" 
CHEF
Log_Status "Finished configuring Chef Client" 

# - - - - - - - - - - - - - - - - - - - - - - - - - - -

Log_Status "Finished bootstrapping"