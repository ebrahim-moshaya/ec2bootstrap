# Inject this as user-data of a Windows 2012 AMI, like this (edit the userPassword to your needs):
#
# <powershell>
# Set-ExecutionPolicy Unrestricted
# icm $executioncontext.InvokeCommand.NewScriptBlock((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/ebrahim-moshaya/ec2bootstrap/master/Bootstrap-EC2-Windows-chef-client.ps1'))
# </powershell>
#

# Pass in the following Parameters


Start-Transcript -Path 'c:\bootstrap-transcript.txt' -append -Force 
Set-StrictMode -Version Latest
Set-ExecutionPolicy Unrestricted -force

$log = 'c:\Bootstrap.txt'
$client = new-object System.Net.WebClient
$bootstrapqueue = "https://sqs.eu-west-1.amazonaws.com/662182053957/BootstrapQueue"



#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
# Detect Processor Architecture and OperatingSystemSKU
# http://blogs.msdn.com/b/david.wang/archive/2006/03/26/howto-detect-process-bitness.aspx
# http://msdn.microsoft.com/en-us/library/ms724358.aspx
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

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



#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
# Download and Install Chef Client
# https://opscode-omnibus-packages.s3.amazonaws.com/windows/2008r2/x86_64/chef-windows-11.16.2-1.windows.msi
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

function CHEF
{
  # Create a new chef directory
  $chef_dir = "C:\chef"
  if (!(Test-Path -path $chef_dir))
  {
    mkdir $chef_dir
  }
  Log_Status "Create System Environment variable for the chef node name"
  [Environment]::SetEnvironmentVariable("CHEFNODE", "JenkinsSlave-${env:Computername}", "Machine")
  "node_name 'JenkinsSlave-${env:ComputerName}'" | out-file -filepath C:\chef\client.rb -append -Encoding UTF8
  "node_name 'JenkinsSlave-${env:ComputerName}'" | out-file -filepath C:\chef\knife.rb -append -Encoding UTF8
  cd $chef_dir
  chef-service-manager -a install
  &sc.exe config chef-client start= auto
  chef-client
  knife node run_list add JenkinsSlave-${env:Computername} 'role[jenkins_slave]' 2>&1 | tee -a c:\chef\knife.log
  chef-client
  Log_Status  "Executed Chef installer" 
}

#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#	Function:	Log_Status
#
#	Comments:	This function is intended to write a status message to SQS queue and / or local log file
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

function Log_Status ($message)
{
  
  Add-Content $log -value $message
  Add-Content $log -value $message
  Write-Host $message -ForegroundColor Green
  Send-SQSMessage -QueueUrl $bootstrapqueue -Region "eu-west-1" -MessageBody $message -AccessKey $AWSAccessKey -SecretKey $AWSSecretKey
}


Log_Status "Downloading and Installing Chef Client" 
CHEF
Log_Status "Finished installing Chef Client" 

#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-



#wait a bit, it's windows after all
Start-Sleep -m 10000

#Write-Host "Press any key to reboot and finish image configuration"
#[void]$host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
 

#Restart-Computer
