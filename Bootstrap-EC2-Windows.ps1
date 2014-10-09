# Inject this as user-data of a Windows 2012 AMI, like this (edit the userPassword to your needs):
#
# <powershell>
# Set-ExecutionPolicy Unrestricted
# icm $executioncontext.InvokeCommand.NewScriptBlock((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/ebrahim-moshaya/ec2bootstrap/master/Bootstrap-EC2-Windows.ps1')) -ArgumentList "userPassword", "AWSAccessKey", "AWSSecretKey"
# </powershell>
#

# Pass in the following Parameters
param(
  [Parameter(Mandatory=$true)]
  [string]
  $userPassword,
  
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
$bootstrapqueue = "https://sqs.eu-west-1.amazonaws.com/662182053957/BootstrapQueue"



while (($userPassword -eq $null) -or ($userPassword -eq ''))
{
  $userPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((Read-Host "Enter a non-null / non-empty User password" -AsSecureString)))
}

while (($AWSAccessKey -eq $null) -or ($AWSAccessKey -eq ''))
{
  $AWSAccessKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((Read-Host "Enter a non-null / non-empty AWS AccessKey" -AsSecureString)))
}

while (($AWSSecretKey -eq $null) -or ($AWSSecretKey -eq ''))
{
  $AWSSecretKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((Read-Host "Enter a non-null / non-empty AWS SecretKey" -AsSecureString)))
}

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
#	Function:	Download-Bucket-File
#
#	Comments:	This function is intended to download a specific file from S3.
#
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
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
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#	Function:	Download-and-unzip-File
#
#	Comments:	This function is intended to download a specific file from S3 and then unzip it
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

function unzip-File ($Filename, $Destination, $Unzipto)
{

$FullPath = $Destination + "\" + $Filename

$zip_file = $shell_app.namespace($fullpath )

$status = "Unzipping " + $Filename 

Log_Status $status


#set the destination directory for the extracts
$UnzipDirectory = $shell_app.namespace($Unzipto)

#unzip the file
$UnzipDirectory.Copyhere($zip_file.items())

$status = "Unzipped " + $Filename 

Log_Status $status

}


#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#	Function:	Wait-Until-Downloaded
#
#	Comments:	This function is intended to wait until a particular file has been downloaded.
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
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
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-


#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
# Configure User Accounts
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

function UserAccounts
{
  #change "Administrator" password
  net user Administrator $userPassword
  Log_Status "Changed Administrator password"
  
  # Create a jenkins user with Their password, add to Admin group
  net user /add jenkins $userPassword;
  net localgroup Administrators /add jenkins;
  Log_Status "jenkins user created and added to admin group"
}



#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
# Configure Firewall
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

function Config-Firewall
{
  netsh advfirewall firewall set rule group="network discovery" new enable=yes
  netsh firewall add portopening TCP 80 "Windows Remote Management";
  netsh advfirewall firewall add rule name="SMB" dir=in action=allow protocol=TCP localport=445 profile=any
  Netsh firewall set portopening tcp 445 smb enable
  # Turn off Windows Firewall for All Networks (Domain, Private, Public)
  #netsh advfirewall set allprofiles state off
  #Log_Status "Windows Firewall has been disabled."
}


#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
# Disable UAC (User Access Control)
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

function Disable-UAC
{
  New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -PropertyType DWord -Value 0 -Force | Out-Null
}


#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
# Enable and configure WINRM
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

function EnableConfigureWINRM
{
  
  #check winrm id, if it's not valid and LocalAccountTokenFilterPolicy isn't established, do it
  $id = &winrm id
  if (($id -eq $null) -and (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue) -eq $null)
  {
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -name LocalAccountTokenFilterPolicy -value 1 -propertyType dword
    Log_Status "Added LocalAccountTokenFilterPolicy since winrm id could not be executed"
  }
  ##winrm quickconfig -q
  ##winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="1024"}'
  ##winrm set winrm/config '@{MaxTimeoutms="1800000"}'
  ##winrm set winrm/config/service '@{AllowUnencrypted="true"}'
  ##winrm set winrm/config/service/auth '@{Basic="true"}'
  
  #winrm set winrm/config/client/auth '@{Basic="true"}'
  # needed for windows to manipulate centralized config files which live of a share. Such as AppFabric.
  #winrm set winrm/config/service/auth '@{CredSSP="true"}';
  ##Log_Status "Attempting to enable built in 5985 firewall rule";
  ##netsh advfirewall firewall add rule name="jenkins-Windows Remote Management (HTTP-In)" dir=in action=allow enable=yes profile=any protocol=tcp localport=5985 remoteip=any;
  ##netsh advfirewall firewall add rule name="jenkins-Windows Remote Management (HTTPS-In)" dir=in action=allow enable=yes profile=any protocol=tcp localport=5986 remoteip=any;
  #netsh advfirewall firewall set rule name="Windows Remote Management (HTTP-In)" profile=public protocol=tcp localport=5985 new remoteip=any;
  ##Log_Status "Adding custom firewall rule for 5985 and 5986"
  #netsh advfirewall firewall add rule name="WinRM 5985" protocol=TCP dir=in localport=5985 action=allow
  #netsh advfirewall firewall add rule name="WinRM 5986" protocol=TCP dir=in localport=5986 action=allow
  #Log_Status  "Opened 5985 & 5986 for incoming winrm"
  
  ##winrm set winrm/config/service/auth '@{Negotiate="false"}'
  ##Set-Service winrm -startuptype "auto"
}


#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
# Disable password complexity requirements
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

function Disable-PassComplexity
{
  "[System Access]" | out-file c:\delete.cfg
  "PasswordComplexity = 0" | out-file c:\delete.cfg -append
  "[Version]" | out-file c:\delete.cfg -append
  'signature="$CHICAGO$"' | out-file c:\delete.cfg -append
  secedit /configure /db C:\Windows\security\new.sdb /cfg c:\delete.cfg /areas SECURITYPOLICY;
  del c:\delete.cfg
}


#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
# Disable the shutdown tracker
# Reference: http://www.askvg.com/how-to-disable-remove-annoying-shutdown-event-tracker-in-windows-server-2003-2008/
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

function Disable-Shutdown-Tracker
{
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability"
  }
  New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -PropertyType DWord -Value 0 -Force -ErrorAction continue
  New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonUI" -PropertyType DWord -Value 0 -Force -ErrorAction continue
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonUI" -Value 0
}


#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#  Disable Automatic Updates
#  Reference: http://www.benmorris.me/2012/05/1st-test-blog-post.html
#
#	Comments:	This function is intended to disable Windows Updates.
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

function Disable-WINUPDATES
{
  $AutoUpdate = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
  $AutoUpdate.NotificationLevel = 1
  $AutoUpdate.Save()
}


#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#	Function:	Disable-IEESC
#
#	Comments:	This function is intended to disable IE Enhance Security Configuration, making it easier for users to access the internet via their browser.
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
function Disable-IEESC
{
  $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
  $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
  Set-ItemProperty -path $AdminKey -name "IsInstalled" -value 0
  Set-ItemProperty -path $UserKey -name "IsInstalled" -value 0
  Rundll32 iesetup.dll, IEHardenLMSettings,1,True
  Rundll32 iesetup.dll, IEHardenUser,1,True
  Rundll32 iesetup.dll, IEHardenAdmin,1,True
  Stop-Process -Name Explorer
}


#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#	Function:	Set-IE-HomePage
#
#	Comments:	This function is intended to set the home page for Internet Explorer.
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
function Set-IEHomePage ($URL)
{
  Set-ItemProperty -path "HKCU:\Software\Microsoft\Internet Explorer\main" -name "Start Page" -value $URL
}


#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
# Configure Powershell
# enable powershell servermanager cmdlets (only for 2008 r2 + above)
#
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

function PS-CONFIG
{
  if ($IsCore)
  {
    DISM /Online /Enable-Feature /FeatureName:MicrosoftWindowsPowerShell /FeatureName:ServerManager-PSH-Cmdlets /FeatureName:BestPractices-PSH-Cmdlets
    Log_Status "Enabled ServerManager and BestPractices Cmdlets"
    
    #enable .NET flavors - on server core only -- errors on regular 2008
    DISM /Online /Enable-Feature /FeatureName:NetFx2-ServerCore /FeatureName:NetFx2-ServerCore-WOW64 /FeatureName:NetFx3-ServerCore /FeatureName:NetFx3-ServerCore-WOW64
    Log_Status "Enabled .NET frameworks 2 and 3 for x86 and x64"
  }
}


#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
# Download and Install 7-Zip
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

function SEVENZIP
{
  $7zUri = if ($Is32Bit) { 'http://sourceforge.net/projects/sevenzip/files/7-Zip/9.22/7z922.msi/download' } `
  else { 'http://sourceforge.net/projects/sevenzip/files/7-Zip/9.22/7z922-x64.msi/download' }
  
  $client.DownloadFile( $7zUri, '7z922.msi')
  Start-Process -FilePath "msiexec.exe" -ArgumentList '/i 7z922.msi /norestart /q INSTALLDIR="c:\program files\7-zip"' -Wait
  SetX Path "${Env:Path};C:\Program Files\7-zip" /m
  $Env:Path += ';C:\Program Files\7-Zip'
  del 7z922.msi
  Log_Status "Installed 7-zip from $7zUri and updated path"
}

#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
# Download and Install C++ Redistributable Package 2010
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

function VCREDIST
{
  $vcredist = if ($Is32Bit) { 'http://download.microsoft.com/download/5/B/C/5BC5DBB3-652D-4DCE-B14A-475AB85EEF6E/vcredist_x86.exe'} `
  else { 'http://download.microsoft.com/download/3/2/2/3224B87F-CFA0-4E70-BDA3-3DE650EFEBA5/vcredist_x64.exe' }
  
  $client.DownloadFile( $vcredist, 'vcredist.exe')
  Start-Process -FilePath 'C:\Users\Administrator\vcredist.exe' -ArgumentList '/norestart /q' -Wait
  del vcredist.exe
  Log_Status "Installed VC++ 2010 Redistributable from $vcredist and updated path"
}


#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
# Download and Install Java Runtime Environment
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

function JRE
{
  $JRE = if ($Is32Bit) { 'http://javadl.sun.com/webapps/download/AutoDL?BundleId=95123' } `
  else { 'http://javadl.sun.com/webapps/download/AutoDL?BundleId=95125' }

  
  $client.DownloadFile( $JRE, 'jre-windows.exe')
  Start-Process -FilePath C:\Users\Administrator\jre-windows.exe -ArgumentList "/s /norestart" -Wait
  del jre-windows.exe
}


#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
# Download and Install curl
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

function CURL-CONFIG
{
  $curlUri = if ($Is32Bit) { 'http://www.paehl.com/open_source/?download=curl_724_0_ssl.zip' } `
  else { 'http://curl.haxx.se/download/curl-7.33.0-win64-ssl-sspi.zip' }
 
  $client.DownloadFile( $curlUri, 'curl.zip')
  mkdir "c:\program files\curl"
  unzip-File "curl.zip" "C:\Users\Administrator" "c:\program files\curl"
  if ($Is32Bit)
  {
    $client.DownloadFile( 'http://www.paehl.com/open_source/?download=libssl.zip', 'libssl.zip')
    unzip-File "libssl.zip" "C:\Users\Administrator" "c:\program files\curl"
    del libssl.zip
  }
  SetX Path "${Env:Path};C:\Program Files\Curl" /m
  $Env:Path += ';C:\Program Files\Curl'
  del curl.zip
  Log_Status "Installed Curl from $curlUri and updated path"
}

#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
# Download and Install chocolatey
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

function chocolatey
{
  #chocolatey - standard one line installer doesn't work on Core b/c Shell.Application can't unzip
  if (-not $IsCore)
  {
    Invoke-Expression ((new-object net.webclient).DownloadString('http://bit.ly/psChocInstall'))
  }
  else
  {
    #[Environment]::SetEnvironmentVariable('ChocolateyInstall', 'c:\nuget', [System.EnvironmentVariableTarget]::User)
    #if (![System.IO.Directory]::Exists('c:\nuget')) {[System.IO.Directory]::CreateDirectory('c:\nuget')}
 
    $tempDir = Join-Path $env:TEMP "chocInstall"
    if (![System.IO.Directory]::Exists($tempDir)) {[System.IO.Directory]::CreateDirectory($tempDir)}
    $file = Join-Path $tempDir "chocolatey.zip"
    $client.DownloadFile("http://chocolatey.org/api/v1/package/chocolatey", $file)
 
    unzip-File "chocolatey.zip" $tempDir $tempDir
    Log_Status 'Extracted Chocolatey'
    $chocInstallPS1 = Join-Path (Join-Path $tempDir 'tools') 'chocolateyInstall.ps1'
 
    & $chocInstallPS1
 
    Log_Status 'Installed Chocolatey / Verifying Paths'
  }
}

#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
# Download and Install NSSM
# http://nssm.cc/
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

function NSSM
{
  choco install NSSM
}

#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
# Configure slave.jar to run as service
# http://nssm.cc/
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

function jenkinsslave
{
  nssm install jenkinsslavejar "java" "-jar C:\Windows\Temp\slave.jar"
}


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
  SetX Path "${Env:Path};C:\opscode\chef\bin" /m
  $Env:Path += ';C:\opscode\chef\bin'
  Log_Status "Created chef directory" 
  #	Download Chef.rb and validation key
  Log_Status "Download bucket files"
  Download-Bucket-File "client.rb"  "chefbootstrap-jenkins" $chef_dir
  Download-Bucket-File "validation.pem"  "chefbootstrap-jenkins" $chef_dir
  Download-Bucket-File "knife.rb"  "chefbootstrap-jenkins" $chef_dir
  #Log_Status "Rename Computer to easily identify it on the chef server" 
  #Rename-Computer -NewName JenkinsSlave-${env:computername} -Force
  Log_Status  "Download Chef-client installer..."
  & 'C:\Program Files\Curl\curl.exe' -# -G -k -L https://opscode-omnibus-packages.s3.amazonaws.com/windows/2008r2/x86_64/chef-windows-11.16.2-1.windows.msi -o chef-windows-11.16.2-1.windows.msi
  Log_Status  "Executing Chef installer..."
  Start-Process -FilePath "msiexec.exe" -ArgumentList '/qn /passive /i chef-windows-11.16.2-1.windows.msi ADDLOCAL="ChefClientFeature,ChefServiceFeature" /norestart' -Wait
  del chef-windows-11.16.2-1.windows.msi
  SetX Path "${Env:Path};C:\opscode\chef\embedded\bin" /m
  $Env:Path += ';C:\opscode\chef\embedded\bin'
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
#
# Download and Install freeSSHd
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

function freeSSHd
{
  $freeSShd = 'http://www.freesshd.com/freeSSHd.exe'

  
  $client.DownloadFile( $freeSShd, 'freeSSHd.exe')
  Start-Process -FilePath C:\Users\Administrator\freeSSHd.exe -ArgumentList '/VERYSILENT /NOICON /norestart /SUPPRESSMSGBOXES /LOADINF="%SOFTWARE%\system\freesshd/freesshd.inf"' -Wait
  del freeSSHd.exe
}

#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
# Download and Install freeSSHd
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

function cygwin
{
  $cygwin = if ($Is32Bit) { 'https://cygwin.com/setup-x86.exe' } `
  else { 'https://cygwin.com/setup-x86_64.exe' }

  
  $client.DownloadFile( $cygwin, 'cygwin-setup.exe')
  Start-Process -FilePath C:\Users\Administrator\freeSSHd.exe -ArgumentList '/VERYSILENT /NOICON /norestart /SUPPRESSMSGBOXES /LOADINF="%SOFTWARE%\system\freesshd/freesshd.inf"' -Wait
  del freeSSHd.exe
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


#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
#	Section	:	Script begins here
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

Log_Status "Started bootstrapping EC2 Instance"


#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
#	Section	:	Configuration
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

#Log_Status  "Disabling User Access Control (UAC)" 
#Disable-UAC
#Log_Status "User Access Control (UAC) has been disabled" 



#Log_Status  "Configuring Firewall" 
#Config-Firewall
#Log_Status "Firewall Configured" 



Log_Status "Disabling password complexity requirements" 
Disable-PassComplexity
Log_Status "password complexity requirements disabled" 



Log_Status "Changing Administrator Pass, Creating jenkins user and add to admin group"
UserAccounts
Log_Status "Administrator Pass changed, jenkins user created and added to admin group"



Log_Status  "Disabling IE Enhanced Security Configuration..." 
Disable-IEESC
Log_Status "IE Enhanced Security Configuration (ESC) has been disabled." 



#Log_Status "Setting home page for IE" 
#Set-IEHomePage "http://www.google.co.uk"
#Log_Status "Homepage Set" 



Log_Status "Configuring Powershell" 
PS-CONFIG
Log_Status "Powershell Configured" 



Log_Status "Disabling Windows Updates" 
Disable-WINUPDATES
Log_Status "Windows Updates Disabled" 



Log_Status "Disabling Shutdown Tracker" 
Disable-Shutdown-Tracker
Log_Status "Shutdown Tracker has been disabled Disabled" 



#Log_Status "Downloading and Installing 7-ZIP" 
#SEVENZIP
#Log_Status "Finished installing 7-zip" 



Log_Status "Downloading and Installing C++ Redistributable Package 2010" 
VCREDIST
Log_Status "Finished installing C++ Redistributable Package 2010"



Log_Status "Downloading and Installing JRE" 
JRE
Log_Status "Finished installing JRE"



Log_Status "Downloading and Installing curl" 
CURL-CONFIG
Log_Status "Finished installing curl" 



Log_Status  "Installing chocolatey" 
chocolatey
Log_Status "chocolatey Installed" 



#Log_Status  "Installing NSSM" 
#NSSM
#Log_Status "Installed NSSM" 



Log_Status "Enabling and Configuring WINRM" 
EnableConfigureWINRM
Log_Status "WINRM Enabled and Configured" 

#wait a bit, it's windows after all


Log_Status "Downloading and Installing Chef Client" 
CHEF
Log_Status "Finished installing Chef Client" 


#Log_Status "Downloading and Installing freeSSHd" 
#freeSSHd
#Log_Status "Finished installing freeSSHd"



#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

Log_Status "Finished bootstrapping"

#Log_Status  "Creating jenkinsslavejar service" 
#jenkinsslave
#Log_Status "jenkinsslavejar service created" 

#wait a bit, it's windows after all
#Start-Sleep -m 10000

#Write-Host "Press any key to reboot and finish image configuration"
#[void]$host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
 

#Restart-Computer
