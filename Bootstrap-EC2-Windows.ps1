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


$systemPath = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
$sysNative = [IO.Path]::Combine($env:windir, "sysnative")
#http://blogs.msdn.com/b/david.wang/archive/2006/03/26/howto-detect-process-bitness.aspx
$Is32Bit = (($Env:PROCESSOR_ARCHITECTURE -eq 'x86') -and ($Env:PROCESSOR_ARCHITEW6432 -eq $null))
Add-Content $log -value "Is 32-bit [$Is32Bit]"

#http://msdn.microsoft.com/en-us/library/ms724358.aspx
$coreEditions = @(0x0c,0x27,0x0e,0x29,0x2a,0x0d,0x28,0x1d)
$IsCore = $coreEditions -contains (Get-WmiObject -Query "Select OperatingSystemSKU from Win32_OperatingSystem" | Select -ExpandProperty OperatingSystemSKU)
Add-Content $log -value "Is Core [$IsCore]"

# move to home, PS is incredibly complex :)
cd $Env:USERPROFILE
Set-Location -Path $Env:USERPROFILE
[Environment]::CurrentDirectory=(Get-Location -PSProvider FileSystem).ProviderPath


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
winrm quickconfig -q
winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="512"}'
winrm set winrm/config '@{MaxTimeoutms="1800000"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
# needed for windows to manipulate centralized config files which live of a share. Such as AppFabric.
winrm set winrm/config/service/auth '@{CredSSP="true"}';
Log_Status "Attempting to enable built in 5985 firewall rule";
netsh advfirewall firewall add rule name="jenkins-Windows Remote Management (HTTP-In)" dir=in action=allow enable=yes profile=any protocol=tcp localport=5985 remoteip=any;
netsh advfirewall firewall add rule name="jenkins-Windows Remote Management (HTTPS-In)" dir=in action=allow enable=yes profile=any protocol=tcp localport=5986 remoteip=any;
netsh advfirewall firewall set rule name="Windows Remote Management (HTTP-In)" profile=public protocol=tcp localport=5985 new remoteip=any;
Log_Status "Adding custom firewall rule for 5985"
netsh advfirewall firewall add rule name="WinRM 5985" protocol=TCP dir=in localport=5985 action=allow
netsh advfirewall firewall add rule name="WinRM 5986" protocol=TCP dir=in localport=5986 action=allow
Log_Status  "Opened 5985 & 5986 for incoming winrm"
Set-Service winrm -startuptype "auto"
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
}


#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#	Function:	Set-IE-HomePage
#
#	Comments:	This function is intended to set the home page for Internet Explorer.
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
function Set-IE-HomePage ($URL)
{
set-ItemProperty -path 'HKCU:\Software\Microsoft\Internet Explorer\main' -name "Start Page" -value $URL
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

Log_Status  "Disabling User Access Control (UAC)" 
Disable-UAC
Log_Status "User Access Control (UAC) has been disabled" 



Log_Status  "Configuring Firewall" 
Config-Firewall
Log_Status "Firewall Configured" 



Log_Status "Changing Administrator Pass, Creating jenkins user and add to admin group"
UserAccounts
Log_Status "Administrator Pass changed, jenkins user created and added to admin group"


Log_Status  "Disabling IE Enhanced Security Configuration..." 
Disable-IEESC
Log_Status "IE Enhanced Security Configuration (ESC) has been disabled." 



Log_Status "Setting home page for IE" 
Set-IE-HomePage "http://www.google.co.uk"
Log_Status "Homepage Set" 



Log_Status "Disabling Windows Updates" 
Disable-WINUPDATES
Log_Status "Windows Updates Disabled" 



Log_Status "Disabling Shutdown Tracker" 
Disable-Shutdown-Tracker
Log_Status "Shutdown Tracker has been disabled Disabled" 



Log_Status "Disabling password complexity requirements" 
Disable-PassComplexity
Log_Status "password complexity requirements disabled" 



Log_Status "Enabling and Configuring WINRM" 
EnableConfigureWINRM
Log_Status "WINRM Enabled and Configured" 


#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
#	Section	:	Create folders
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-


# Create a new scripts directory

Log_Status  "Creating directories.."

$chef_dir = "C:\chef"
if (!(Test-Path -path $chef_dir))
{
mkdir $chef_dir
}
Write-host "Created chef directory"

# Create a new cookbooks directory

$cookbook_dir = "C:\chef\cookbooks"
if (!(Test-Path -path $cookbook_dir))
{
mkdir $cookbook_dir
}
Write-host "Created cookbooks directory"



# Create a new installers directory

$installer_dir = "C:\installers"
if (!(Test-Path -path $installer_dir ))
{
mkdir $installer_dir 
}
Write-host "Created installers directory"

#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-



#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

Log_Status "Finished bootstrapping"


#wait a bit, it's windows after all
Start-Sleep -m 10000

#Write-Host "Press any key to reboot and finish image configuration"
#[void]$host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
 
#Stop-Process -Name Explorer
#Restart-Computer
