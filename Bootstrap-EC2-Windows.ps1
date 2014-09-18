# Inject this as user-data of a Windows 2012 AMI, like this (edit the userPassword to your needs):
#
# <powershell>
# Set-ExecutionPolicy Unrestricted
# icm $executioncontext.InvokeCommand.NewScriptBlock((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/ebrahim-moshaya/ec2bootstrap/b990abc1db41bc6a610018245f079511bcfa753c/Bootstrap-EC2-Windows.ps1')) -ArgumentList "userPassword"
# </powershell>
#

param(
[Parameter(Mandatory=$true)]
[string]
$userPassword
)

# Set Powershell execution policy to Bypass
Set-ExecutionPolicy Bypass -force
Write-host "Set execution policy to Bypass -force"
Set-ExecutionPolicy Unrestricted



Start-Transcript -Path 'c:\bootstrap-transcript.txt' -Force
$log = 'c:\Bootstrap.txt'

while (($userPassword -eq $null) -or ($userPassword -eq ''))
{
$AdminPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((Read-Host "Enter a non-null / non-empty Administrator password" -AsSecureString)))
}










netsh advfirewall set currentprofile state off


# Step 1: Disable UAC
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -PropertyType DWord -Value 0 -Force | Out-Null
Write-Host "User Access Control (UAC) has been disabled." -ForegroundColor Green

$bootstrapqueue = "https://sqs.eu-west-1.amazonaws.com/123412341234/BootstrapQueue"



#Disable password complexity requirements
"[System Access]" | out-file c:\delete.cfg
"PasswordComplexity = 0" | out-file c:\delete.cfg -append
"[Version]" | out-file c:\delete.cfg -append
'signature="$CHICAGO$"' | out-file c:\delete.cfg -append
secedit /configure /db C:\Windows\security\new.sdb /cfg c:\delete.cfg /areas SECURITYPOLICY;

# Create a user with Their password, add to Admin group
net user Administrator $password;
net user /add $user $password;
net localgroup Administrators /add $user;

# Get the instance ready for Chef bootstrapper
winrm quickconfig -q
winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="512"}'
winrm set winrm/config '@{MaxTimeoutms="1800000"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
# needed for windows to manipulate centralized config files which live of a share. Such as AppFabric.
winrm set winrm/config/service/auth '@{CredSSP="true"}';
write-host 'Attempting to enable built in 5985 firewall rule';
netsh advfirewall firewall set rule name="Windows Remote Management (HTTP-In)" profile=public protocol=tcp localport=5985 new remoteip=any;
write-host 'Adding custom firewall rule for 5985';
netsh advfirewall firewall add rule name="WinRM 5985" protocol=TCP dir=in localport=5985 action=allow
netsh advfirewall firewall add rule name="WinRM 5986" protocol=TCP dir=in localport=5986 action=allow
Write-Host "Opened 5985 for incoming winrm"
netsh advfirewall firewall add rule name="Opscode-Windows Remote Management (HTTP-In)" dir=in action=allow enable=yes profile=any protocol=tcp localport=5985 remoteip=any;
Set-Service winrm -startuptype "auto"
netsh advfirewall firewall set rule group="network discovery" new enable=yes
netsh firewall add portopening TCP 80 "Windows Remote Management";

# Disable password complexity requirements
$seccfg = [IO.Path]::GetTempFileName()
secedit /export /cfg $seccfg
(Get-Content $seccfg) | Foreach-Object {$_ -replace "PasswordComplexity\s*=\s*1", "PasswordComplexity=0"} | Set-Content $seccfg
secedit /configure /db $env:windir\security\new.sdb /cfg $seccfg /areas SECURITYPOLICY
del $seccfg


# Disable the shutdown tracker
# Reference: http://www.askvg.com/how-to-disable-remove-annoying-shutdown-event-tracker-in-windows-server-2003-2008/
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability")) {
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability"
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -PropertyType DWord -Value 0 -Force -ErrorAction continue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonUI" -PropertyType DWord -Value 0 -Force -ErrorAction continue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonUI" -Value 0
Write-Host "Shutdown Tracker has been disabled." -ForegroundColor Green

# Disable Automatic Updates
# Reference: http://www.benmorris.me/2012/05/1st-test-blog-post.html
$AutoUpdate = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
$AutoUpdate.NotificationLevel = 1
$AutoUpdate.Save()
Write-Host "Windows Update has been disabled." -ForegroundColor Green

# Step 8: Disable Windows Firewall
#&netsh "advfirewall" "set" "allprofiles" "state" "off"
#Write-Host "Windows Firewall has been disabled." -ForegroundColor Green

#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#	Function:	Disable-IEESC
#
#	Comments:	This function is intended to disable IE Enhance Security Configuration, making it easier for users to access the internet via their browser.
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
function Disable-IEESC
{
$AdminKey = “HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}”
$UserKey = “HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}”
Set-ItemProperty -path $AdminKey -name “IsInstalled” -value 0
Set-ItemProperty -path $UserKey -name “IsInstalled” -value 0
Stop-Process -Name Explorer
Write-Host “IE Enhanced Security Configuration (ESC) has been disabled.” -ForegroundColor Green
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

Add-Content "`n" + $message -Path c:\bootstrap.log

Send-SQSMessage -QueueUrl $bootstrapqueue -Region "eu-west-1" -MessageBody $message

}

#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
#	Section	:	Script begins here
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-

Log_Status "Started bootstrapping"



#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-
#
#	Section	:	Configuration
#
#	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-	-


Log_Status  "Disabling IE Enhanced Security Configuration..." 

Disable-IEESC

Log_Status "Disabled IE Enhanced Security Configuration" 


Log_Status "Setting home page for IE" 

Set-IE-HomePage "http://www.google.co.uk"


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
