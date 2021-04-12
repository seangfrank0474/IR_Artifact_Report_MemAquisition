If (Get-Content $env:windir\system32\drivers\etc\hosts){
    "Get-Content $env:windir\system32\drivers\etc\hosts"
    "`n"
    Get-Content $env:windir\system32\drivers\etc\hosts
    "`n"
    "#"*80
}

If (Get-Content $env:windir\system32\drivers\etc\networks){
"`n"
    "Get-Content $env:windir\system32\drivers\etc\networks"
    "`n"
    Get-Content $env:windir\system32\drivers\etc\networks
    "#"*80
}

# Dumping the firewall information
#"Firewall State: netsh firewall show state"
#netsh firewall show state | ConvertTo-Html
#echo "`n`n`nFirewall Config: firewall show config"
#netsh firewall show config | Format-List
#"`n`n`nFirewall Dump: netsh dump"
#netsh dump

#iex ((New-Object System.Net.WebClient).DownloadString('url ps1 goes here'))

# Temp Directory Listing
foreach($userpath in (Get-WmiObject win32_userprofile | Select-Object -ExpandProperty localpath)) {
    if (Test-Path(($userpath + "\AppData\Local\Temp\"))) {
        Get-ChildItem -Force ($userpath + "\AppData\Local\Temp\*") | Select FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc
    }
}

(Get-ChildItem C:\Users).Name

C:\ProgramData\Microsoft\Windows\Start Menu\Programs
C:\Users\<User>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs

Get-Item -Path Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run

The following run keys are created by default on Windows systems:

    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce

The following Registry keys can be used to set startup folder items for persistence:

    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
    HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
    HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders

The following Registry keys can control automatic startup of services during boot:

    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices
    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices

Using policy settings to specify startup programs creates corresponding values in either of two Registry keys:

    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run

 Invoke-Command -ComputerName $Mycomputer_name -ScriptBlock {cmd.exe /C
"C:\temp\winpmem.exe $Mycomputer_name.raw" } -Credential $MySecureCreds

EventLogs
#  This script exports consolidated and filtered event logs to CSV
#  Author: Michael Karsyan, FSPro Labs, eventlogxp.com (c) 2016
#

Set-Variable -Name EventAgeDays -Value 7     #we will take events for the latest 7 days
Set-Variable -Name CompArr -Value @("SERV1", "SERV2", "SERV3", "SERV4")   # replace it with your server names
Set-Variable -Name LogNames -Value @("Application", "System")  # Checking app and system logs
Set-Variable -Name EventTypes -Value @("Error", "Warning")  # Loading only Errors and Warnings
Set-Variable -Name ExportFolder -Value "C:\TEST\"


$el_c = @()   #consolidated error log
$now=get-date
$startdate=$now.adddays(-$EventAgeDays)
$ExportFile=$ExportFolder + "el" + $now.ToString("yyyy-MM-dd---hh-mm-ss") + ".csv"  # we cannot use standard delimiteds like ":"

foreach($comp in $CompArr)
{
  foreach($log in $LogNames)
  {
    Write-Host Processing $comp\$log
    $el = get-eventlog -ComputerName $comp -log $log -After $startdate -EntryType $EventTypes
    $el_c += $el  #consolidating
  }
}
$el_sorted = $el_c | Sort-Object TimeGenerated    #sort by time
Write-Host Exporting to $ExportFile
$el_sorted|Select EntryType, TimeGenerated, Source, EventID, MachineName | Export-CSV $ExportFile -NoTypeInfo  #EXPORT
Write-Host Done!

Chrome
$Path = "$Env:systemdrive\Users\s839160\AppData\Local\Google\Chrome\User Data\Default\History"
        if (-not (Test-Path -Path $Path)) {
            Write-Verbose "[!] Could not find Chrome History for username: $UserName"
        }
        $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
        $Value = Get-Content -Path "$Env:systemdrive\Users\s839160\AppData\Local\Google\Chrome\User Data\Default\History"|Select-String -AllMatches $regex |% {($_.Matches).Value} |Sort -Unique
        $Value | ForEach-Object {
            $Key = $_
            if ($Key -match $Search){
                New-Object -TypeName PSObject -Property @{
                    User = $UserName
                    Browser = 'Chrome'
                    DataType = 'History'
                    Data = $_
                }
            }
        } 
FireFox
$Path = "$Env:systemdrive\Users\s839160\AppData\Roaming\Mozilla\Firefox\Profiles\"
        if (-not (Test-Path -Path $Path)) {
            Write-Verbose "[!] Could not find FireFox History for username: $UserName"
        }
        else {
            $Profiles = Get-ChildItem -Path "$Path\*.default\" -ErrorAction SilentlyContinue
            $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
            $Value = Get-Content $Profiles\places.sqlite | Select-String -Pattern $Regex -AllMatches |Select-Object -ExpandProperty Matches |Sort -Unique
            $Value.Value |ForEach-Object {
                if ($_ -match $Search) {
                    ForEach-Object {
                    New-Object -TypeName PSObject -Property @{
                        User = 's839160'
                        Browser = 'Firefox'
                        DataType = 'History'
                        Data = $_
                        }    
                    }
                }
            }
        }
IE
$Null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
        $Paths = Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }

        ForEach($Path in $Paths) {

            $User = ([System.Security.Principal.SecurityIdentifier] $Path.PSChildName).Translate( [System.Security.Principal.NTAccount]) | Select -ExpandProperty Value

            $Path = $Path | Select-Object -ExpandProperty PSPath

            $UserPath = "$Path\Software\Microsoft\Internet Explorer\TypedURLs"
            if (-not (Test-Path -Path $UserPath)) {
                Write-Verbose "[!] Could not find IE History for SID: $Path"
            }
            else {
                Get-Item -Path $UserPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $Key = $_
                    $Key.GetValueNames() | ForEach-Object {
                        $Value = $Key.GetValue($_)
                        if ($Value -match $Search) {
                            New-Object -TypeName PSObject -Property @{
                                User = 's839160'
                                Browser = 'IE'
                                DataType = 'History'
                                Data = $Value
                            }
                        }
                    }
                }
            }
        }

StartMenu Stuff
$get_user_start_array = @()
$get_progdata_strt = (Get-ChildItem C:\ProgramData\Microsoft\Windows\Start` Menu\Programs | Select-Object BaseName, FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc, Extension, Attributes | ConvertTo-Html -As Table -Fragment -PreContent '<h3>Program Data Start Menu</h3>' | Out-String)
$get_user_start_array += $get_progdata_strt
$get_user_array = (Get-ChildItem C:\Users).Name
foreach ($user_in in $get_user_array) {
    $get_strt = (Get-ChildItem C:\Users\$user_in\AppData\Roaming\Microsoft\Windows\Start` Menu\Programs -ErrorAction SilentlyContinue | Select-Object BaseName, FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc, Extension, Attributes)
    $precontent = ‘<h3>' + $user_in + ' Start Menu Info</h3>’
    $user_start = $get_strt | ConvertTo-Html -As Table -Fragment -PreContent $precontent | Out-String
    $get_user_start_array += $user_start
}


$htmlParams = @{
       PreContent = "
          <pre>
              Host: $ENV:ComputerName 
              Date: $(get-date -UFormat "%Y-%m-%d Time: %H:%M:%S")
          </pre>"
        PostContent = $get_user_start_array
    }
    $ir_report_full_path = "\ArtifactReport" + $(get-date -UFormat "%Y-%m-%dT%H-%M-%S") + ".html"
    ConvertTo-HTML @htmlParams | Out-File $ir_report_full_path
    Invoke-Item $ir_report_full_path

foreach($userpath in (Get-WmiObject win32_userprofile | Select-Object -ExpandProperty localpath)) {
    if (Test-Path(($userpath + "\AppData\Local\Temp\"))) {
        Get-ChildItem -Force ($userpath + "\AppData\Local\Temp\*") | Select-Object BaseName, FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc, Extension, Attributes
    }
    if (Test-Path(($userpath + "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"))) {
        Get-ChildItem -Force ($userpath + "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\*") | Select-Object BaseName, FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc, Extension, Attributes
    }
    if (Test-Path(($userpath + "\Downloads"))) {
        Get-ChildItem -Force ($userpath + "\Downloads\*") | Select-Object BaseName, FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc, Extension, Attributes
    }
}

Prefetch

$pfconf = (Get-ItemProperty "hklm:\system\currentcontrolset\control\session manager\memory management\prefetchparameters").EnablePrefetcher 
Switch -Regex ($pfconf) {
    "[1-3]" {
        $o = "" | Select-Object FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc
        ls $env:windir\Prefetch\*.pf | % {
            $o.FullName = $_.FullName;
            $o.CreationTimeUtc = Get-Date($_.CreationTimeUtc) -format o;
            $o.LastAccesstimeUtc = Get-Date($_.LastAccessTimeUtc) -format o;
            $o.LastWriteTimeUtc = Get-Date($_.LastWriteTimeUtc) -format o;
            $o
        }
    }
    default {
        Write-Output "Prefetch not enabled on ${env:COMPUTERNAME}."
    }
}
