#iex ((New-Object System.Net.WebClient).DownloadString('url ps1 goes here'))

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