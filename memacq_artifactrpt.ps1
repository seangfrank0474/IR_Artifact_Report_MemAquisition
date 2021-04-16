<#
.SYNOPSIS
    Pull common artifacts from a host during an incident response

.DESCRIPTION
    IR-Artifact-Acquision test to see if there is enough disk space to pull a memory image and creates html formated artifact reports. 
    It will automatically create directory structure on the disk that has the biggest space even if it is not pulling a memory image. 

.PARAMETER all
    This will find a suitable drive with enough freespace. 
    Create the paths where the image, reports and event logs will be saved. 
    Then acquire a memory image, save artifact data in an HTML report and specific event logs in a json format. 

.PARAMETER image
    This will find a suitable drive with enough freespace. 
    Create the path where the image will be saved. 
    Then acquire a memory image only. 

.PARAMETER report
    This will find a suitable drive with enough freespace. 
    Create the path where the reports will be saved. 
    Then run commands to collect artifacts in an HTML report.
    
.PARAMETER event
    This will find a suitable drive with enough freespace. 
    Create the path where the event logs will be saved. 
    Then run commands to collect specific event logs in a json format. 

.EXAMPLE
     Need to run in elevated privileges
     .\memacq_artifactrpt.ps1 both

.INPUTS
    String

.NOTES
    Author:  Sean G. Frank, Village Idiot
#>

function IR-Artifact-Acquisition-Setup($triageType) {
     
    # Setup IR Artifact directory. Looking for the drive with the most free space.
    $dsk_id_array = (Get-CimInstance -Class CIM_LogicalDisk).DeviceId
    $dsk_free_array_bytes = (Get-CimInstance -Class CIM_LogicalDisk).FreeSpace
    $physical_mem_bytes = (Get-CimInstance -Class win32_ComputerSystem).TotalPhysicalMemory
    $physical_mem_gb = [math]::Round($physical_mem_bytes/1024/1024/1024)
    $dsk_id_cnt = $dsk_id_array.Count
    $drv_viability = $physical_mem_gb * 2
    $dsk_free_array_gb = @()
    # Creating an array to be used to find a viable drive to create a directory for image acquision and artifact reports.
    for ($i = 0; $i -lt $dsk_id_cnt; $i++){
        $dsk_free_gb = [math]::Round($dsk_free_array_bytes[$i]/1024/1024/1024)
        $dsk_free_array_gb += $dsk_free_gb
    }
    # Finding the drive with the maximum free space in the array that was created in the previous for loop. If none is found it will exit the script.
    $dsk_free_max = ($dsk_free_array_gb | measure -Maximum).Maximum
    for ($i = 0; $i -lt $dsk_id_cnt; $i++){
        if ( ($triageType -eq 'all') -or ($triageType -eq 'image') ){
            if (($dsk_free_array_gb[$i] -eq $dsk_free_max) -and ($dsk_free_array_gb[$i] -ge $drv_viability)){
                $viable = 1
                $dsk_to_use = $dsk_id_array[$i]
                $screen_output = "[+] {0} Found disk that meets the criteria for memory acquisition/reports/events. Disk to be used: {1} with freespace: {2} GB and phyisical memory to image: {3} GB" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $dsk_to_use, $dsk_free_max, $physical_mem_gb
                Write-Output $screen_output
                break
                }
            else {
                $viable = 0 
                $dsk_to_use = $dsk_id_array[$i]
                $screen_output = "[+] {0} No disk(s) that meet the criteria for memory acquisition/reports/events. Disk: {1} with freespace: {2} GB and phyisical memory to image: {3} GB" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $dsk_to_use, $dsk_free_array_gb[$i], $physical_mem_gb
                Write-Output $screen_output
                }
            }
        elseif ( $triageType -eq 'report' -or $triageType -eq 'event' ){
            if (($dsk_free_array_gb[$i] -eq $dsk_free_max) -and ($dsk_free_array_gb[$i] -gt $physical_mem_gb)){
                $viable = 1
                $dsk_to_use = $dsk_id_array[$i]
                $screen_output = "[+] {0} Found disk that meets the criteria for memory acquisition/reports/events. Disk to be used: {1} with freespace: {2} GB and phyisical memory to image: {3} GB" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $dsk_to_use, $dsk_free_max, $physical_mem_gb
                Write-Output $screen_output
                break
                }
            else {
                $viable = 0 
                $dsk_to_use = $dsk_id_array[$i]
                $screen_output = "[+] {0} No disk(s) that meet the criteria for memory acquisition/reports/events. Disk: {1} with freespace: {2} GB and phyisical memory to image: {3} GB" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $dsk_to_use, $dsk_free_array_gb[$i], $physical_mem_gb
                Write-Output $screen_output
                }
            }
        else {
            $screen_output = "[+] {0} Triage type is unknown, please try again. Variable used: {1}" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $triageType
            Write-Output $screen_output
            exit 
            }
    }    
    if ($viable -eq 1){
        $ir_triage_path = $dsk_to_use + ':\IRTriage'
        $ir_triage_path_host = $ir_triage_path + '\' + $ENV:ComputerName
        $ir_triage_path_image = $ir_triage_path_host + '\image'
        $ir_triage_path_report = $ir_triage_path_host + '\report'
        $ir_triage_path_event = $ir_triage_path_host + '\event'
        $ir_triage_path_return = @($ir_triage_path_image, $ir_triage_path_report, $ir_triage_path_event)
        if (!(Test-Path -Path $ir_triage_path)){
            New-Item -ItemType directory -Path $ir_triage_path | Out-Null
            New-Item -ItemType directory -Path $ir_triage_path_host | Out-Null
            New-Item -ItemType directory -Path $ir_triage_path_image | Out-Null
            New-Item -ItemType directory -Path $ir_triage_path_report | Out-Null
            New-Item -ItemType directory -Path $ir_triage_path_event | Out-Null
            $screen_output = "[+] {0} IR Triage and Acquisition paths have been setup." -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S")
            Write-Output $screen_output
        }
        else{
            $screen_output = "[+] {0} IR Triage and Acquision paths have been previously setup and is ready for the acquisition process." -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S")
            Write-Output $screen_output
        }    
    }
    else { 
        $screen_output = "[+] {0} No viable drive(s) have been found for memory acquisition and/or reports. Exiting the script" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S")
        Write-Output $screen_output
        exit
        }
    return $ir_triage_path_return
}

function IR-Artifact-Acquisition-Image($ir_image_var) {
    $script_root_path = (Get-Item $PSScriptRoot).FullName
    $winpmem_path = $script_root_path + "\winpmem.exe"
    if (Test-Path -Path $winpmem_path) {
        $mem_acq_file = $ENV:ComputerName + '_mem_img_' + $(get-date -UFormat "%Y_%m_%dT%H_%M_%S") + '.raw'
        $mem_img_full_path = $ir_image_var + '\' + $mem_acq_file
        $winpmem_full_cmd =  'cmd.exe /C "' + $winpmem_path + ' ' + $mem_img_full_path + '"'
        $screen_output = "[+] {0} IR Triage and Acquisition is going to acquire a memory image this will take awhile, so go get a cup off coffee. image path: {1} filename: {2}" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_image_var, $mem_acq_file
        Write-Output $screen_output 
        #Invoke-Command -ComputerName $Mycomputer_name -ScriptBlock {$winpmem_full_cmd}
        $screen_output = "[+] {0} IR Triage and Acquisition memory acquisition is complete. Image can be found here: {1}" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $mem_img_full_path
        Write-Output $screen_output   
    }

    #$screen_output = "[+] IR Triage and Acquisition is going to acquire a memory image this will take awhile so go get a cup off coffee." -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $triageType
    #Write-Output $screen_output
    #Invoke-Command -ComputerName $Mycomputer_name -ScriptBlock {cmd.exe /C "C:\temp\winpmem.exe $Mycomputer_name.raw" } -Credential $MySecureCreds
#$screen_output = "[+] {0} Triage type is unknown. (Default variable: report - Valid variables: image,report,both) Variable used: {1}. Script exiting." -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $triageType
#    Write-Output $screen_output
}

function IR-Artifact-Acquisition-Environment($ir_report_var) {  
    $create_report = 'env'  
    # Host OS Environment Artifacts converted into html fragments
    $get_proc = Get-WmiObject -Class Win32_Processor -ErrorAction SilentlyContinue | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3>Processor Info</h3>’ -Property Name, Caption, Manufacturer, MaxClockSpeed, SocketDesignation | Out-String
    $get_bios = Get-WmiObject -Class Win32_Bios -ErrorAction SilentlyContinue | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3>BIOS Info</h3>’ -Property Name, Manufacturer, Version, SMBIOSBIOSVersion, SerialNumber | Out-String
    $get_os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3>OS Info</h3>’ -Property Organization, RegisteredUser, Version, BuildNumber, SerialNumber, SystemDirectory | Out-String
    $get_drv = Get-WmiObject -Class Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3>Drive Info</h3>’ -Property DeviceID, DriveType, ProviderName, Size, FreeSpace | Out-String
    $get_env = Get-ChildItem ENV: -ErrorAction SilentlyContinue | ConvertTo-Html -As TABLE -Fragment -PreContent ‘<h3>Environment Info</h3>’ -Property Name, Value| Out-String
    $get_local_user = Get-LocalUser | ConvertTo-Html -As Table -PreContent ‘<h3>Local Users Info</h3>’ -Fragment -Property Name, FullName, SID, Description, LastLogon, PasswordRequired, PasswordLastSet, PasswordExpires, UserMayChangePassword, Enabled | Out-String
    $get_local_admins = & net localgroup administrators | Select-Object -Skip 6 | ? {
    $_ -and $_ -notmatch "The command completed successfully" 
    } | % {
    $o = "" | Select-Object Account
    $o.Account = $_
    $o
    } | ConvertTo-Html -As Table -PreContent ‘<h3>Local Admin Members Info</h3>’ -Fragment -Property Account | Out-String
    $post_output = @($get_proc, $get_bios, $get_os, $get_drv, $get_env, $get_local_user, $get_local_admins)
    $report_array = @($ir_report_var, $create_report, $post_output)
    IR-Artifact-Acquisition-Report-Creation($report_array)
}

function IR-Artifact-Acquisition-Network($ir_report_var) {
    $create_report = 'net'
    # Host Network Config Artifacts
    # Host Network Config Artifacts Arrays
    $net_adpt_result = @()
    $net_cfg_result = @()
    $net_rt_result = @()
    $net_bnd_result = @()
    $net_arp_result = @()
    # Host Network Config Artifacts Properties
    $get_net_adpt = (Get-NetAdapter | Select-Object -Property Name, ifIndex, InterfaceDescription, MacAddress, Status)
    $get_net_cfg = (Get-NetIPConfiguration | Select-Object -Property InterfaceIndex, InterfaceAlias,Ipv4Address, DNSServer, DefaultIPGateway)
    $get_net_rt = (Get-NetRoute | Select-Object -Property ifIndex, DestinationPrefix, NextHop, RouteMetric)
    $get_net_bnd = (Get-NetAdapterBinding | Select-Object -Property Name, DisplayName, ComponentID, Enables)
    $get_net_arp = (Get-NetNeighbor | Select-Object -Property ifIndex, IPAddress, LinkLayerAddress, State)
    # Host Network Config Artifacts counts to iterate over for loop 
    $net_adpt_cnt = ($get_net_adpt.ifIndex | measure).Count
    $net_cfg_cnt = ($get_net_cfg.InterfaceIndex | measure).Count
    $net_rt_cnt = ($get_net_rt.ifIndex | measure).Count
    $net_bnd_cnt = ($get_net_bnd.Name | measure).Count
    $net_arp_cnt = ($get_net_arp.ifIndex | measure).Count
    # Host Network Config Artifacts for loops to generate the result arrays
    for ($i = 0; $i -lt $net_adpt_cnt; $i++){ 
        $net_adpt_result += New-Object -TypeName PSCustomObject -Property ([ordered]@{
            'Name' = $get_net_adpt[$i].Name
            'Interface' = $get_net_adpt[$i].ifIndex -join ','
            'Description' = $get_net_adpt[$i].InterfaceDescription -join ','
            'MacAddress' = $get_net_adpt[$i].MacAddress -join ','
            'Status' = $get_net_adpt[$i].Status -join ','
             })
    }
    for ($i = 0; $i -lt $net_cfg_cnt; $i++){ 
        $net_cfg_result += New-Object -TypeName PSCustomObject -Property ([ordered]@{
            'Name' = $get_net_cfg[$i].InterfaceAlias
            'Interface' = $get_net_cfg[$i].InterfaceIndex -join ','
            'IPAdress' = $get_net_cfg[$i].Ipv4Address -join ','
            'DNSServer' = ($get_net_cfg[$i].DNSServer | Select-Object -ExpandProperty ServerAddresses) -join ','
            })
    }
    for ($i = 0; $i -lt $net_rt_cnt; $i++){ 
        $net_rt_result += New-Object -TypeName PSCustomObject -Property ([ordered]@{
            'Interface' = $get_net_rt[$i].ifIndex 
            'DestinationPrefix' = $get_net_rt[$i].DestinationPrefix -join ','
            'NextHop' = $get_net_rt[$i].NextHop -join ','
            'RouteMetric' = $get_net_rt[$i].RouteMetric -join ','
            })
    }
    for ($i = 0; $i -lt $net_bnd_cnt; $i++){ 
        $net_bnd_result += New-Object -TypeName PSCustomObject -Property ([ordered]@{
            'Name' = $get_net_bnd[$i].Name 
            'DisplayName' = $get_net_bnd[$i].DisplayName -join ','
            'ComponentID' = $get_net_bnd[$i].ComponentID -join ','
            'Status' = $get_net_bnd[$i].Enables -join ','
            })
    }
    for ($i = 0; $i -lt $net_arp_cnt; $i++){ 
        $net_arp_result += New-Object -TypeName PSCustomObject -Property ([ordered]@{
            'Interface' = $get_net_arp[$i].ifIndex 
            'IPAddress' = $get_net_arp[$i].IPAddress -join ','
            'MACAddress' = $get_net_arp[$i].LinkLayerAddress -join ','
            'State' = $get_net_arp[$i].State -join ','
            })
    }
    $files_array = @()
    $fileline = @()
    $host_net_array = @()
    If (Get-Content $env:windir\system32\drivers\etc\hosts){
        $get_hosts_file = $env:windir + "\system32\drivers\etc\hosts"
        $files_array += $get_hosts_file
        $html_prop = "Host File: " + $env:windir + "\system32\drivers\etc\hosts"
        $obj_name = "HostFile"
    }
    If (Get-Content $env:windir\system32\drivers\etc\networks){
        $get_network_file = $env:windir + "\system32\drivers\etc\networks"
        $files_array += $get_network_file
        $html_prop = "Host File: " + $env:windir + "\system32\drivers\etc\networks"
        $obj_name = "NetworkFile"
    }
    Foreach ($files in $files_array) {
        $get_file_content = Get-Content $files
        Foreach ($line in $get_file_content) {
            $file_obj = New-Object -TypeName PSObject
            Add-Member -InputObject $file_obj -Type NoteProperty -Name $obj_name -Value $line
            $fileline += $file_obj
        }
            if ($files -eq $get_hosts_file) {
                $host_net_array += $fileline | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3>Host File Info</h3>’ -Property $obj_name | Out-String
            }  
            if ($files -eq $get_network_file) {
                $host_net_array += $fileline | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3>Nework File Info</h3>’ -Property $obj_name | Out-String
            }
    }
    $fw_state = netsh firewall show state
    $fw_config = netsh firewall show config
    $fw_dump = netsh dump
    $fw_cmd_array = @($fw_state, $fw_config, $fw_dump)
    $fw_line = @()
    Foreach ($fw_cmd in $fw_cmd_array) {
        $fw_cmd | Out-Null
        Foreach ($fw_cmd_line in $fw_cmd) {
            $cmd_obj = New-Object -TypeName PSObject
            Add-Member -InputObject $cmd_obj -Type NoteProperty -Name HostFirewall -Value $fw_cmd_line
            $fw_line += $cmd_obj
        }
    
    }
    $proc_net_array = @{}
    Get-Process -IncludeUserName | ForEach-Object {
        $proc_net_array[$_.Id] = $_
        }
    $net_con = Get-NetTCPConnection |
        Select-Object LocalAddress, LocalPort, RemoteAddress,
            RemotePort, State, CreationTime,
            @{Name="PID";         Expression={ $_.OwningProcess }},
            @{Name="ProcessName"; Expression={ $proc_net_array[[int]$_.OwningProcess].ProcessName }}, 
            @{Name="UserName";    Expression={ $proc_net_array[[int]$_.OwningProcess].UserName }} |
            Sort-Object -Property State, CreationTime
        
    $get_net_con = $net_con | ConvertTo-Html -As Table -Fragment -PreContent '<h3>Windows Netstat Info</h3>' | Out-String
    $get_fw_status = $fw_line | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3>Host Firewall Info</h3>’ -Property HostFirewall | Out-String  
    # Host Network Config Artifacts All results converted into html fragments
    $net_adpt = $net_adpt_result | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3>Network Adapter Info</h3>’ | Out-String
    $net_cfg = $net_cfg_result | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3>Network IP Info</h3>’ | Out-String
    $net_rt = $net_rt_result | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3>Network Routing Info</h3>’ | Out-String
    $net_bnd = $net_bnd_result | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3>Network Component Info</h3>’ | Out-String
    $net_arp = $net_arp_result | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3>Arp Cache Info</h3>’ | Out-String
    $get_smb = Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name, ShareType, Path, Description, SecurityDescriptor, EncryptData, CurrentUsers | ConvertTo-Html -As Table -PreContent ‘<h3>SMB Shares Info</h3>’ -Fragment | Out-String
    $get_dns_cache = Get-DnsClientCache | ConvertTo-Html -As Table -PreContent ‘<h3>DNS Cache Info (Status 0 equals success)</h3>’ -Fragment -Property Entry, Data, TimeToLive, Status | Out-String
    $post_output = @($net_adpt, $net_cfg, $net_bnd, $get_fw_status, $host_net_array[0], $host_net_array[1], $net_rt, $net_arp, $get_smb, $get_dns_cache, $get_net_con)
    $report_array = @($ir_report_var, $create_report, $post_output)
    IR-Artifact-Acquisition-Report-Creation($report_array)
}

function IR-Artifact-Acquisition-Process($ir_report_var) {
    $create_report = 'procsvc'
    # Host Running Services, Process, and Scheduled Task Artifacts converted into html fragments
    $get_procc = Get-Process | Sort-Object -Property CreateUtc| ConvertTo-Html -PreContent ‘<h3>Process Info</h3>’ -Fragment -Property ProcessName, Id, Handles, PriorityClass, FileVersion, Path | Out-String
    $get_svc = Get-Service  | ConvertTo-Html -PreContent ‘<h3> Service Info</h3>’ -Fragment -Property Name, ServiceName, DisplayName,  Status, StartType | Out-String
    $get_schd_tsk = Get-ScheduledTask | ConvertTo-Html -As Table -PreContent ‘<h3>Scheduled Tasks Info</h3>’ -Fragment -Property TaskName, Author, Date, Description, URI, Version, State | Out-String
    $get_proc_mod_out = Get-Process -ErrorAction SilentlyContinue | % { 
    $MM = $_.MainModule | Select-Object -ExpandProperty FileName
    $Modules = $($_.Modules | Select-Object -ExpandProperty FileName)
    $currPID = $_.Id
 
    foreach($Module in $Modules) {
        $get_proc_mod = "" | Select-Object Name, ParentPath, ProcessName, ProcPID, CreateUTC, LastAccessUTC, LastWriteUTC
        $get_proc_mod.Name = $Module.Substring($Module.LastIndexOf("\") + 1)
        $get_proc_mod.ParentPath = $Module.Substring(0, $Module.LastIndexOf("\"))
        $get_proc_mod.ProcessName = ($MM.Split('\'))[-1]
        $get_proc_mod.ProcPID = $currPID
        $get_proc_mod.CreateUTC = (Get-Item -Force $Module).CreationTimeUtc
        $get_proc_mod.LastAccessUTC = (Get-Item -Force $Module).LastAccessTimeUtc
        $get_proc_mod.LastWriteUTC = (Get-Item -Force $Module).LastWriteTimeUtc
        $get_proc_mod
    }
    } | Sort-Object -Property CreationTimeUtc | ConvertTo-Html -As Table -PreContent ‘<h3>Process and Loaded Modules Info</h3>’ -Fragment -Property ProcessName, ProcPID, Name, ParentPath, CreateUTC, LastAccessUTC, LastWriteUTC| Out-String
    $post_output = @($get_procc, $get_proc_mod_out, $get_svc, $get_schd_tsk)
    $report_array = @($ir_report_var, $create_report, $post_output)
    IR-Artifact-Acquisition-Report-Creation($report_array)
}

function IR-Artifact-Acquisition-File($ir_report_var) {
    $create_report = 'filereg'
    $user_temp_file_array = @()
    $user_dnld_file_array = @()
    $user_strt_file_array = @()
    $user_ff_brwsr_array = @()
    $user_chrm_brwsr_array = @()
    $user_ie_brwsr_array = @()
    $url_match = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
    $Null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
    $user_paths = Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }
    $auto_run_out = @()
    $auto_run_reg_array = @("\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "\Software\Microsoft\Windows\CurrentVersion\Run", "\Software\Microsoft\Windows\CurrentVersion\RunOnce", "\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", "\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User` Shell` Folders", "\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce", "\Software\Microsoft\Windows\CurrentVersion\RunServices", "\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")
    foreach ($reg_path in $auto_run_reg_array) {
        if (Test-Path -Path Registry::HKEY_LOCAL_MACHINE$reg_path){ 
            $precont_reg = '<h3>Auto Run Hive "' + $reg_path + '" Info</h3>'
            $auto_run_hive = Get-ItemProperty -Path HKLM:$reg_path | Select-Object * -ExcludeProperty PSPath, PSChildName, PSProvider, PSDrive
            $auto_run_out += $auto_run_hive
            }

    }
    foreach($userpath in (Get-WmiObject win32_userprofile | Select-Object -ExpandProperty localpath)) {
        if (Test-Path(($userpath + "\AppData\Local\Temp"))) {
            $user_temp = Get-ChildItem -Force ($userpath + "\AppData\Local\Temp\*") | Select-Object FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc, Extension, Attributes | Sort-Object -Property CreationTimeUtc
            $user_temp_file_array += $user_temp
        } 
        if (Test-Path(($userpath + "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"))) {
            $user_strt = Get-ChildItem -Force ($userpath + "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\*") | Select-Object FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc, Extension, Attributes | Sort-Object -Property CreationTimeUtc
            $user_strt_file_array += $user_strt
        }
        if (Test-Path(($userpath + "\Downloads"))) {
            $user_dwnld = Get-ChildItem -Force ($userpath + "\Downloads\*") | Select-Object FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc, Extension, Attributes | Sort-Object -Property CreationTimeUtc
            $user_dnld_file_array += $user_dwnld
        }
        if (Test-Path(($userpath + "\AppData\Local\Google\Chrome\User Data\Default\History"))) {
            $get_user_chrme = $userpath + "\AppData\Local\Google\Chrome\User Data\Default\History"
            $get_cont_chrome = Get-Content -Path $get_user_chrme |Select-String -AllMatches $url_match |% {($_.Matches).Value} |Sort -Unique
            $user_chrm_bd = $get_cont_chrome | ForEach-Object {
            $chrome_key = $_
            if ($chrome_key -match $Search){
                New-Object -TypeName PSObject -Property @{
                    UserPath = $get_user_chrme
                    URL = $_
                    }
                }
            }
            $user_chrm_brwsr_array += $user_chrm_bd
        }
        if (Test-Path(($userpath + "\AppData\Roaming\Mozilla\Firefox\Profiles"))) {
        $get_user_ff = $userpath + "\AppData\Roaming\Mozilla\Firefox\Profiles\"
        $get_ff_prof = Get-ChildItem -Path "$get_user_ff\*.default*\" -ErrorAction SilentlyContinue
        $get_cont_ff = Get-Content $get_ff_prof\places.sqlite | Select-String -Pattern $url_match -AllMatches |Select-Object -ExpandProperty Matches |Sort -Unique
        $user_ff_bd = $get_cont_ff.Value |ForEach-Object {
            if ($_ -match $Search) {
                ForEach-Object {
                New-Object -TypeName PSObject -Property @{
                    UserPath = $get_user_ff
                    URL = $_
                        }    
                    }
                }
            }
            $user_ff_brwsr_array += $user_ff_bd
        } 

    }
    foreach($user_path in $user_paths) {
        $get_user = ([System.Security.Principal.SecurityIdentifier] $user_path.PSChildName).Translate( [System.Security.Principal.NTAccount]) | Select -ExpandProperty Value
        $user_path = $user_path | Select-Object -ExpandProperty PSPath
        $ie_user_path = "$user_path\Software\Microsoft\Internet Explorer\TypedURLs"
        if (Test-Path -Path $ie_user_path) {
            $user_ie_url = Get-Item -Path $ie_user_path -ErrorAction SilentlyContinue | ForEach-Object {
                $ie_key = $_
                $ie_key.GetValueNames() | ForEach-Object {
                    $ie_value = $ie_key.GetValue($_)
                    if ($ie_value -match $Search) {
                        New-Object -TypeName PSObject -Property @{
                            User = $get_user
                            URL = $ie_value
                            }
                        }
                    }
                }
                $user_ie_brwsr_array += $user_ie_url
            }
    }
    $pref_chk = (Get-ItemProperty "hklm:\system\currentcontrolset\control\session manager\memory management\prefetchparameters").EnablePrefetcher
    if ($pref_chk -in (1,2,3)){
        $lst_pref = Get-ChildItem $env:windir\Prefetch\*.pf
        $get_pref = $lst_pref | Select-Object -Property FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc, Extension, Attributes | Sort-Object -Property CreationTimeUtc | ConvertTo-Html -As Table -Fragment -PreContent '<h3>Windows Prefetch Info</h3>' | Out-String
        }
    else { $get_pref = "No Prefetch Enabled" | ConvertTo-Html -As Table -Fragment -PreContent '<h3>Windows Prefetch Info</h3>' | Out-String}
    $get_auto_run = $auto_run_out | Convertto-html -As List -Fragment -PreContent '<h3>Auto Run Hive Info</h3>' | Out-String
    $get_ie_bd = $user_ie_brwsr_array | Select-Object User, URL | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3>IE Browser Info</h3>’ | Out-String
    $get_ch_bd = $user_chrm_brwsr_array | Select-Object UserPath, URL | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3>Chrome Browser Info</h3>’ | Out-String
    $get_ff_bd = $user_ff_brwsr_array | Select-Object UserPath, URL | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3>FireFox Browser Info</h3>’ | Out-String
    $get_progdata_strt = (Get-ChildItem $env:ProgramData\Microsoft\Windows\Start` Menu\Programs | Select-Object FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc, Extension, Attributes | Sort-Object -Property CreationTimeUtc | ConvertTo-Html -As Table -Fragment -PreContent '<h3>Program Data Start Directory Info</h3>' | Out-String)
    $get_sys_temp = (Get-ChildItem $env:windir\Temp | Select-Object FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc, Extension, Attributes | Sort-Object -Property CreationTimeUtc | ConvertTo-Html -As Table -Fragment -PreContent '<h3>Window Temp Directory Info</h3>' | Out-String)
    $get_temp = $user_temp_file_array | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3>User Temp Directory Info</h3>’ | Out-String
    $get_strt = $user_strt_file_array | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3>User Start Directory Info</h3>’ | Out-String
    $get_dnld = $user_dnld_file_array | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3>User Download Directory Info</h3>’ | Out-String
    $post_output = @($get_auto_run, $get_strt, $get_progdata_strt, $get_pref, $get_temp, $get_sys_temp, $get_ie_bd, $get_ch_bd, $get_ff_bd, $get_dnld)
    $report_array = @($ir_report_var, $create_report, $post_output)
    IR-Artifact-Acquisition-Report-Creation($report_array)
}

function IR-Artifact-Acquisition-EventLogs($ir_event_var){
    $log_array = @("Security","System","Windows Powershell")
    $three_days = (Get-Date) - (New-TimeSpan -Day 3)
    foreach ($log in $log_array) {
        if ($log -eq "Security"){
            $evntid_array = @(1102, 2004, 2005, 4616, 4624, 4625, 4634, 4648, 4657, 4663, 4688, 4697, 4698, 4699, 4700, 4701, 4702, 4719, 4720, 4722, 4723, 4725, 4728, 4732, 4735, 4737, 4738, 4740, 4755, 4756, 4767, 4768, 4772, 4777, 4782, 4946, 4947, 4950, 4954, 4964, 5025, 5031, 5140, 5152, 5153, 5155, 5157, 5447)
            $event_logs_3d = $ir_event_var + "\Security3d.json"
            }
        if ($log -eq "System"){
            $evntid_array = @(7045, 7040)
            $event_logs_3d = $ir_event_var + "\System3d.json"
            }
        if ($log -eq "Windows Powershell"){
            $evntid_array = @(400, 500)
            $event_logs_3d = $ir_event_var + "\WinPwrShell3d.json"
            }
        $get_sec_events = (Get-WinEvent -LogName $log -ErrorAction SilentlyContinue | ?{($_.TimeCreated -ge $three_days) -and ($_.Id -in ($evntid_array))} | Select-Object TimeCreated, LogName, Id, MachineName, UserId, KeywordsDisplayNames, Message )
        $hash_table_event = $get_sec_events | ForEach-Object -Process {
                    New-Object -TypeName PSCustomObject -Property ([ordered]@{
                        'TimeCreated' = $_.TimeCreated 
                        'LogName' = $_.LogName -join ','
                        'EventId' = $_.Id -join ','
                        'MachineName' = $_.MachineName -join ','
                        'UserId' = $_.UserId -join ','
                        'Keyword' = $_.KeywordsDisplayNames -join ','
                        'Message' = $_.Message -join ','
                         })}
        $hash_table_event | ConvertTo-Json -Depth 100 | Out-File $event_logs_3d
    }
}

function IR-Artifact-Acquisition-Report-Creation($report_array) {
    $ir_report_var = $report_array[0]
    $create_report = $report_array[1]
    $post_output = $report_array[2]
    $head = @’
    <title>Artifact Collection Report</title>
    <style>
        body {
            background-color: #F5FFFA;
            }
        table {
            font-family: arial, sans-serif;
            border-collapse: collapse;
            width: 100%;
            }
        td, th {
            border: 2px solid #008147;
            text-align: left;
            padding: 5px;
            }
        tr:nth-child(even) {
            background-color: #90EE90;
            }
        th {
            background-color: #228B22;
            color: white;
            }
    </style>
‘@
    
    if ($create_report -eq 'index'){
        $body = @’
            <p>
                <center>
                    <h2>
                        Host Artifact Index
                    </h2>
                </center>
            <p>
                <h3>
                    Index Report Links
                </h3>
                <button onclick="document.location='Environment.html'">Environment</button>
                <button onclick="document.location='Network.html'">Network</button>
                <button onclick="document.location='ProcSvc.html'">Processes</button>
                <button onclick="document.location='FileReg.html'">Files_Reg</button>
   
‘@
        $postcontent = '<center><h1><h1></center>'
        $html_report = 'index.html'
    }
    if ($create_report -eq 'env'){
        $body = "<center><h2>OS Environment Artifact Report</h2></center>"
        $postcontent = $post_output
        $html_report = 'Environment.html'
    }
    if ($create_report -eq 'net'){
        $body = "<center><h2>Network Config Artifact Report</h2></center>"
        $postcontent = $post_output
        $html_report = 'Network.html'
    }
    if ($create_report -eq 'procsvc'){
        $body = "<center><h2>Processes and Services Artifact Report</h2></center>"
        $postcontent = $post_output
        $html_report = 'ProcSvc.html'
    }
    if ($create_report -eq 'filereg'){
        $body = "<center><h2>Directory and Registry Artifact Report</h2></center>"
        $postcontent = $post_output
        $html_report = 'FileReg.html'
    }
    
    $precontent = '<pre> Host: ' + $ENV:ComputerName + ' ' + $(get-date -UFormat "Date: %Y-%m-%d Time: %H:%M:%S") + ' </pre>'

    # HTML Parameters to create the final report
    $htmlParams = @{
        Head = $head
        Body = $body
        PreContent = $precontent
        PostContent = $postcontent
    }
    $ir_report_full_path = $ir_report_var + "\" + $html_report
    ConvertTo-HTML @htmlParams | Out-File $ir_report_full_path
    Invoke-Item $ir_report_full_path
}

$ir_cmd_array = @('all', 'event', 'image', 'report')
if ( $args.count -eq 0 ){
    $triageType = 'report'
    }
elseif ( $args[0] -in $ir_cmd_array ){ 
    $triageType = $args[0] 
    }
else {
    $triageType = $args[0]
    $screen_output = "[+] {0} Triage type is unknown. (Default variable: report - Valid variables: image,report,both) Variable used: {1}. Script exiting." -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $triageType
    Write-Output $screen_output
    exit 
    }

if ($triageType -eq 'all') {
    $ir_setup_out = IR-Artifact-Acquisition-setup($triageType)
    Write-Output $ir_setup_out[0..1]
    $ir_image_var = $ir_setup_out[2]
    $ir_report_var = $ir_setup_out[3]
    $ir_event_var = $ir_setup_out[4]
    $screen_output = "[+] {0} IR Triage and Acquisition - image path: {1} report path: {2} event path: {3}" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_image_var, $ir_report_var, $ir_event_var
    Write-Output $screen_output
    IR-Artifact-Acquisition-Image($ir_image_var)
    IR-Artifact-Acquisition-Report-Creation($ir_report_var,'index','None')
    IR-Artifact-Acquisition-Environment($ir_report_var)
    IR-Artifact-Acquisition-Network($ir_report_var)
    IR-Artifact-Acquisition-Process($ir_report_var)
    IR-Artifact-Acquisition-File($ir_report_var)
    IR-Artifact-Acquisition-EventLogs($ir_event_var){}
    }
if ($triageType -eq 'image') {
    $ir_setup_out = IR-Artifact-Acquisition-setup($triageType)
    Write-Output $ir_setup_out[0..1]
    $ir_image_var = $ir_setup_out[2]
    $screen_output = "[+] {0} IR Triage and Acquisition - image path: {1}" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_image_var
    Write-Output $screen_output
    IR-Artifact-Acquisition-Image($ir_image_var)
    }
if ($triageType -eq 'report') {
    $ir_setup_out = IR-Artifact-Acquisition-setup($triageType)
    Write-Output $ir_setup_out[0..1]
    $ir_report_var = $ir_setup_out[3]
    $screen_output = "[+] {0} IR Triage and Acquisition - report path: {1}" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_report_var
    Write-Output $screen_output
    IR-Artifact-Acquisition-Report-Creation($ir_report_var,'index','None')
    IR-Artifact-Acquisition-Environment($ir_report_var)
    IR-Artifact-Acquisition-Network($ir_report_var)
    IR-Artifact-Acquisition-Process($ir_report_var)
    IR-Artifact-Acquisition-File($ir_report_var)
    }
if ($triageType -eq 'event') {
    $ir_setup_out = IR-Artifact-Acquisition-setup($triageType)
    Write-Output $ir_setup_out[0..1]
    $ir_event_var = $ir_setup_out[4]
    $screen_output = "[+] {0} IR Triage and Acquisition - event path: {1}" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_event_var
    Write-Output $screen_output
    IR-Artifact-Acquisition-EventLogs($ir_event_var)
    }
$screen_output = "[+] {0} IR Triage and Acquisition is complete. Exiting the script." -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S")
Write-Output $screen_output