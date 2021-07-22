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
# Function call to check drive space to write event, images, and reports
function IR-Artifact-Acquisition-Setup($triageType) {
    # Setup IR Artifact directory. Looking for the drive with the most free space.
    $dsk_array = (Get-CimInstance -Class CIM_LogicalDisk | where {$_.DeviceID})
    $physical_mem_bytes = (Get-CimInstance -Class win32_ComputerSystem).TotalPhysicalMemory
    $physical_mem_gb = [math]::Round($physical_mem_bytes/1024/1024/1024)
    $all_img_viable = [math]::Round($physical_mem_gb * 2.5)
    $evt_rpt_viable = [math]::Round($physical_mem_gb * 1.5)
    $dsk_to_use = $null
    # Finding the drive with the maximum free space in the array that was created in the previous for loop. If none is found it will exit the script.
    foreach ($disk in $dsk_array){
        $disk_free = [math]::Round($disk.FreeSpace/1024/1024/1024)
        if ($triageType -in ('all','image') -and $disk_free -ge $all_img_viable){
            $dsk_to_use = $disk.DeviceID
            $screen_output = "[+] {0} Found disk that meets the criteria for memory acquisition/reports/events. Disk to be used: {1} with freespace: {2} GB and phyisical memory to image: {3} GB" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $dsk_to_use, $disk_free, $physical_mem_gb
            Write-Output $screen_output
            break
        }
        if ($triageType -in ('event','report') -and $disk_free -ge $evt_rpt_viable){
            $dsk_to_use = $disk.DeviceID
            $screen_output = "[+] {0} Found disk that meets the criteria for memory acquisition/reports/events. Disk to be used: {1} with freespace: {2} GB and phyisical memory to image: {3} GB" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $dsk_to_use, $disk_free, $physical_mem_gb
            Write-Output $screen_output
            break
        }
    }  

    Switch -Regex ($dsk_to_use) {
        "^[A-Za-z]\:$" {
            $ir_triage_path = $dsk_to_use + '\IRTriage'
            }
        "^[A-Za-z]$"{
            $ir_triage_path = $dsk_to_use + ':\IRTriage'
            }
        default {
            $screen_output = "[+] {0} No viable drive(s) can be found for memory acquisition and/or reports. Exiting the script" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S")
            Write-Output $screen_output
            exit
            }
    }   
    # Create a directory structure for image acquision and artifact reports.
    $ir_triage_path_host = $ir_triage_path + '\' + $ENV:ComputerName
    $ir_triage_path_image = $ir_triage_path_host + '\image'
    $ir_triage_path_report = $ir_triage_path_host + '\report'
    $ir_triage_path_event = $ir_triage_path_host + '\event'
    $ir_triage_path_return = @($ir_triage_path_image, $ir_triage_path_report, $ir_triage_path_event, $ir_triage_path_host, $ir_triage_path)
    if (!(Test-Path -Path $ir_triage_path)){
        New-Item -ItemType directory -Path $ir_triage_path | Out-Null
        New-Item -ItemType directory -Path $ir_triage_path_host | Out-Null
        New-Item -ItemType directory -Path $ir_triage_path_image | Out-Null
        New-Item -ItemType directory -Path $ir_triage_path_report | Out-Null
        New-Item -ItemType directory -Path $ir_triage_path_event | Out-Null
        $screen_output = "[+] {0} IR Triage and Acquisition paths have been setup." -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S")
        Write-Output $screen_output
    }
    else {
        $screen_output = "[+] {0} IR Triage and Acquision paths have been previously setup and is ready for the acquisition process." -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S")
        Write-Output $screen_output
    }    
    return $ir_triage_path_return
}
# Function call to create a raw memory image that will be written to the \IRTriage\<hostname>\image\<hostname>_mem_img_<date>.raw
function IR-Artifact-Acquisition-Image($ir_image_var) {
    $script_run_path = (Get-Item $PSScriptRoot).FullName + "\winpmem.exe"
    $ir_pull_path = $env:TEMP  + "\irts\IR_Artifact_Report_MemAquisition-main\winpmem.exe"
    $relative_path = ".\winpmem.exe"
    $winpmem_path_array = @($relative_path,$ir_pull_path,$script_run_path)
    $winpmem_path_cnt = 0
    switch ($winpmem_path_array){
        {(Test-Path -Path $_) -eq $true } {
            $winpmem_path = $_
            break
        }
        {(Test-Path -Path $_) -eq $false } {
            $winpmem_path_cnt += 1
        }
        {$winpmem_path_cnt -ge 2} {
            $screen_output = "[+] {0} IR Triage and Acquisition could not find the path of winpmem.exe and will now exit. The winpmem.exe file needs to be in the script path" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S")
            Write-Output $screen_output
            exit
        }
    }
    $mem_acq_file = $ENV:ComputerName + '_mem_img_' + $(get-date -UFormat "%Y_%m_%dT%H_%M_%S") + '.raw'
    $mem_img_full_path = $ir_image_var + '\' + $mem_acq_file
    $screen_output = "[+] {0} IR Triage and Acquisition is going to acquire a memory image this will take awhile, so go get a cup off coffee. image path: {1} filename: {2}" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_image_var, $mem_acq_file
    Write-Output $screen_output 
    $mem_acq = Start-Process -PassThru -NoNewWindow -RedirectStandardOutput "winpmem.txt" -RedirectStandardError "Error.txt" -FilePath "$env:comspec" -ArgumentList "/c","$winpmem_path","$mem_img_full_path"
    $get_proc_id = $mem_acq.Id
    do {
        $screen_output = "[+] {0} IR Triage and Acquisition is still dumping memory - please standby." -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S")
        Write-Output $screen_output
        Start-Sleep -Seconds 10
    }
    until ((Get-Process -Name "cmd" -ErrorAction SilentlyContinue | where {$_.Id -eq $get_proc_id}) -eq $null)
    $screen_output = "[+] {0} IR Triage and Acquisition memory acquisition is complete. Image can be found here: {1}" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $mem_img_full_path
    Write-Output $screen_output   
}
# Function call to create the HTML fragments that will be written to the \IRTriage\<hostname>\report\Environment.html
function IR-Artifact-Acquisition-Environment($ir_report_var) {  
    $create_report = 'env'  
    # Host OS Environment Artifacts converted into html fragments
    $get_proc = Get-WmiObject -Class Win32_Processor -ErrorAction SilentlyContinue | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3 id="E1">Processor Info</h3>’ -Property Name, Caption, Manufacturer, MaxClockSpeed, SocketDesignation | Out-String
    $get_bios = Get-WmiObject -Class Win32_Bios -ErrorAction SilentlyContinue | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3 id="E2">BIOS Info</h3>’ -Property Name, Manufacturer, Version, SMBIOSBIOSVersion, SerialNumber | Out-String
    $get_os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3 id="E3">OS Info</h3>’ -Property Organization, RegisteredUser, Version, BuildNumber, SerialNumber, SystemDirectory | Out-String
    $get_drv = Get-WmiObject -Class Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3 id="E4">Drive Info</h3>’ -Property DeviceID, DriveType, ProviderName, Size, FreeSpace | Out-String
    $get_av = Get-WmiObject -namespace root\Microsoft\SecurityClient -Class AntimalwareHealthStatus | select Name, Version, Enabled, AntispywareEnabled, AntivirusEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, NisEnabled, RtpEnabled | ConvertTo-Html -As List -Fragment -PreContent ‘<h3 id="E5">AV Info</h3>’ | Out-String
    $get_install_prog = Get-WmiObject -Class Win32_Product | Select Name, Vendor, Version | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3 id="E6">Installed Programs Info</h3>’ | Out-String
    $get_env = Get-ChildItem ENV: -ErrorAction SilentlyContinue | ConvertTo-Html -As TABLE -Fragment -PreContent ‘<h3 id="E7">Environment Info</h3>’ -Property Name, Value| Out-String
    $get_local_user = Get-LocalUser | ConvertTo-Html -As Table -PreContent ‘<h3 id="E8">Local Users Info</h3>’ -Fragment -Property Name, FullName, SID, Description, LastLogon, PasswordRequired, PasswordLastSet, PasswordExpires, UserMayChangePassword, Enabled | Out-String
    $get_local_admins = & net localgroup administrators | Select-Object -Skip 6 | ? {
    $_ -and $_ -notmatch "The command completed successfully" 
    } | % {
    $o = "" | Select-Object Account
    $o.Account = $_
    $o
    } | ConvertTo-Html -As Table -PreContent ‘<h3 id="E9">Local Admin Members Info</h3>’ -Fragment -Property Account | Out-String
    $post_output = @($get_proc, $get_bios, $get_os, $get_drv, $get_av, $get_install_prog, $get_env, $get_local_user, $get_local_admins)
    $report_array = @($ir_report_var, $create_report, $post_output)
    IR-Artifact-Acquisition-Report-Creation($report_array)
}
# Function call to create the HTML fragments that will be written to the \IRTriage\<hostname>\report\Network.html
function IR-Artifact-Acquisition-Network($ir_report_var) {
    $create_report = 'net'
    # Host Network Config Artifacts
    # Host Network Config Artifacts Arrays
    foreach ($cmd_array in ("Get-NetAdapter","Get-NetIPConfiguration","Get-NetRoute","Get-NetAdapterBinding","Get-NetNeighbor")){
        switch -casesensitive ($cmd_array) {
            "Get-NetAdapter" { 
                $get_net_adpt = (Get-NetAdapter | Select-Object -Property Name, ifIndex, InterfaceDescription, MacAddress, Status)
                $net_cnt = ($get_net_adpt.ifIndex | measure).Count 
                $net_adpt_result = @()
                }
            "Get-NetIPConfiguration" { 
                $get_net_cfg = (Get-NetIPConfiguration | Select-Object -Property InterfaceIndex, InterfaceAlias,Ipv4Address, DNSServer, DefaultIPGateway)
                $net_cnt = ($get_net_cfg.InterfaceIndex | measure).Count
                $net_cfg_result = @()
                }
            "Get-NetRoute" { 
                $get_net_rt = (Get-NetRoute | Select-Object -Property ifIndex, DestinationPrefix, NextHop, RouteMetric)
                $net_cnt = ($get_net_rt.ifIndex | measure).Count 
                $net_rt_result = @()
                }
            "Get-NetAdapterBinding" { 
                $get_net_bnd = (Get-NetAdapterBinding | Select-Object -Property Name, DisplayName, ComponentID, Enables)
                $net_cnt = ($get_net_bnd.Name | measure).Count
                $net_bnd_result = @()
                }
            "Get-NetNeighbor" { 
                $get_net_arp = (Get-NetNeighbor | Select-Object -Property ifIndex, IPAddress, LinkLayerAddress, State)
                $net_cnt = ($get_net_arp.ifIndex | measure).Count 
                $net_arp_result = @()
                }
        } 
        for ($i = 0; $i -lt $net_cnt; $i++){
            switch -casesensitive ($cmd_array) {
                "Get-NetAdapter" { 
                    $net_adpt_result += New-Object -TypeName PSCustomObject -Property ([ordered]@{
                        'Name' = $get_net_adpt[$i].Name
                        'Interface' = $get_net_adpt[$i].ifIndex -join ','
                        'Description' = $get_net_adpt[$i].InterfaceDescription -join ','
                        'MacAddress' = $get_net_adpt[$i].MacAddress -join ','
                        'Status' = $get_net_adpt[$i].Status -join ','
                        })
                    }
                "Get-NetIPConfiguration" { 
                    $net_cfg_result += New-Object -TypeName PSCustomObject -Property ([ordered]@{
                        'Name' = $get_net_cfg[$i].InterfaceAlias
                        'Interface' = $get_net_cfg[$i].InterfaceIndex -join ','
                        'IPAdress' = $get_net_cfg[$i].Ipv4Address -join ','
                        'DNSServer' = ($get_net_cfg[$i].DNSServer | Select-Object -ExpandProperty ServerAddresses) -join ','
                        })
                    }
                "Get-NetRoute" { 
                    $net_rt_result += New-Object -TypeName PSCustomObject -Property ([ordered]@{
                        'Interface' = $get_net_rt[$i].ifIndex 
                        'DestinationPrefix' = $get_net_rt[$i].DestinationPrefix -join ','
                        'NextHop' = $get_net_rt[$i].NextHop -join ','
                        'RouteMetric' = $get_net_rt[$i].RouteMetric -join ','
                        })
                    }
                "Get-NetAdapterBinding" { 
                    $net_bnd_result += New-Object -TypeName PSCustomObject -Property ([ordered]@{
                        'Name' = $get_net_bnd[$i].Name 
                        'DisplayName' = $get_net_bnd[$i].DisplayName -join ','
                        'ComponentID' = $get_net_bnd[$i].ComponentID -join ','
                        'Status' = $get_net_bnd[$i].Enables -join ','
                        })
                    }
                "Get-NetNeighbor" { 
                    $net_arp_result += New-Object -TypeName PSCustomObject -Property ([ordered]@{
                        'Interface' = $get_net_arp[$i].ifIndex 
                        'IPAddress' = $get_net_arp[$i].IPAddress -join ','
                        'MACAddress' = $get_net_arp[$i].LinkLayerAddress -join ','
                        'State' = $get_net_arp[$i].State -join ','
                        })
                }
            }
        }   
    }
    $post_host_file = "<pre>`n None `n </pre>"
    $post_net_file = "<pre>`n None `n </pre>"
    $post_fw_status = "<pre>`n None `n </pre>"
    If (Get-Content $env:windir\system32\drivers\etc\hosts){
        $hosts_file = (Get-Content $env:windir\system32\drivers\etc\hosts) | Out-String
        $post_host_file = "<pre>`n" + $hosts_file + "`n </pre>"
        }
    If (Get-Content $env:windir\system32\drivers\etc\networks){
        $network_file = (Get-Content $env:windir\system32\drivers\etc\networks) | Out-String
        $post_net_file = "<pre>`n" + $network_file + "`n </pre>"
        }
    If (netsh firewall show state) {
        $fw_state = netsh firewall show state | Out-String
        $fw_config = netsh firewall show config | Out-String
        $fw_dump = netsh dump | Out-String
        $post_fw_status = "<pre>`n" + $fw_state + "`n" + $fw_config + "`n" + $fw_dump + "`n </pre>"
        }
    $proc_net_array = @{}
    Get-Process -IncludeUserName | ForEach-Object {
        $proc_net_array[$_.Id] = $_
        }
    $net_con_tcp = Get-NetTCPConnection |
        Select-Object LocalAddress, LocalPort, RemoteAddress,
            RemotePort, State, CreationTime,
            @{Name="PID";         Expression={ $_.OwningProcess }},
            @{Name="ProcessName"; Expression={ $proc_net_array[[int]$_.OwningProcess].ProcessName }}, 
            @{Name="UserName";    Expression={ $proc_net_array[[int]$_.OwningProcess].UserName }} |
            Sort-Object -Property State, CreationTime
    $net_con_udp = Get-NetUDPEndpoint |
    Select-Object LocalAddress, LocalPort, CreationTime,
        @{Name="PID";         Expression={ $_.OwningProcess }},
        @{Name="ProcessName"; Expression={ $proc_net_array[[int]$_.OwningProcess].ProcessName }}, 
        @{Name="UserName";    Expression={ $proc_net_array[[int]$_.OwningProcess].UserName }} |
        Sort-Object -Property CreationTime
    # Host Network Config Artifacts All results converted into html fragments
    $net_adpt = $net_adpt_result | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3 id="N1">Network Adapter Info</h3>’ | Out-String    
    $net_cfg = $net_cfg_result | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3 id="N2">Network IP Info</h3>’ | Out-String
    $net_bnd = $net_bnd_result | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3 id="N3">Network Component Info</h3>’ | Out-String
    $get_fw_status = ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3 id="N4">Host Firewall Info</h3>’ -PostContent $post_fw_status | Out-String
    $get_host_file = ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3 id="N5">Host File Info</h3>’ -PostContent $post_host_file | Out-String
    $get_net_file = ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3 id="N6">Network File Info</h3>’ -PostContent $post_net_file | Out-String 
    $net_rt = $net_rt_result | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3 id="N7">Network Routing Info</h3>’ | Out-String
    $net_arp = $net_arp_result | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3 id="N8">Arp Cache Info</h3>’ | Out-String
    $get_smb = Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name, ShareType, Path, Description, SecurityDescriptor, EncryptData, CurrentUsers | ConvertTo-Html -As Table -PreContent ‘<h3 id="N9">SMB Shares Info</h3>’ -Fragment | Out-String
    $get_net_con_tcp = $net_con_tcp | ConvertTo-Html -As Table -Fragment -PreContent '<h3 id="N10">Windows Netstat TCP Info</h3>' | Out-String
    $get_net_con_udp = $net_con_udp | ConvertTo-Html -As Table -Fragment -PreContent '<h3 id="N11">Windows Netstat UDP Info</h3>' | Out-String
    $get_dns_cache = Get-DnsClientCache | ConvertTo-Html -As Table -PreContent ‘<h3 id="N12">DNS Cache Info (Status 0 equals success)</h3>’ -Fragment -Property Entry, Data, TimeToLive, Status | Out-String
    $post_output = @($net_adpt, $net_cfg, $net_bnd, $get_fw_status, $get_host_file, $get_net_file, $net_rt, $net_arp, $get_smb, $get_dns_cache, $get_net_con_tcp, $get_net_con_udp)
    $report_array = @($ir_report_var, $create_report, $post_output)
    IR-Artifact-Acquisition-Report-Creation($report_array)
}
# Function call to create the HTML fragments that will be written to the \IRTriage\<hostname>\report\ProcSvc.html
function IR-Artifact-Acquisition-Process($ir_report_var) {
    $create_report = 'procsvc'
    # Host Running Services, Process, and Scheduled Task Artifacts converted into html fragments
    $get_procc = Get-Process -ErrorAction SilentlyContinue | Sort-Object -Property StartTime| ConvertTo-Html -PreContent ‘<h3 id="P1">Process Info</h3>’ -Fragment -Property ProcessName, Id, Path, Handles, PriorityClass, FileVersion  | Out-String
    $get_svc = Get-Service | ConvertTo-Html -PreContent ‘<h3 id="P4">Service Info</h3>’ -Fragment -Property Name, ServiceName, DisplayName,  Status, StartType | Out-String
    $get_schd_tsk = Get-ScheduledTask | ConvertTo-Html -As Table -PreContent ‘<h3 id="P5">Scheduled Tasks Info</h3>’ -Fragment -Property TaskName, Author, Date, Description, URI, Version, State | Out-String
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
        $get_proc_mod.CreateUTC = (Get-Item -Force $Module -ErrorAction SilentlyContinue).CreationTimeUtc
        $get_proc_mod.LastAccessUTC = (Get-Item -Force $Module -ErrorAction SilentlyContinue).LastAccessTimeUtc
        $get_proc_mod.LastWriteUTC = (Get-Item -Force $Module -ErrorAction SilentlyContinue).LastWriteTimeUtc
        $get_proc_mod
    }
    } | Sort-Object -Property CreateUtc | ConvertTo-Html -As Table -PreContent ‘<h3 id="P3">Process and Loaded Modules Info</h3>’ -Fragment -Property ProcessName, ProcPID, Name, ParentPath, CreateUTC, LastAccessUTC, LastWriteUTC| Out-String
    $main_pid = (Get-Process -ErrorAction SilentlyContinue).Id
    $proc_pid_cli = @()
    foreach($mpid in $main_pid) {
        $main_info = (Get-CimInstance -Class Win32_Process -Filter "ProcessId = $mpid" -ErrorAction SilentlyContinue)
        $process_name = $main_info.ProcessName
        $process_path = $main_info.ExecutablePath
        $process_cli = $main_info.CommandLine
        $process_ctime = $main_info.CreationDate
        $parent_pid = $main_info.ParentProcessId
        $parent_info = (Get-CimInstance -Class Win32_Process -Filter "ProcessId = $parent_pid" -ErrorAction SilentlyContinue)
        $parent_name = $parent_info.ProcessName
        $parent_path = $parent_info.ExecutablePath
        $parent_cli = $parent_info.CommandLine
        $parent_ctime = $parent_info.CreationDate
        $proc_pid_cli += New-Object -TypeName PSCustomObject -Property ([ordered]@{
                            'Child_Creation_Date' = $process_ctime
                            'Child_Process_Name' = $process_name -join ','
                            'Child_PID' = $mpid -join ','
                            'Child_Exec_Path' = $process_path -join ','
                            'Child_CLI' = $process_cli -join ','
                            'Parent_Creation_Date' = $parent_ctime -join ','
                            'Parent_Process_Name' =  $parent_name -join ','
                            'Parent_PID' = $parent_pid -join ','
                            'Parent_Exec_Path' =  $parent_path -join ','
                            'Parent_CLI' =  $parent_cli -join ',' 
                            
                            })
    }
    $get_proc_cli = $proc_pid_cli | Sort-Object -Property  Child_Creation_Date | ConvertTo-Html -As Table -PreContent ‘<h3 id="P2">Process (Child - Parent - CommandLine) Info</h3>’ -Fragment | Out-String
    $post_output = @($get_procc, $get_proc_cli, $get_proc_mod_out, $get_svc, $get_schd_tsk)
    $report_array = @($ir_report_var, $create_report, $post_output)
    IR-Artifact-Acquisition-Report-Creation($report_array)
}
# Function call to create the HTML fragments that will be written to the \IRTriage\<hostname>\report\FileReg.html
function IR-Artifact-Acquisition-File($ir_report_var) {
    $create_report = 'filereg'
    $ci_hash_array = @()
    $appdata_local_array = @()
    $appdata_roam_array = @()
    $user_dld_array = @()
    $user_dsk_array = @()
    $user_doc_array = @()
    $user_chrm_brwsr_array = @()
    $user_ff_brwsr_array = @()
    $sys_root_array = @()
    $sys_win_array = @()
    $sys_temp_array = @()
    $sys_w32_array = @()
    $sys_w64_array = @()
    $hku_url_path_out = @()
    $hku_run_path_out = @()
    $auto_run_out = @()
    $sys_paths_array = @($env:SystemDrive, $env:windir, "$env:windir\Temp", "$env:windir\System32", "$env:windir\SysWOW64")
    $url_match = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
    $auto_run_reg_array = @("\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "\Software\Microsoft\Windows\CurrentVersion\Run", "\Software\Microsoft\Windows\CurrentVersion\RunOnce", "\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", "\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User` Shell` Folders", "\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce", "\Software\Microsoft\Windows\CurrentVersion\RunServices", "\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")
    $Null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
    $user_paths = Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }
    switch ($auto_run_reg_array) {
        {(Test-Path -Path Registry::HKEY_LOCAL_MACHINE$_ -ErrorAction SilentlyContinue) -eq $true} {
            Get-Item -Path HKLM:$_ | Foreach {
                $key = $_
                 $key.GetValueNames() | ForEach {
                     $auto_run_out += New-Object -TypeName PSCustomObject -Property ([ordered]@{
                         'Hive' = $key.Name
                         'Name' = $_ -join ','
                         'Data' = $key.GetValue($_) -join ','
                         })
                }
            } 
        }
        {(Test-Path -Path Registry::HKEY_LOCAL_MACHINE$_ -ErrorAction SilentlyContinue) -eq $false} {
            $auto_run_out += New-Object -TypeName PSCustomObject -Property ([ordered]@{
                'Hive' = 'HKEY_LOCAL_MACHINE' + $_
                'Name' = 'Path does not exist' -join ','
                'Data' = 'No Data' -join ','
            })
        }
    }
    foreach ($user_profile in (Get-WmiObject win32_userprofile | Select-Object -ExpandProperty localpath)){
        $appdata_local = $user_profile + "\AppData\Local"
        $appdata_roam = $user_profile + "\AppData\Roaming"
        $user_dld = $user_profile + "\Downloads"
        $user_dsk = $user_profile + "\Desktop"
        $user_doc = $user_profile + "\Documents"
        $user_chrome = $user_profile + "\AppData\Local\Google\Chrome\User Data\Default\History"
        $user_ff = $user_profile + "\AppData\Roaming\Mozilla\Firefox\Profiles"
        $user_prof_array = @($appdata_local,$appdata_roam,$user_dld,$user_dsk,$user_doc,$user_chrome,$user_ff,$user_prof_array)
        foreach ($user_prof_path in $user_prof_array) {
            if ($user_prof_path -isnot [String]){ 
                continue
            }
            if ((Test-Path -Path $user_prof_path) -eq $true){
                if ($user_prof_path -eq $user_chrome){
                    $get_cont_chrome = Get-Content -Path $user_prof_path |Select-String -AllMatches $url_match |% {($_.Matches).Value} |Sort -Unique
                    $get_cont_chrome | ForEach-Object {
                        $chrome_key = $_
                        if ($chrome_key -match $Search){
                            $user_chrm_brwsr_array += New-Object -TypeName PSObject -Property @{
                                FullName = $user_prof_path
                                URL = $_
                            }
                        }
                    }
                    continue 
                }              
              if ($user_prof_path -eq $user_ff){
                  $get_ff_prof = Get-ChildItem -Path "$user_prof_path\*.default*\" -ErrorAction SilentlyContinue
                  $get_cont_ff = Get-Content $get_ff_prof\places.sqlite | Select-String -Pattern $url_match -AllMatches |Select-Object -ExpandProperty Matches |Sort -Unique
                  $get_cont_ff.Value |ForEach-Object {
                      if ($_ -match $Search) {
                          ForEach-Object {
                              $user_ff_brwsr_array += New-Object -TypeName PSObject -Property @{
                                  FullName = $user_prof_path
                                  URL = $_
                              }
                          }
                      }
                  }
                  continue 
              }
              $get_child_items = (Get-ChildItem -Force -Recurse -Path $user_prof_path\* -ErrorAction SilentlyContinue)
              foreach ($child_item in $get_child_items){
                  $child_ext = $child_item.Extension
                  $child_fn = $child_item.FullName
                  if (($user_prof_path -eq $appdata_local -or $user_prof_path -eq $appdata_roam) -and ($child_fn -match "^.+(\\Local\\Packages\\|\\Local\\Google\\Chrome\\|\\Roaming\\Mozilla\\Firefox\\).+$")){
                      continue
                  }
                  if ($child_ext -in (".exe",".com",".dll",".sys",".zip",".rar",".dat",".tar",".gz",".tgz",".bin",".js",".pdf",".doc",".docx",".xls",".xlsx")){
                      $child_item_hash = $child_item |  Select-Object -Property CreationTimeUtc, Attributes, FullName, @{name="Hash";expression={(Get-FileHash $child_fn -ErrorAction SilentlyContinue).hash}}, LastAccessTimeUtc, LastWriteTimeUtc
                      $ci_hash_array += $child_item_hash
                  }
                  else {
                      $child_item_hash = $child_item |  Select-Object -Property CreationTimeUtc, Attributes, FullName, @{name="Hash";expression="None"}, LastAccessTimeUtc, LastWriteTimeUtc
                  }
                  if ($user_prof_path -eq $appdata_local){
                      $appdata_local_array += $child_item_hash
                      continue
                  }
                  if ($user_prof_path -eq $appdata_roam){
                      $appdata_roam_array += $child_item_hash
                      continue
                  }    
                  if ($user_prof_path -eq $user_dld) {
                      $user_dld_array += $child_item_hash
                      continue
                  }
                  if ($user_prof_path -eq $user_dsk) {
                      $user_dsk_array += $child_item_hash
                      continue
                  }
                  if ($user_prof_path -eq $user_doc) {
                      $user_doc_array += $child_item_hash
                      continue
                  }       
              }      
          }
      }
  }
    foreach ($sys_path in $sys_paths_array) {
        if ($sys_path -eq "$env:windir\Temp"){
            $sys_childs = (Get-ChildItem -Force -Recurse -Path $sys_path\* -ErrorAction SilentlyContinue)
        }
        else {
            $sys_childs = (Get-ChildItem -Force -Path $sys_path\* -ErrorAction SilentlyContinue)
        }
        foreach ($sys_child in $sys_childs) {
            $sys_child_ext = $sys_child.Extension
            $sys_child_fn = $sys_child.FullName
            if ($sys_child_ext -in (".exe",".com",".dll",".sys",".zip",".rar",".dat",".tar",".gz",".tgz",".bin",".js",".pdf",".doc",".docx",".xls",".xlsx")){
                $sys_child_item_hash = $sys_child |  Select-Object -Property CreationTimeUtc, Attributes, FullName, @{name="Hash";expression={(Get-FileHash $sys_child_fn -ErrorAction SilentlyContinue).hash}}, LastAccessTimeUtc, LastWriteTimeUtc
                $ci_hash_array += $sys_child_item_hash
            }
            else {
                $sys_child_item_hash = $sys_child |  Select-Object -Property CreationTimeUtc, Attributes, FullName, @{name="Hash";expression="None"}, LastAccessTimeUtc, LastWriteTimeUtc
            }
            if ($sys_path -eq $env:SystemDrive){
                $sys_root_array += $sys_child_item_hash
                continue
            }
            if ($sys_path -eq $env:windir){
                $sys_win_array += $sys_child_item_hash
                continue
            }
            if ($sys_path -eq "$env:windir\Temp"){
                $sys_temp_array += $sys_child_item_hash
                continue
            }
            if ($sys_path -eq "$env:windir\System32"){
                $sys_w32_array += $sys_child_item_hash
                continue
            }
            if ($sys_path -eq "$env:windir\SysWOW64"){
                $sys_w64_array += $sys_child_item_hash
                continue
            }
        }
    }
    foreach ($user_path in $user_paths) {
        $get_user = ([System.Security.Principal.SecurityIdentifier] $user_path.PSChildName).Translate( [System.Security.Principal.NTAccount]) | Select -ExpandProperty Value
        $user_path = $user_path | Select-Object -ExpandProperty PSPath
        $hku_url_paths = @("\Software\Microsoft\Internet Explorer\TypedURLs")
        $hku_run_paths = @("\Software\Microsoft\Windows\CurrentVersion\Run", "\Software\Microsoft\Windows\CurrentVersion\RunOnce")
        foreach ($hku_url_path in $hku_url_paths) {
            $hku_full_url_path = $user_path + $hku_url_path
            switch (Test-Path -Path $hku_full_url_path ) { 
                $true{
                    Get-Item -Path $hku_full_url_path | Foreach {
                    $key = $_
                    $key.GetValueNames() | ForEach {
                        $hku_url_path_out += New-Object -TypeName PSCustomObject -Property ([ordered]@{
                            'UserName' = $get_user
                            'Hive' = $key.Name -join ','
                            'Name' = $_ -join ','
                            'Data' = $key.GetValue($_) -join ','
                            })
                        }
                    }
                }
                $false{ 
                    continue 
                }
            }
        }
        foreach ($hku_run_path in $hku_run_paths) {
            $hku_full_run_path = $user_path + $hku_run_path
            switch (Test-Path -Path $hku_full_run_path ) { 
                $true{
                    Get-Item -Path $hku_full_run_path | Foreach {
                    $key = $_
                    $key.GetValueNames() | ForEach {
                        $hku_run_path_out += New-Object -TypeName PSCustomObject -Property ([ordered]@{
                            'UserName' = $get_user
                            'Hive' = $key.Name -join ','
                            'Name' = $_ -join ','
                            'Data' = $key.GetValue($_) -join ','
                            })
                        }
                    }
                }
                $false{ 
                    continue 
                }
            }
        }
    }
    switch ((Get-ItemProperty "hklm:\system\currentcontrolset\control\session manager\memory management\prefetchparameters").EnablePrefetcher){
         {$_ -in (1,2,3)}{
             $lst_pref = Get-ChildItem $env:windir\Prefetch\*.pf
             $get_pref = $lst_pref | Select-Object -Property FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc, Extension, Attributes | Sort-Object -Property CreationTimeUtc | ConvertTo-Html -As Table -Fragment -PreContent '<h3 id="F4">Windows Prefetch Info</h3>' | Out-String
             }
         default {$get_pref = "No Prefetch Enabled" | ConvertTo-Html -As Table -Fragment -PreContent '<h3 id="F4">Windows Prefetch Info</h3>' | Out-String}
    }
    $get_auto_run = $auto_run_out | Convertto-html -As Table -Fragment -PreContent '<h3 id="F1">HKLM Auto Run Hive Info</h3>' | Out-String
    $get_hku_autorun = $hku_run_path_out | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3 id="F2">HKU Auto Run Hive Info</h3>’ | Out-String
    $get_progdata_strt = (Get-ChildItem $env:ProgramData\Microsoft\Windows\Start` Menu\Programs | Select-Object FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc, Extension, Attributes | Sort-Object -Property CreationTimeUtc | ConvertTo-Html -As Table -Fragment -PreContent '<h3  id="F3">Program Data Start Directory Info</h3>' | Out-String)
    $get_hku_url = $hku_url_path_out | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3 id="F5">IE Browser Info</h3>’ | Out-String
    $hash_csv_out = $ir_report_var + "\" +$ENV:ComputerName + "_sha256_files_" + $(get-date -UFormat "%Y%m%dT%H%M%S") + ".csv"
    $get_hash_out = $ci_hash_array | Sort-Object -Property CreationTimeUtc | Export-Csv -NoTypeInformation -Delimiter ';' -Path $hash_csv_out
    $get_user_ff = $user_ff_brwsr_array | Sort-Object -Property CreationTimeUtc | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3 id="F6">User FireFox Browser Info</h3>’ | Out-String
    $get_user_chrm = $user_chrm_brwsr_array | Sort-Object -Property CreationTimeUtc | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3 id="F7">User Chrome Browser Info</h3>’ | Out-String
    $get_app_local = $appdata_local_array | Sort-Object -Property CreationTimeUtc, Hash | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3 id="F8">User AppData Local Directory Info</h3>’ | Out-String
    $get_app_roam = $appdata_roam_array | Sort-Object -Property CreationTimeUtc, Hash | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3 id="F9">User AppData Roaming Directory Info</h3>’ | Out-String
    $get_user_dld = $user_dld_array | Sort-Object -Property CreationTimeUtc, Hash | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3 id="F10">User Downloads Directory Info</h3>’ | Out-String
    $get_user_dsk = $user_dsk_array | Sort-Object -Property CreationTimeUtc, Hash | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3 id="F11">User Desktop Directory Info</h3>’ | Out-String
    $get_user_doc = $user_doc_array | Sort-Object -Property CreationTimeUtc, Hash | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3 id="F12">User Documents Directory Info</h3>’ | Out-String
    $get_sys_root = $sys_root_array | Sort-Object -Property CreationTimeUtc, Hash | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3 id="F13">System Root Info</h3>’ | Out-String
    $get_sys_win = $sys_win_array | Sort-Object -Property CreationTimeUtc, Hash | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3 id="F14">System Windows Info</h3>’ | Out-String
    $get_sys_tmp = $sys_temp_array | Sort-Object -Property CreationTimeUtc, Hash | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3 id="F15">System Temp Info</h3>’ | Out-String
    $get_sys_w32 = $sys_w32_array | Sort-Object -Property CreationTimeUtc, Hash | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3 id="F16">System32 Info</h3>’ | Out-String
    $get_sys_w64 = $sys_w64_array | Sort-Object -Property CreationTimeUtc, Hash | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3 id="F17">SysWOW64 Info</h3>’ | Out-String
    $get_named_pipe = Get-Childitem \\.\pipe\ | Select Name, FullName | ConvertTo-Html -AS Table -Fragment -PreContent ‘<h3 id="F18">Named Pipe Info</h3>’ | Out-String
    $post_output = @($get_auto_run, $get_hku_autorun, $get_progdata_strt, $get_pref, $get_named_pipe, $get_hku_url, $get_user_ff, $get_user_chrm, $get_app_local, $get_app_roam, $get_user_dld, $get_user_dsk, $get_user_doc, $get_sys_root, $get_sys_win, $get_sys_tmp, $get_sys_w32, $get_sys_w64)
    $report_array = @($ir_report_var, $create_report, $post_output)
    IR-Artifact-Acquisition-Report-Creation($report_array)
}
# Function call to create the JSON format event logs that will be written to the \IRTriage\<hostname>\event
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
# Function call to create the HTML reports that will be written to the \IRTriage\<hostname>\report
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
            font-size: 15px;
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
        $body = @’
            <p>
                <center>
                    <h2>OS Environment Artifact Report</h2>
                </center>
            <p>
            <p>
                <a href="#E1">Processor</a>&nbsp;<a href="#E2">BIOS</a>&nbsp;<a href="#E3">OS</a>&nbsp;<a href="#E4">Drives</a>
            <p>
                <a href="#E5">AV</a>&nbsp;<a href="#E6">Installed Programs</a>&nbsp;<a href="#E7">Environment Variables</a>
            <p>
                <a href="#E8">Local Users</a>&nbsp;<a href="#E9">Local Admins</a>
   
‘@
        $postcontent = $post_output
        $html_report = 'Environment.html'
    }
    if ($create_report -eq 'net'){
        $body = @’
            <p>
                <center>
                    <h2>Network Artifact Report</h2>
                </center>
            <p>
            <p>
                <a href="#N1">Net Adapter</a>&nbsp;<a href="#N2">Net Config</a>&nbsp;<a href="#N3">Net Bind</a>&nbsp;<a href="#N4">FW Config</a>
            <p>
                <a href="#N5">Hosts File</a>&nbsp;<a href="#N6">Networks File</a>&nbsp;<a href="#N7">Route Config</a>&nbsp;<a href="#N8">Arp Cache</a>
            <p>
                <a href="#N9">Mapped SMB</a>&nbsp;<a href="#N10">NetStat TCP</a>&nbsp;<a href="#N11">NetStat UDP</a>&nbsp;<a href="#N12">DNS Cache</a>
‘@
        $postcontent = $post_output
        $html_report = 'Network.html'
    }
    if ($create_report -eq 'procsvc'){
        $body = @’
            <p>
                <center>
                    <h2>Processes and Services Artifact Report</h2>
                </center>
            <p>
            <p>
                <a href="#P1">Processes</a>&nbsp;<a href="#P2">Process CommandLines</a>&nbsp;<a href="#P3">Process Modules</a>&nbsp;<a href="#P4">Services</a>&nbsp;<a href="#P5">Scheduled Tasks</a>
               
‘@
        $postcontent = $post_output
        $html_report = 'ProcSvc.html'
    }
    if ($create_report -eq 'filereg'){
        $body = @’
            <p>
                <center>
                    <h2>Directory and Registry Artifact Report</h2>
                </center>
            <p>
            <p>
                <a href="#F1">HKLM Auto Run</a>&nbsp;<a href="#F2">HKU Auto Run</a>&nbsp;<a href="#F3">Program Data Start Menu</a>&nbsp;<a href="#F4">Prefetch</a>;<a href="#F18">Named Pipes</a>
            <p>
                <a href="#F5">IE Browser</a>&nbsp;<a href="#F6">FireFox Browser</a>&nbsp;<a href="#F7">Chrome Browser</a>
            <p>
                <a href="#F8">AppData Local</a>&nbsp;<a href="#F9">AppData Roaming</a>&nbsp;<a href="#F10">User Downloads</a>&nbsp;<a href="#F11">User Desktop</a>&nbsp;<a href="#F12">User Documents</a>
            <p>
                <a href="#F13">System Root</a>&nbsp;<a href="#F14">System Windows</a>&nbsp;<a href="#F15">System Temp</a>&nbsp;<a href="#F16">System32</a>&nbsp;<a href="#F17">SysWOW64</a>
   
‘@
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
    #Invoke-Item $ir_report_full_path
}
#Start of the script
$ir_cmd_array = @('all', 'event', 'image', 'report')
if ($args.count -eq 0){
        $triageType = 'report'    
}
elseif ($args[0] -in $ir_cmd_array){
        $triageType = $args[0]
}
else {
    $triageType = $args[0]
    $screen_output = "[+] {0} Triage type is unknown. (Default variable: report - Valid variables: all, event, image, report) Variable used: {1}. Script exiting." -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $triageType
    Write-Output $screen_output
    exit 
}
switch ($triageType) {
    {$triageType -eq 'all'}{
        $ir_setup_out = IR-Artifact-Acquisition-setup($triageType)
        Write-Output $ir_setup_out[0..1]
        $ir_image_var = $ir_setup_out[2]
        $ir_report_var = $ir_setup_out[3]
        $ir_event_var = $ir_setup_out[4]
        $screen_output = "[+] {0} IR Triage and Acquisition - image path: ({1}) report path: ({2}) event path: ({3})" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_image_var, $ir_report_var, $ir_event_var
        Write-Output $screen_output
        IR-Artifact-Acquisition-Image($ir_image_var)
        IR-Artifact-Acquisition-Report-Creation($ir_report_var,'index','None')
        $screen_output = "[+] {0} IR Triage and Acquisition - index.html created" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_report_var
        Write-Output $screen_output
        IR-Artifact-Acquisition-Environment($ir_report_var)
        $screen_output = "[+] {0} IR Triage and Acquisition - Environment Report Complete" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_report_var
        Write-Output $screen_output
        IR-Artifact-Acquisition-Network($ir_report_var)
        $screen_output = "[+] {0} IR Triage and Acquisition - Network Report Complete" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_report_var
        Write-Output $screen_output
        IR-Artifact-Acquisition-Process($ir_report_var)
        $screen_output = "[+] {0} IR Triage and Acquisition - Processes and Services Report Complete" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_report_var
        Write-Output $screen_output
        IR-Artifact-Acquisition-File($ir_report_var)
        $screen_output = "[+] {0} IR Triage and Acquisition - Files and Registry Report Complete" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_report_var
        Write-Output $screen_output
        $screen_output = "[+] {0} IR Triage and Acquisition - Pulling events from Security/System/Powershell for the past 3 days" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_event_var
        Write-Output $screen_output
        IR-Artifact-Acquisition-EventLogs($ir_event_var){}
        $screen_output = "[+] {0} IR Triage and Acquisition - Events pull is complete" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_event_var
        Write-Output $screen_output
        break
    }
    {$triageType -eq 'image'} {
        $ir_setup_out = IR-Artifact-Acquisition-setup($triageType)
        Write-Output $ir_setup_out[0..1]
        $ir_image_var = $ir_setup_out[2]
        $screen_output = "[+] {0} IR Triage and Acquisition - image path: ({1})" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_image_var
        Write-Output $screen_output
        IR-Artifact-Acquisition-Image($ir_image_var)
        break
    }
    {$triageType -eq 'report'} {
        $ir_setup_out = IR-Artifact-Acquisition-setup($triageType)
        Write-Output $ir_setup_out[0..1]
        $ir_report_var = $ir_setup_out[3]
        $screen_output = "[+] {0} IR Triage and Acquisition - report path: ({1})" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_report_var
        Write-Output $screen_output
        IR-Artifact-Acquisition-Report-Creation($ir_report_var,'index','None')
        $screen_output = "[+] {0} IR Triage and Acquisition - index.html created" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_report_var
        Write-Output $screen_output
        IR-Artifact-Acquisition-Environment($ir_report_var)
        $screen_output = "[+] {0} IR Triage and Acquisition - Environment Report Complete" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_report_var
        Write-Output $screen_output
        IR-Artifact-Acquisition-Network($ir_report_var)
        $screen_output = "[+] {0} IR Triage and Acquisition - Network Report Complete" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_report_var
        Write-Output $screen_output
        IR-Artifact-Acquisition-Process($ir_report_var)
        $screen_output = "[+] {0} IR Triage and Acquisition - Processes and Services Report Complete" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_report_var
        Write-Output $screen_output
        IR-Artifact-Acquisition-File($ir_report_var)
        $screen_output = "[+] {0} IR Triage and Acquisition - Files and Registry Report Complete" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_report_var
        Write-Output $screen_output
        break
     }
    {$triageType -eq 'event'} {
        $ir_setup_out = IR-Artifact-Acquisition-setup($triageType)
        Write-Output $ir_setup_out[0..1]
        $ir_event_var = $ir_setup_out[4]
        $screen_output = "[+] {0} IR Triage and Acquisition - event path: ({1})" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_event_var
        Write-Output $screen_output
        $screen_output = "[+] {0} IR Triage and Acquisition - Pulling events from Security/System/Powershell for the past 3 days" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_event_var
        Write-Output $screen_output
        IR-Artifact-Acquisition-EventLogs($ir_event_var){}
        $screen_output = "[+] {0} IR Triage and Acquisition - Events pull is complete" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_event_var
        Write-Output $screen_output
        break
    }
}
$script_run_path = (Get-Item $PSScriptRoot).FullName + "\7za.exe"
$ir_pull_path = $env:TEMP + "\irts\IR_Artifact_Report_MemAquisition-main\7za.exe"
$relative_path = ".\7za.exe"
$zip_path_array = @($relative_path,$ir_pull_path,$script_run_path)
$zip_7z_path_cnt = 0
switch ($zip_path_array){
    {(Test-Path -Path $_) -eq $true } {
        $zip_7z_path = $_
        break
    }
    {(Test-Path -Path $_) -eq $false } {
        $zip_7z_path_cnt += 1
    }
    {$zip_7z_path_cnt -ge 2} {
        $screen_output = "[+] {0} IR Triage and Acquisition could not find the path of 7za.exe and will now exit. The 7za.exe file needs to be in the script path" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S")
        Write-Output $screen_output
        exit
    }
}
$ir_trgt_comp = $ir_setup_out[5] + "\*"
$ir_trgt_zip = $ir_setup_out[6] + "\" + $ENV:ComputerName + "_" + $(get-date -UFormat "%Y_%m_%dT%H_%M_%S") + ".7z"
$screen_output = "[+] {0} IR Triage and Acquisition compression has started, depending on the data being compressed this could take awhile - compressed path: ({1})." -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_trgt_zip
Write-Output $screen_output
$zip_evidence = Start-Process -PassThru -NoNewWindow -RedirectStandardOutput "7zip.txt" -RedirectStandardError "Error.txt" -FilePath "$env:comspec" -ArgumentList "/c","$zip_7z_path","a","-mx1","$ir_trgt_zip","$ir_trgt_comp","-pinfected"
$get_proc_id = $zip_evidence.Id
do {
    $screen_output = "[+] {0} IR Triage and Acquisition compressing please wait." -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S")
    Write-Output $screen_output
    Start-Sleep -Seconds 10
}
until ((Get-Process -Name "cmd" -ErrorAction SilentlyContinue | where {$_.Id -eq $get_proc_id}) -eq $null)
$screen_output = "[+] {0} IR Triage and Acquisition has compressed all findings - compressed path: ({1})." -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_trgt_zip
Write-Output $screen_output
$screen_output = "[+] {0} IR Triage and Acquisition is complete. Exiting the script." -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S")
Write-Output $screen_output