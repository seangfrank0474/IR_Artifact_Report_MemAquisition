<#
.SYNOPSIS
    Pull common artifacts from a host during an incident response

.DESCRIPTION
    IR-Artifact-Acquision test to see if there is enough disk space to pull a memory image and creates html formated artifact reports. 
    It will automatically create directory structure on the disk that has the biggest space even if it is not pulling a memory image. 

.PARAMETER both
    This will find a suitable drive with enough freespace. 
    Create the paths where the image and the reports will be saved. 
    Then acquire a memory image and save artifacts in an HTML report. 

.PARAMETER image
    This will find a suitable drive with enough freespace. 
    Create the path where the image will be saved. 
    Then acquire a memory image only. 

.PARAMETER report
    This will find a suitable drive with enough freespace. 
    Create the path where the reports will be saved. 
    Then run commands to collect artifacts in an HTML report. 

.EXAMPLE
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
        if ( ($triageType -eq 'both') -or ($triageType -eq 'image') ){
            if (($dsk_free_array_gb[$i] -eq $dsk_free_max) -and ($dsk_free_array_gb[$i] -ge $drv_viability)){
                $viable = 1
                $dsk_to_use = $dsk_id_array[$i]
                $screen_output = "[+] {0} Found disk that meets the criteria for memory acquisition and/or reports. Disk to be used: {1} with freespace: {2} GB and phyisical memory to image: {3} GB" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $dsk_to_use, $dsk_free_max, $physical_mem_gb
                Write-Output $screen_output
                break
                }
            else {
                $viable = 0 
                $dsk_to_use = $dsk_id_array[$i]
                $screen_output = "[+] {0} No disk(s) that meet the criteria for memory acquisition and/or reports. Disk: {1} with freespace: {2} GB and phyisical memory to image: {3} GB" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $dsk_to_use, $dsk_free_array_gb[$i], $physical_mem_gb
                Write-Output $screen_output
                }
            }
        elseif ( $triageType -eq 'report' ){
            if (($dsk_free_array_gb[$i] -eq $dsk_free_max) -and ($dsk_free_array_gb[$i] -gt $physical_mem_gb)){
                $viable = 1
                $dsk_to_use = $dsk_id_array[$i]
                $screen_output = "[+] {0} Found disk that meets the criteria for memory acquisition and/or reports. Disk to be used: {1} with freespace: {2} GB and phyisical memory to image: {3} GB" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $dsk_to_use, $dsk_free_max, $physical_mem_gb
                Write-Output $screen_output
                break
                }
            else {
                $viable = 0 
                $dsk_to_use = $dsk_id_array[$i]
                $screen_output = "[+] {0} No disk(s) that meet the criteria for memory acquisition and/or reports. Disk: {1} with freespace: {2} GB and phyisical memory to image: {3} GB" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $dsk_to_use, $dsk_free_array_gb[$i], $physical_mem_gb
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
        $ir_triage_path = $dsk_to_use + ':\Users\s839160\Documents\Automation_OpenSource\PowerShell\IRTriage'
        $ir_triage_path_image = $ir_triage_path + '\image'
        $ir_triage_path_report = $ir_triage_path + '\report'
        $ir_triage_path_return = @($ir_triage_path_image, $ir_triage_path_report)
        if (!(Test-Path -Path $ir_triage_path)){
            New-Item -ItemType directory -Path $ir_triage_path
            New-Item -ItemType directory -Path $ir_triage_path_image
            New-Item -ItemType directory -Path $ir_triage_path_report
            $screen_output = "[+] {0} IR Triage and Acquisition paths have been setup." -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S")
            Write-Output $screen_output
        }
        else{
            $screen_output = "[+] {0} IR Triage and Acquision paths have been previously setup and are ready for the acquisition process." -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S")
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
    Write-Output $ir_image_var
}

function IR-Artifact-Acquisition-Report($ir_report_var) {
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
    # Host OS Environment Artifacts converted into html fragments
    $get_proc = Get-WmiObject -Class Win32_Processor -ErrorAction SilentlyContinue | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3>Processor Info</h3>’ -Property Name, Caption, Manufacturer, MaxClockSpeed, SocketDesignation | Out-String
    $get_bios = Get-WmiObject -Class Win32_Bios -ErrorAction SilentlyContinue | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3>BIOS Info</h3>’ -Property Name, Manufacturer, Version, SMBIOSBIOSVersion, SerialNumber | Out-String
    $get_os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3>OS Info</h3>’ -Property Organization, RegisteredUser, Version, BuildNumber, SerialNumber, SystemDirectory | Out-String
    $get_drv = Get-WmiObject -Class Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3>Drive Info</h3>’ -Property DeviceID, DriveType, ProviderName, Size, FreeSpace | Out-String
    $get_env = Get-ChildItem ENV: -ErrorAction SilentlyContinue | ConvertTo-Html -As TABLE -Fragment -PreContent ‘<h3>Environment Info</h3>’ -Property Name, Value| Out-String
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
    # Host Network Config Artifacts All results converted into html fragments
    $net_adpt = $net_adpt_result | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3>Network Adapter Info</h3>’ | Out-String
    $net_cfg = $net_cfg_result | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3>Network IP Info</h3>’ | Out-String
    $net_rt = $net_rt_result | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3>Network Routing Info</h3>’ | Out-String
    $net_bnd = $net_bnd_result | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3>Network Component Info</h3>’ | Out-String
    $net_arp = $net_arp_result | ConvertTo-Html -As Table -Fragment -PreContent ‘<h3>Arp Cache Info</h3>’ | Out-String
    $get_dns_cache = Get-DnsClientCache | ConvertTo-Html -As Table -PreContent ‘<h3>DNS Cache Info (Status 0 equals success)</h3>’ -Fragment -Property Entry, Data, TimeToLive, Status | Out-String
    # Host Running Services, Process, and Scheduled Task Artifacts converted into html fragments
    $get_procc = Get-Process | ConvertTo-Html -PreContent ‘<h3>Process Info</h3>’ -Fragment -Property ProcessName, Id, Handles, PriorityClass, FileVersion, Path | Out-String
    $get_svc = Get-Service  | ConvertTo-Html -PreContent ‘<h3>Service Info</h3>’ -Fragment -Property Name, ServiceName, DisplayName,  Status, StartType | Out-String
    $get_schd_tsk = Get-ScheduledTask | ConvertTo-Html -As Table -PreContent ‘<h3>Service Info</h3>’ -Fragment -Property TaskName, Author, Source, Description, URI, Version, State | Out-String
    $get_local_user = Get-LocalUser | ConvertTo-Html -As Table -PreContent ‘<h3>Local Users Info</h3>’ -Fragment -Property Name, FullName, SID, Description, LastLogon, PasswordRequired, PasswordLastSet, PasswordExpires, UserMayChangePassword, Enabled | Out-String
    # HTML Parameters to create the final report
    $htmlParams = @{
        Head = $head
        Body = "<center><h2>Host Artifact Report</h2></center>"
        PreContent = "
          <pre>
              Host: $ENV:ComputerName 
              Date: $(get-date -UFormat "%Y-%m-%d Time: %H:%M:%S")
          </pre>"
        PostContent = $get_proc, $get_bios, $get_os, $get_drv, $get_env, $net_adpt, $net_cfg, $net_rt, $net_bnd, $net_arp, $get_dns_cache, $get_svc, $get_procc, $get_schd_tsk, $get_local_user
    }
    $ir_report_full_path = $ir_report_var + "\ArtifactReport" + $(get-date -UFormat "%Y-%m-%dT%H-%M-%S") + ".html"
    ConvertTo-HTML @htmlParams | Out-File $ir_report_full_path
    Invoke-Item $ir_report_full_path
}

$ir_cmd_array = @('both', 'image', 'report')
if ( $args.count -eq 0 ){
    $triageType = 'report'
    }
elseif ( $args[0] -in $ir_cmd_array ){ 
    $triageType = $args[0] 
    }
else {
    $triageType = $args[0]
    $screen_output = "[+] {0} Triage type is unknown. Default variable: report Valid variables: image,report,both. Variable used: {1}. Script exiting." -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $triageType
    Write-Output $screen_output
    exit 
    }

if ($triageType -eq 'both') {
    $ir_setup_out = IR-Artifact-Acquisition-setup($triageType)
    Write-Output $ir_setup_out[0..1]
    $ir_image_var = $ir_setup_out[2]
    $ir_report_var = $ir_setup_out[3]
    $screen_output = "[+] {0} IR Triage and Acquisition - image path: {1} report path: {2}" -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S"), $ir_image_var, $ir_report_var
    Write-Output $screen_output
    IR-Artifact-Acquisition-Image($ir_image_var)
    IR-Artifact-Acquisition-Report($ir_report_var)
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
    IR-Artifact-Acquisition-Report($ir_report_var)
    }

$screen_output = "[+] {0} IR Triage and Acquisition is complete. Exiting the script." -f $(get-date -UFormat "%Y-%m-%dT%H:%M:%S")
Write-Output $screen_output