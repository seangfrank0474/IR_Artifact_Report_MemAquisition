$compname = [Environment]::MachineName
$dns_rslv = (Resolve-DNSName -Name $compname -type A).IPAddress
$recon_json_final = @()
foreach ( $i in $dns_rslv ){
    $recon_json = @()
    $octet = $i.Split(".")
    $octet_start = 1 
    $octet_end = 254
    $net_cidr =  $octet[0] + '.' + $octet[1] + '.' + $octet[2] + "."
    for ($i = $octet_start; $i -le $octet_end; $i++){
        $full_ip = $net_cidr + $i
        $recon_ping = Test-Connection -ComputerName $full_ip -count 1 -Quiet
        if ($recon_ping -match 'False'){
            continue
        }
        if ($recon_ping -match 'True'){
            try{
                $dns_name = (Resolve-DnsName -Name $full_ip -Type PTR -ErrorAction Stop).NameHost
            }
            catch {
                $dns_name = ''
            }
            finally {
                if (!$dns_name){
                    $dns_name = "No-Resolution"
                }
                $port_array = @(21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1723, 3306, 3389, 5900, 8080, 9100)
                $open_ports = @()
                foreach ($port in $port_array){
                    $recon_connect = new-Object system.Net.Sockets.TcpClient
                    $recon_prt_result = $recon_connect.ConnectAsync($full_ip,$port).Wait(40)
                    if ($recon_prt_result -match 'True'){
                        $open_ports += $port
                    }
                    else { 
                        continue 
                    }
                }
                $json_elements = '{"ip": "'+$full_ip+'", "domain": "'+$dns_name+'", "open": "'+$open_ports+'"}'
                $recon_json += $json_elements
            }
        }
    }
    $recon_json_final += $recon_json
}
Write-Host $recon_json_final