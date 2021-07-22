# IR_Artifact_Report_MemAquisition

Currently it defaults to report if no argument is given.
The report and the events log collection are working still need to test the memory acquisition.
Image function has been tested on Windows 10 and Windows 2016 Server with the current version of winpmem.exe

WinPMem
https://github.com/Velocidex/WinPmem/releases/tag/v4.0.rc1

Using 7-Zip to compress all the output (7za.exe)
https://www.7-zip.org/download.html

<pre>
  Uses Winpmem to do memory acquisitions
  
  Pulls three days of winevents from Security, System, and Windows Powershell
  
  What is in the Artifact Report?
  
  Environment:
  Processor
  BIOS
  OS
  Drive
  Windows Defender/AV
  Installed Programs
  Environment Variables
  Local Users/Administrators
  
  Network:
  Adapters
  Adapters IP Config
  Adapter Components
  Host Firewall Config
  Hosts/Netowrks File
  Routing
  Arp Cache
  SMB Shares
  DNS Cache
  Netstat TCP/UDP
  
  Processes and Services:
  Running Processes
  Child Processes linked to Parent Processes and CLI 
  Modules loaded on the running processes
  Services
  Scheduled Tasks
  
  Files and Registry:
  HKLM Auto Run
  HKU Auto Run
  Program Data Start Menu
  Prefetch
  Named Pipes
  User Downloads/Desktop/Documents
  URL Browser Cache IE/FF/Chrome
  System root/windows/temp/system32/syswow64
  Sha256 of files in the above directories for extenstions - .exe,.com,.dll,.sys,.zip,.rar,.dat,.tar,.gz,.tgz,.bin,.js,.pdf,.doc,.docx,.xls,.xlsx
  Creates a seperate CSV file with the above Sha256 to bulk check with things like Virus Total
</pre>

You can run this script from the box you would like to triage. 
It will pull the latest zip and expand the archive into your environments temp directory.
https://github.com/seangfrank0474/IR_Artifact_Mem_Pull/blob/main/irartmem_pull.ps1

<pre>
  Use:
  default - No argument - Runs the artifact report
  ir_artifact_rprt_mem_acq.ps1 
  
  all - Runs winpmem.exe, report and event log gathering. Winpmem.exe needs to be in the same directory as the script
  ir_artifact_rprt_mem_acq.ps1 all
  
  report - Runs the artifact report
  ir_artifact_rprt_mem_acq.ps1 report
  
  event - Gathers 3 days of Security, System, and Windows PowerShell events and writes them out to a json files.
  Logs gathered:
  Security - 1102, 2004, 2005, 4616, 4624, 4625, 4634, 4648, 4657, 4663, 4688, 4697, 4698, 4699, 4700, 4701, 4702, 4719, 4720, 4722, 4723, 4725, 4728, 4732, 4735, 4737,     4738, 4740, 4755, 4756, 4767, 4772, 4777, 4782, 4946, 4947, 4950, 4954, 4964, 5025, 5031, 5140, 5152, 5153, 5155, 5157, 5447
  System - 7045, 7040
  Windows Powershell - 400, 500
  ir_artifact_rprt_mem_acq.ps1 event
  
  image - Runs winpmem.exe to pull a memory image. Winpmem.exe needs to be in the same directory as the script
  ir_artifact_rprt_mem_acq.ps1 image
</pre>
  
