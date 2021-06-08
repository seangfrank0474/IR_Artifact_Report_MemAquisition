# IR_Artifact_Report_MemAquisition

Currently it defaults to report if no argument is given.
The report and the events log collection are working still need to test the memory acquisition.
Image function has been tested on Windows 10 and Windows 2016 Server with the current version of winpmem.exe

WinPMem
https://github.com/Velocidex/WinPmem/releases/tag/v4.0.rc1

Using 7-Zip to compress all the output (7za.exe)
https://www.7-zip.org/download.html

<dl>
  <dt><b>Uses Winpmem to do memory acquisitions</b></dt>
  <dt><b>Pulls three days of winevents from Security, System, and Windows Powershell</b></dt>
  <dt><b>What is in the Artifact Report:</b></dt>
  <dt><b>Environment:</b></dt>
  <dd><i>Processor</i></dd>
  <dd><i>BIOS</i></dd>
  <dd><i>OS</i></dd>
  <dd><i>Drive</i></dd>
  <dd><i>Windows Defender/AV</i></dd>
  <dd><i>Installed Programs</i></dd>
  <dd><i>Environment Variables</i></dd>
  <dd><i>Local Users/Administrators</i></dd>
  <dt><b>Network:</b></dt>
  <dd><i>Adapters</i></dd>
  <dd><i>Adapters IP Config</i></dd>
  <dd><i>Adapter Components</i></dd>
  <dd><i>Host Firewall Config</i></dd>
  <dd><i>Hosts/Netowrks File</i></dd>
  <dd><i>Routing</i></dd>
  <dd><i>Arp Cache</i></dd>
  <dd><i>SMB Shares</i></dd>
  <dd><i>DNS Cache</i></dd>
  <dd><i>Netstat TCP/UDP</i></dd>
  <dt><b>Processes and Services:</b></dt>
  <dd><i>Running Processes</i></dd>
  <dd><i>Modules loaded on the running processes</i></dd>
  <dd><i>Services</i></dd>
  <dd><i>Scheduled Tasks</i></dd>
  <dt><b>Files and Registry:</b></dt>
  <dd><i>HKLM Auto Run</i></dd>
  <dd><i>HKU Auto Run</i></dd>
  <dd><i>Program Data Start Menu</i></dd>
  <dd><i>Prefetch</i></dd>
  <dd><i>User Downloads/Desktop/Documents</i></dd>
  <dd><i>URL Browser Cache IE/FF/Chrome</i></dd>
  <dd><i>System root/windows/temp/system32/syswow64</i></dd>
  <dd><i>Sha256 of files in the above directories for extenstions - .exe,.com,.dll,.sys,.zip,.rar,.dat,.tar,.gz,.tgz,.bin,.js,.pdf,.doc,.docx,.xls,.xlsx</i></dd>
  <dd><i>Creates a seperate CSV file with the above Sha256 to bulk check with things like Virus Total</i></dd>
</dl>

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
  
