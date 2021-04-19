# IR_Artifact_Report_MemAquisition

Currently it defaults to report if no argument is given.
The report and the events log collection are working still need to test the memory acquisition.
Have not tested the memory acquisition portion yet it is there but commented out (use at your own risk)

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
  
