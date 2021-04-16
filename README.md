# IR_Artifact_Report_MemAquisition

Currently it defaults to report if no argument is given.
The report and the events log collection are working still need to test the memory acquisition.
Have not tested the memory acquisition portion yet it is there but commented out (use at your own risk)

<pre>
  Use:
  default - No argument - Runs the artifact report
  memacq_artifactrpt.ps1 
  
  all - Runs winpmem.exe, report and event log gathering. Winpmem.exe needs to be in the same directory as the script
  memacq_artifactrpt.ps1 all
  
  report - Runs the artifact report
  memacq_artifactrpt.ps1 report
  
  event - Gathers 3 days of Security, System, and Windows PowerShell events and writes them out to a json files.
  memacq_artifactrpt.ps1 event
  
  
