<# 
 Author: manoj.ampalam@microsoft.com

 Description: ssh-add.exe like Powershell utility to do host key management.
 Input parameter mimic ssh-add.exe cmdline arguments. 
 
 Host keys on Windows need to be registered as SYSTEM (i.e ssh-add.exe would 
 need to run as SYSTEM while talking to ssh-agent). This typically requires 
 an external utility like psexec. 

 This script tries to use the Task scheduler option:
  - registers a task scheduler task to run ssh-add.exe operation as SYSTEM
  - actual output of ssh-add.exe is written to file (both stdout and stderr)
  - Dumps the file contents to console

#>

# see https://linux.die.net/man/1/ssh-add for what the arguments mean
[CmdletBinding(DefaultParameterSetName='Add_key')]
Param(    
  [Parameter(ParameterSetName="List_fingerprints")]
  [switch]$List_fingerprints, #ssh-add -l 
  [Parameter(ParameterSetName="List_pubkeys")]
  [switch]$List_pubkeys,      #ssh-add -L 
  [Parameter(ParameterSetName="Delete_key")]
  [switch]$Delete_key,        #ssh-add -d 
  [Parameter(ParameterSetName="Delete_all")]
  [switch]$Delete_all,       #ssh-add -D
  [Parameter(Mandatory, Position=0, ParameterSetName="Delete_key")]
  [Parameter(Mandatory, Position=0, ParameterSetName="Add_key")] 
  [ValidateNotNullOrEmpty()]
  [string]$key
)

$ssh_add_cmd = get-command ssh-add.exe -ErrorAction Ignore
if($ssh_add_cmd -eq $null)
{
    Throw "Cannot find ssh-add.exe."
}

#create ssh-add cmdlinet
$ssh_add_cmd_str = $ssh_add_cmd.Path
if ($List_fingerprints) { $ssh_add_cmd_str += " -l" } 
elseif ($List_pubkeys)      { $ssh_add_cmd_str += " -L" } 
elseif ($Delete_key)        { $ssh_add_cmd_str += " -d $key" } 
elseif ($Delete_all)        { $ssh_add_cmd_str += " -D" } 
else
{
    if ( ($key.Length -gt 0) -and (-not($key.Contains("host"))) ) {
        Do {
            $input = Read-Host -Prompt "Are you sure the provided key is a host key? [Yes] Y; [No] N (default is `"Y`")"
            if([string]::IsNullOrEmpty($input))
            {
                $input = 'Y'
            }        
        } until ($input -match "^(y(es)?|N(o)?)$")
        $result = $Matches[0]
        if (-not($result.ToLower().Startswith('y'))) { exit }            
    }
    $ssh_add_cmd_str += " $key"
}

#globals
$taskfolder = "\OpenSSHUtils\hostkey_tasks\"
$taskname = "hostkey_task"
$ssh_add_output = Join-Path (pwd).Path "ssh-add-hostkey-tmp.txt"
$task_argument = "/c `"$ssh_add_cmd_str > $ssh_add_output 2>&1 `""

#create TaskScheduler task
$ac = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $task_argument -WorkingDirectory (pwd).path
$task = Register-ScheduledTask -TaskName $taskname -User System -Action $ac -TaskPath $taskfolder -Force

#run the task
if (Test-Path $ssh_add_output) {Remove-Item $ssh_add_output -Force}
Start-ScheduledTask -TaskPath $taskfolder -TaskName $taskname

#if still running, wait a little while for task to complete
$num = 0
while ((Get-ScheduledTask -TaskName $taskname -TaskPath $taskfolder).State -eq "Running")
{
    sleep 1
    $num++
    if($num -gt 20) { break }
}
if (-not(Test-Path $ssh_add_output)) {throw "cannot find task output file. Something went WRONG!!! "}

#dump output to console
Get-Content $ssh_add_output

#cleanup task and output file
Remove-Item $ssh_add_output -Force
Unregister-ScheduledTask -TaskPath $taskfolder -TaskName $taskname -Confirm:$false




