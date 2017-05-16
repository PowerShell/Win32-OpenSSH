Run OpenSSH Pester Tests:
==================================

#### To setup the test environment before test run:

```powershell
Import-Module  .\openssh-portable\contrib\win32\openssh\OpenSSHTestHelper.psm1 –Force
Setup-OpenSSHTestEnvironment
```

`Setup-OpenSSHTestEnvironment` contains below parameters:
* `-OpenSSHBinPath`: Specify the location where ssh.exe should be picked up. If not specified, the function will prompt to user if he/she want to choose the first ssh.exe found in `$env:path` if exists.
* `-TestDataPath`: Specify the location where the test binaries deploy to. The default is `$env:SystemDrive\OpenSSHTests` if it not specified.
* `-Quiet`: If it is set, the function will do all the changes without prompting to user to confirm.
* `-DebugMode`: If it is set, the subsequent tests will be running in debug mode. User can modify by setting $OpenSSHTestInfo["DebugMode"] .

#### To run the test suites:

```powershell
Run-OpenSSHE2ETest
Run-OpenSSHUnitTest
```

#### To run a particular test, just run the script or the executatlbe directly

```powershell
C:\git\openssh-portable\regress\pesterTests\SCP.Tests.ps1
C:\git\openssh-portable\bin\x64\Release\unittest-bitmap\unittest-bitmap.exe
```

#### To verify / modify (Ex- DebugMode) the Test setup environment 

```powershell
$OpenSSHTestInfo
$OpenSSHTestInfo["DebugMode"] = $true
```

#### To revert what's done in Setup-OpenSSHTestEnvironment:

```powershell
Cleanup-OpenSSHTestEnvironment
```


#### Guidelines for writing Pester based OpenSSH test cases
Follow these simple steps for test case indexing
- Initialize the following variables at start
```  
  $tC = 1
  $tI = 0
```
- Place the following blocks in Describe
```
    BeforeEach {
        $stderrFile=Join-Path $testDir "$tC.$tI.stderr.txt"
        $stdoutFile=Join-Path $testDir "$tC.$tI.stdout.txt"
        $logFile = Join-Path $testDir "$tC.$tI.log.txt"
    }        
    AfterEach {$tI++;}
```
- Place the following blocks in each Context
```
  BeforeAll {$tI=1}
  AfterAll{$tC++}
```
- Prefix any test out file with $tC.$tI. You may use pre-created $stderrFile, $stdoutFile, $logFile for this purpose
