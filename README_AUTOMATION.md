# GitHub Automation (v6)

## Modes
- `-DryRun` : print steps, no changes
- `-Start`  : run local proof, fork/clone, branch, push, create Issue + PR
- `-Stop`   : cleanup work dir

## Usage
```powershell
cd <v6 folder>
Set-ExecutionPolicy -Scope Process Bypass -Force
.\gh-automation.ps1 -Start
```
Add your GitHub CLI auth first:
```powershell
winget install --id GitHub.cli
gh auth login
```
