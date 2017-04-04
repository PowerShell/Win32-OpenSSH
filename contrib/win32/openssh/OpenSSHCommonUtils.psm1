<#
.Synopsis
    Finds the root of the git repository

.Outputs
    A System.IO.DirectoryInfo for the location of the root.

.Inputs
    None

.Notes
    FileNotFoundException is thrown if the current directory does not contain a CMakeLists.txt file.
#>
function Get-RepositoryRoot
{
    $currentDir = (Get-Item -Path $PSCommandPath).Directory

    while ($null -ne $currentDir.Parent)
    {
        $path = Join-Path -Path $currentDir.FullName -ChildPath '.git'
        if (Test-Path -Path $path)
        {
            return $currentDir
        }
        $currentDir = $currentDir.Parent
    }

    throw new-object System.IO.DirectoryNotFoundException("Could not find the root of the GIT repository")
}

Export-ModuleMember -Function Get-RepositoryRoot