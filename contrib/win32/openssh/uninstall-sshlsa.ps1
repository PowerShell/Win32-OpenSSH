$subkey = 'SYSTEM\CurrentControlSet\Control\Lsa'
$value  = 'Authentication Packages'
$reg = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 0)
$key = $reg.OpenSubKey($subkey, $true)
$arr = $key.GetValue($value)
if ($arr -contains 'ssh-lsa') {
  $tempArryList = New-Object System.Collections.Arraylist(,$arr)
  $tempArryList.Remove('ssh-lsa')
  $key.SetValue($value, [string[]]$tempArryList, 'MultiString')
}
