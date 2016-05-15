copy .\ssh-lsa.dll $env:windir\system32
$subkey = 'SYSTEM\CurrentControlSet\Control\Lsa'
$value  = 'Authentication Packages'
$reg = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 0)
$key = $reg.OpenSubKey($subkey, $true)
$arr = $key.GetValue($value)
if ($arr -notcontains 'ssh-lsa') {
  $arr += 'ssh-lsa'
  $key.SetValue($value, [string[]]$arr, 'MultiString')
}
