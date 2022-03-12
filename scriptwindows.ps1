$CAContent = "CA_CONTENT"
$HostName = "HOST_NAME"
$HostAddress = "HOST_IP_ADDRESS"

try {
    New-Item -Path . -Name "ca.pem" -ItemType "file" -Value $CertificateContent -Force
}
catch {
    Write-Error "An error occurred:"
    Write-Error $_
    Read-Host "Для продолжения нажмите клавишу ENTER ..."
    Break
}

try { 
    Import-Certificate -CertStoreLocation cert:\LocalMachine\Root\ -FilePath ca.pem
    Write-Host "Сертификат центра сертификации VPN сервера успешно установлен" -ForegroundColor Green
}
catch {
    Remove-item ca.pem
    Write-Error "An error occurred:"
    Write-Error $_
    Break
}

Remove-item ca.pem

Remove-VpnConnection -Name $HostName -Force

Add-VpnConnection -Name $HostName -ServerAddress $HostAddress -TunnelType "IKEv2" -AuthenticationMethod "EAP" -EncryptionLevel "Maximum" -RememberCredential `

Set-VpnConnectionIPsecConfiguration -Name $HostName -AuthenticationTransformConstants GCMAES256 -CipherTransformConstants GCMAES256 -DHGroup ECP384 -IntegrityCheckMethod SHA384 -PfsGroup ECP384 -EncryptionMethod GCMAES256

Get-VpnConnection -Name $HostName

Read-Host "Для продолжения нажмите клавишу ENTER ..."
