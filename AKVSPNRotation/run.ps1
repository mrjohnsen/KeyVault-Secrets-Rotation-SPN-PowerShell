param($eventGridEvent, $TriggerMetadata)

function RegenerateCredential($credentialId, $providerAddress){
    Write-Host "Regenerating credential. Id: $credentialId Resource Id: $providerAddress"
    
    #Write code to regenerate credential, update your service with new credential and return it

    $bytes = New-Object Byte[] 32
    $rand = ([System.Security.Cryptography.RandomNumberGenerator]::Create()).GetBytes($bytes)
    $newCredentialValue = [System.Convert]::ToBase64String($bytes) | ConvertTo-SecureString -AsPlainText -Force

    return $newCredentialValue
    
    #>
}

function GetAlternateCredentialId($credentialId){
    #Write code to get alternate credential id for your service

   #EXAMPLE FOR STORAGE

   <#
   $validCredentialIdsRegEx = 'key[1-2]'
   
   If($credentialId -NotMatch $validCredentialIdsRegEx){
       throw "Invalid credential id: $credentialId. Credential id must follow this pattern:$validCredentialIdsRegEx"
   }
   If($credentialId -eq 'key1'){
       return "key2"
   }
   Else{
       return "key1"
   }
   #>
}

function AddSecretToKeyVault($keyVAultName,$secretName,$secretvalue,$exprityDate,$tags){
    
     Set-AzKeyVaultSecret -VaultName $keyVAultName -Name $secretName -SecretValue $secretvalue -Tag $tags -Expires $expiryDate

}

function RoatateSecret($keyVaultName,$secretName,$secretVersion){
    #Retrieve Secret
    $secret = (Get-AzKeyVaultSecret -VaultName $keyVAultName -Name $secretName)
    Write-Host "Secret Retrieved"
    
    If($secret.Version -ne $secretVersion){
        #if current version is different than one retrived in event
        Write-Host "Secret version is already rotated"
        return 
    }

    #Retrieve Secret Info
    $validityPeriodDays = $secret.Tags["ValidityPeriodDays"]
    $credentialId=  $secret.Tags["CredentialId"]
    $providerAddress = $secret.Tags["ProviderAddress"]
    
    Write-Host "Secret Info Retrieved"
    Write-Host "Validity Period: $validityPeriodDays"
    Write-Host "Credential Id: $credentialId"
    Write-Host "Provider Address: $providerAddress"

    #Regenerate alternate access credential in provider
    $newCredentialValue = (RegenerateCredential $credentialId $providerAddress)
    Write-Host "Credential regenerated. Credential Id: $credentialId Resource Id: $providerAddress"

    #Add new credential to Key Vault
    $newSecretVersionTags = @{}
    $newSecretVersionTags.ValidityPeriodDays = $validityPeriodDays
    $newSecretVersionTags.CredentialId=$CredentialId
    $newSecretVersionTags.ProviderAddress = $providerAddress

    $expiryDate = (Get-Date).AddDays([int]$validityPeriodDays).ToUniversalTime()
    $secretvalue = $newCredentialValue
    AddSecretToKeyVault $keyVAultName $secretName $secretvalue $expiryDate $newSecretVersionTags

    Write-Host "New credential added to Key Vault. Secret Name: $secretName"

    # Reset password in Azure AD App Credential
    Remove-AzADAppCredential -ObjectId $providerAddress -Force
    New-AzADAppCredential -ObjectId $providerAddress -Password $secretvalue -startDate $(get-date) -EndDate $expiryDate
}
$ErrorActionPreference = "Stop"
# Make sure to pass hashtables to Out-String so they're logged correctly
$eventGridEvent | ConvertTo-Json | Write-Host

$secretName = $eventGridEvent.subject
$secretVersion = $eventGridEvent.data.Version
$keyVaultName = $eventGridEvent.data.VaultName

Write-Host "Key Vault Name: $keyVAultName"
Write-Host "Secret Name: $secretName"
Write-Host "Secret Version: $secretVersion"

#Rotate secret
Write-Host "Rotation started."
RoatateSecret $keyVAultName $secretName $secretVersion
Write-Host "Secret Rotated Successfully"