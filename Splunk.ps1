#
# Splunk.ps1 - Splunk
#


# Maybe needed to trust proxy certificate.
<#Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
#>

$Log_MaskableKeys = @(
    'Password',
    "proxy_password",
    "client_secret"
)

$Properties = @{
    AccountLockoutReport = @(
        @{ name = '_time';                          options = @('default')                      }
        @{ name = 'user';                           options = @('default')                      }
        @{ name = 'Account_Domain';                 options = @('default')                      }
        @{ name = 'Caller_Computer_Name';           options = @('default')                      }
        @{ name = 'ComputerName';                   options = @('default')                      }
    )
}

#
# System functions
#
function Idm-SystemInfo {
    param (
        # Operations
        [switch] $Connection,
        [switch] $TestConnection,
        [switch] $Configuration,
        # Parameters
        [string] $ConnectionParams
    )

    Log info "-Connection=$Connection -TestConnection=$TestConnection -Configuration=$Configuration -ConnectionParams='$ConnectionParams'"

    if ($Connection) {
        @(
            @{
                name = 'hostname'
                type = 'textbox'
                label = 'Hostname'
                description = 'Hostname for Web Services'
                value = 'customer.splunk.com'
            }
            @{
                name = 'client_secret'
                type = 'textbox'
                label = 'Client Secret'
                description = 'Authentication: Client Secret'
                value = ''
            }
            @{
                name = 'use_proxy'
                type = 'checkbox'
                label = 'Use Proxy'
                description = 'Use Proxy server for requets'
                value = $false                  # Default value of checkbox item
            }
            @{
                name = 'proxy_address'
                type = 'textbox'
                label = 'Proxy Address'
                description = 'Address of the proxy server'
                value = 'http://127.0.0.1:8888'
                disabled = '!use_proxy'
                hidden = '!use_proxy'
            }
            @{
                name = 'use_proxy_credentials'
                type = 'checkbox'
                label = 'Use Proxy Credentials'
                description = 'Use credentials for proxy'
                value = $false
                disabled = '!use_proxy'
                hidden = '!use_proxy'
            }
            @{
                name = 'proxy_username'
                type = 'textbox'
                label = 'Proxy Username'
                label_indent = $true
                description = 'Username account'
                value = ''
                disabled = '!use_proxy_credentials'
                hidden = '!use_proxy_credentials'
            }
            @{
                name = 'proxy_password'
                type = 'textbox'
                password = $true
                label = 'Proxy Password'
                label_indent = $true
                description = 'User account password'
                value = ''
                disabled = '!use_proxy_credentials'
                hidden = '!use_proxy_credentials'
            }
            @{
                name = 'nr_of_sessions'
                type = 'textbox'
                label = 'Max. number of simultaneous sessions'
                description = ''
                value = 1
            }
            @{
                name = 'sessions_idle_timeout'
                type = 'textbox'
                label = 'Session cleanup idle time (minutes)'
                description = ''
                value = 1
            }
        )
    }

    if ($TestConnection) {
        
    }

    if ($Configuration) {
        @()
    }

    Log info "Done"
}

function Idm-OnUnload {
}

#
# Object CRUD functions
#

function Idm-AccountLockoutReportRead {
    param (
        # Mode
        [switch] $GetMeta,    
        # Parameters
        [string] $SystemParams,
        [string] $FunctionParams

    )
        $system_params   = ConvertFrom-Json2 $SystemParams
        $function_params = ConvertFrom-Json2 $FunctionParams
        
        if ($GetMeta) {
            Get-ClassMetaData -SystemParams $SystemParams -Class 'AccountLockoutReport'
            
        } else {

            #Retrieve Report
            $uri = "https://$($system_params.hostname)/servicesNS/admin/search/search/jobs/export"
            
            $headers = @{
                "Authorization" = "Bearer $($system_params.client_secret)"
            }

            try {
                $splat = @{
                    Method = "GET"
                    Uri = $uri
                    Headers = $headers
                    Body = @{
                        "search" = 'search index="win*" EventCode="4740"| table _time, user, Account_Domain, Caller_Computer_Name, ComputerName'
                        "earliest_time" = "-24h@h"
                        "latest_time" = "now"
                        "output_mode" =  "csv"
                    }
                }

                if($system_params.use_proxy)
                {
                    $splat["Proxy"] = $system_params.proxy_address

                    if($system_params.use_proxy_credentials)
                    {
                        $splat["proxyCredential"] = New-Object System.Management.Automation.PSCredential ($system_params.proxy_username, (ConvertTo-SecureString $system_params.proxy_password -AsPlainText -Force) )
                    }
                }
                
                $response = Invoke-RestMethod @splat -ErrorAction Stop

                # Assure key is the first column
                $key = ($Global:Properties.AccountLockoutReport | Where-Object { $_.options.Contains('key') }).name
                $properties = $Global:Properties.AccountLockoutReport.Name
                $hash_table = [ordered]@{}

                foreach ($prop in $properties) {
                    log info $prop
                    $hash_table[$prop] = ""
                }

                foreach($rowItem in ($response | ConvertFrom-Csv)) {
                    log info ($rowitem | ConvertTo-Json) 
                    $row = New-Object -TypeName PSObject -Property $hash_table
                    
                    foreach($prop in $rowItem.PSObject.properties) {
                            $row.($prop.Name) = $prop.Value
                        }

                    $row
                }
                

            }
            catch [System.Net.WebException] {
                $message = "Error : $($_)"
                Log error $message
                Write-Error $_
            }
            catch {
                $message = "Error : $($_)"
                Log error $message
                Write-Error $_
            }
        }
}
function Check-SplunkConnection { 
    param (
        [string] $SystemParams
    )
     Open-SplunkConnection $SystemParams
}

function Open-SplunkConnection {
    param (
        [hashtable] $SystemParams
    )
    
   
}

function Get-ClassMetaData {
    param (
        [string] $SystemParams,
        [string] $Class
    )

    @(
        @{
            name = 'properties'
            type = 'grid'
            label = 'Properties'
            table = @{
                rows = @( $Global:Properties.$Class | ForEach-Object {
                    @{
                        name = $_.name
                        usage_hint = @( @(
                            foreach ($opt in $_.options) {
                                if ($opt -notin @('default', 'idm', 'key')) { continue }

                                if ($opt -eq 'idm') {
                                    $opt.Toupper()
                                }
                                else {
                                    $opt.Substring(0,1).Toupper() + $opt.Substring(1)
                                }
                            }
                        ) | Sort-Object) -join ' | '
                    }
                })
                settings_grid = @{
                    selection = 'multiple'
                    key_column = 'name'
                    checkbox = $true
                    filter = $true
                    columns = @(
                        @{
                            name = 'name'
                            display_name = 'Name'
                        }
                        @{
                            name = 'usage_hint'
                            display_name = 'Usage hint'
                        }
                    )
                }
            }
            value = ($Global:Properties.$Class | Where-Object { $_.options.Contains('default') }).name
        }
    )
}
