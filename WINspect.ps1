                                      ############# WINspect #############
                                      #------ beta version
                                      #------ Author : A-mIn3



#  This script is part of a larger project for auditing different areas of Windows environments.
#  It focuses on enumerating different parts of a Windows machine aiming to identify security weaknesses 
#  and point to components that that need further hardening. The main targets for the script are domain-joined 
#  windows machines. Howerver, some of the functions can also be invoked for standalone workstations.
  


[Console]::ForegroundColor="White"
[Console]::BackGroundColor="Black"


[System.String]$scriptDirectoryPath  = split-path -parent $MyInvocation.MyCommand.Definition
[System.String]$secpolFilePath       = join-path $scriptDirectoryPath "secedit.log"
[System.String]$reportFilePath       = join-path $scriptDirectoryPath "report-$env:COMPUTERNAME.txt"
[System.String]$exceptionsFilePath   = join-path $scriptDirectoryPath "exceptions-$env:COMPUTERNAME.txt"



[System.String]$culture=(Get-Culture).Name

$PSVersion=$PSVersionTable.PSVersion.Major

[int]$systemRoleID = $(get-wmiObject -Class Win32_ComputerSystem).DomainRole

$systemRoles = @{
                        0         =    " Standalone Workstation    " ;
                        1         =    " Member Workstation        " ;
                        2         =    " Standalone Server         " ;
                        3         =    " Member Server             " ;
                        4         =    " Backup  Domain Controller " ;
                        5         =    " Primary Domain Controller "       
                }



function initialize-audit {
    
    clear-host
     
    SecEdit.exe /export /cfg $secpolFilePath /quiet
     
    $start = get-date 
    
    sleep 1 
   
    write-host "Starting Audit at", $start
    "-------------------------------------`n"
   
    sleep 2

    Write-Host "[?] Checking for administrative privileges ..`n" -ForegroundColor black -BackgroundColor white  ; sleep 1

    $isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if(!$isAdmin){
            
            "[-] Some of the operations need administrative privileges.`n"
            
            "[*] Please run the script using an administrative account.`n"
            
            Read-Host "Type any key to continue .."

            exit
    
    }
    write-host "[?] Checking for Default PowerShell version ..`n" -ForegroundColor black -BackgroundColor white  ; sleep 1
   
    
    if($PSVersion -lt 2){
       
        Write-Warning -Message "       [!] You have PowerShell v1.0.`n"
        
        write-warning -Message "       [!]This script only supports Powershell verion 2 or above.`n"
        
        read-host "Type any key to continue .."
        
        exit  
   
    }
   
    write-host "       [+] ----->  PowerShell v$PSVersion`n" ; sleep 1
  
    write-host "[?] Detecting system role ..`n" -ForegroundColor black -BackgroundColor white ; sleep 1
  
    $systemRoleID = $(get-wmiObject -Class Win32_ComputerSystem).DomainRole
    
    if($systemRoleID -ne 1){
    
            "       [-] This script needs access to the domain. It can only be run on a domain member machine.`n"
           
            Read-Host "Type any key to continue .."
            
            exit
        
    }
    
    write-host "       [+] ----->",$systemRoles[[int]$systemRoleID],"`n" ; sleep 1
   
    get-LocalSecurityProducts
    
    get-WorldExposedLocalShares 

    check-LocalMembership

    check-UACLevel

    check-autoruns

    get-BinaryWritableServices -display

    get-ConfigurableServices   -display

    get-UnquotedPathServices   -display

    check-HostedServices       -display

    check-DLLHijackability     

    
    $fin = get-date
    
    "`n[!]Done`n"; sleep 1
    
    "Audit completed in {0} seconds. `n" -f $(New-TimeSpan -Start $start -End $fin ).TotalSeconds
    
}


function get-LocalSecurityProducts
{

       <#    

		    .SYNOPSIS

				Gets Windows Firewall Profile status and checks for installed third party security products.
			
        
	        .DESCRIPTION
                This function operates by examining registry keys specific to the Windows Firewall and by using the 
               Windows Security Center to get information regarding installed security products. 
	            
            
            .NOTE
              
                The documentation in the msdn is not very clear regarding the productState property provided by
              the SecurityCenter2 namespace.
              For this reason, This function only uses available informations that were obtained by testing 
              different security products againt the Windows API. 
                            



            .LINK
                      http://neophob.com/2010/03/wmi-query-windows-securitycenter2
	  
      #>



	           $firewallPolicySubkey="HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy"
               
               
               Write-host "`n[?] Checking if Windows Firewall is enabled ..`n"     -ForegroundColor black -BackgroundColor white ; ""; sleep 2
               
               
               write-host "       [?] Checking Firewall Profiles ..`n" -ForegroundColor black -BackgroundColor white ; "" ; sleep 2
               
            
               if(Test-Path -Path $($firewallPolicySubkey+"\StandardProfile")){
              
              
                            $enabled = (Get-ItemProperty -Path $($firewallPolicySubkey+"\StandardProfile") -Name EnableFirewall).EnableFirewall  
              
                            if($enabled -eq 1){$standardProfile="Enabled"}else{$standardProfile="Disabled"}
              
                            "                   [*] Standard Profile  Firewall     :  {0}.`n" -f $standardProfile
              }else{
                    
                            Write-Warning "[-] Could not find Standard Profile Registry Subkey.`n"
              }    
             
             
              if(Test-Path -Path $($firewallPolicySubkey+"\PublicProfile")){
                   
                            $enabled = (Get-ItemProperty -Path $($firewallPolicySubkey+"\PublicProfile") -Name EnableFirewall).EnableFirewall  
                           
                            if($enabled -eq 1){$publicProfile="Enabled"}else{$publicProfile="Disabled"}
                           
                            "                   [*] Public   Profile  Firewall     :  {0}.`n" -f $publicProfile
              }else{
                            Write-Warning "[-] Could not find Public Profile Registry Subkey.`n"
             
              }

                 
              if(Test-Path -Path $($firewallPolicySubkey+"\DomainProfile")){
                     
                            $enabled = (Get-ItemProperty -Path $($firewallPolicySubkey+"\DomainProfile") -Name EnableFirewall).EnableFirewall  
              
                            if($c -eq 1){$domainProfile="Enabled"}else{$domainProfile="Disabled"}
              
                            "                   [*] Domain   Profile  Firewall     :  {0}.`n`n" -f $domainProfile
              }else{
                    
                            Write-Warning "[-] Could not find Private Profile Registry Subkey.`n`n"
              }              
               
               
      
            
             sleep 2 
            
             
             $SecurityProvider=@{
               
                                   "00"     =   "None";
                                   "01"     =   "Firewall";
                                   "02"     =   "AutoUpdate_Settings";
                                   "04"     =   "AntiVirus";           
                                   "08"     =   "AntiSpyware";
                                   "10"     =   "Internet_Settings";
                                   "20"     =   "User_Account_Control";
                                   "40"     =   "Service"
               
              }
               
               
                
              $RealTimeBehavior = @{
                                    
                                  "00"    =    "Off";
                                  "01"    =    "Expired";
                                  "10"    =    "ON";
                                  "11"    =    "Snoozed"
               
              }
               
              $DefinitionStatus = @{
              
                                 "00"     =     "Up-to-date";
                                 "10"     =     "Out-of-date"
              
              
              }
               
              $securityCenterNS="root\SecurityCenter"
             
            
             
              [System.Version]$OSVersion=(Get-WmiObject -class Win32_operatingsystem).Version
              
              if($OSVersion -gt [System.Version]'6.0.0.0'){$SecurityCenterNS+="2"}
              
              
              # checks for third party firewall products 
 
              write-host "`n[?] Checking for third party Firewall products .. `n" -ForegroundColor Black -BackgroundColor White; sleep 1
              
              $firewalls= @(Get-WmiObject -Namespace $securityCenterNS -class FirewallProduct)
           
              if($firewalls.Count -eq 0){
            
             
                        "       [-] No other firewall installed.`n"
            
              }
            
              else {
             
             
                        "       [+] Found {0} third party firewall products.`n"  -f $($firewalls.Count); sleep 1     
             
                
                        write-host "            [?] Checking for product configuration ...`n" -ForegroundColor black -BackgroundColor white ; sleep 1
            
             
                        $firewalls|%{
               
                          
                                if($securityCenterNS.endswith("2")){
                                            
                                         [int]$productState=$_.ProductState
                          
                                         $hexString=[System.Convert]::toString($productState,16).padleft(6,'0')
                          
                                         $provider=$hexString.substring(0,2)
                          
                                         $realTimeProtec=$hexString.substring(2,2)
                          
                                         $definition=$hexString.substring(4,2)
                                         
                                         "                     [+] Product Name          : {0}."     -f $_.displayName
                                         "                     [+] Service Type          : {0}."     -f $SecurityProvider[[String]$provider]
                                         "                     [+] State                 : {0}.`n`n" -f $RealTimeBehavior[[String]$realTimeProtec]
                                      
                                   
          

                            
                                }else{
                            
                                         "                     [+] Company Name           : {0}."     -f $_.CompanyName
                                         "                     [+] Product Name           : {0}."     -f $_.displayName
                                         "                     [+] State                  : {0}.`n`n" -f $_.enabled
                                                              
                            
                                }
                           
               
                    }
              



              }
            
              sleep 2
  
              # checks for antivirus products

              write-host "`n[?] Checking for installed antivirus products .."-ForegroundColor Black -BackgroundColor white ;""; sleep 2

              
              $antivirus=@(Get-WmiObject -Namespace $securityCenterNS -class AntiVirusProduct)
              
              
              if($antivirus.Count -eq 0){
                
                  
                        "       [-] No antivirus product installed.`n`n"; sleep 1       
              
              }else{
              
                        "       [+] Found {0} AntiVirus solutions.`n" -f $($antivirus.Count); sleep 1
              
              
                        write-host "            [?] Checking for product configuration ..`n" -ForegroundColor black -BackgroundColor white ; sleep 2
              
              
                        $antivirus|foreach-object{
               
                                
                                if($securityCenterNS.endswith("2")){
                                            
                                         [int]$productState=$_.ProductState
                                       
                                         $hexString=[System.Convert]::toString($productState,16).padleft(6,'0')
                                       
                                         $provider=$hexString.substring(0,2)
                                       
                                         $realTimeProtec=$hexString.substring(2,2)
                                       
                                         $definition=$hexString.substring(4,2)
                                         
                                         "                     [+] Product Name          : {0}."     -f $_.displayName
                                         "                     [+] Service Type          : {0}."     -f $SecurityProvider[[String]$provider]
                                         "                     [+] Real Time Protection  : {0}."     -f $RealTimeBehavior[[String]$realTimeProtec]
                                         "                     [+] Signature Definitions : {0}.`n`n" -f $DefinitionStatus[[String]$definition]
                                         
                                         
          

                            
                                }else{
                            
                                         "                     [+] Company Name           : {0}."     -f $_.CompanyName
                                         "                     [+] Product Name           : {0}."     -f $_.displayName
                                         "                     [+] Real Time Protection   : {0}."     -f $_.onAccessScanningEnabled
                                         "                     [+] Product up-to-date     : {0}.`n`n" -f $_.productUpToDate
                            
                                }
                           
                        
               
                       }
               
                
              }


          # Checks for antispyware products

	      write-host "`n[?] Checking for installed antispyware products ..`n"-ForegroundColor Black -BackgroundColor white ; sleep 2
            
         
          $antispyware=@(Get-WmiObject -Namespace $securityCenterNS -class AntiSpywareProduct)
         
              
          if($antispyware.Count -eq 0){
          
         
                     "       [-] No antiSpyware product installed.`n`n"; sleep 1       
         
         
          }else{
     
            
                     "       [+] Found {0} antiSpyware solutions.`n" -f $($antiSpyware.Count); sleep 1
    
          
               
                     write-host "            [?] Checking for product configuration ..`n" -ForegroundColor black -BackgroundColor white ; sleep 2
              
          
                     $antispyware|foreach-object{
               
                             
                               if($securityCenterNS.endswith("2")){
                                            
                                         [int]$productState=$_.ProductState
                                         
                                         $hexString=[System.Convert]::toString($productState,16).padleft(6,'0')
                                         
                                         $provider=$hexString.substring(0,2)
                                         
                                         $realTimeProtec=$hexString.substring(2,2)
                                         
                                         $definition=$hexString.substring(4,2)
                                         
                                         "                     [+] Product Name          : {0}."     -f $_.displayName
                                         "                     [+] Service Type          : {0}."     -f $SecurityProvider[[String]$provider]
                                         "                     [+] Real Time Protection  : {0}."     -f $RealTimeBehavior[[String]$realTimeProtec]
                                         "                     [+] Signature Definitions : {0}.`n`n" -f $DefinitionStatus[[String]$definition]
                                         
                                         
          

                            
                               }else{
                            
                                         "                     [+] Company Name           : {0}."     -f $_.CompanyName
                                         "                     [+] Product Name           : {0}."     -f $_.displayName
                                         "                     [+] Real Time Protection   : {0}."     -f $_.onAccessScanningEnabled
                                         "                     [+] Product up-to-date     : {0}.`n`n" -f $_.productUpToDate
                            
                               }
                           
                            
               
                    }



         }


}


function get-WorldExposedLocalShares

{

	<#

		.SYNOPSIS
			
            Gets informations about local shares and their associated DACLs.

		.DESCRIPTION
			
            This function checks local file system shares and collects informations
		    about each Access Control Entry (ACE) looking for those targeting the Everyone(Tout le monde) group.
            
       
        .NOTE
			
            This function can be modified in a way that for each share we
 		    return its corresponding ace objects for further processing.

        .LINK
            
            https://msdn.microsoft.com/en-us/library/windows/desktop/aa374862(v=vs.85).aspx

	#>

	$permissionFlags = @{

                    1               =     "Read-List";
                    2               =     "Write-Create";
                    4               =     "Append-Create Subdirectory";
                    8               =     "Read extended attributes";
                   16               =     "Write extended attributes";
                   32               =     "Execute file-Traverse directory";
                   64               =     "Delete directory";
                  128               =     "Read file attributes";
                  256               =     "Change file attributes";
                65536               =     "Delete";
               131072               =     "Read access to the security descriptor and owner";
               262144               =     "Write access to DACL";
               524288               =     "Assigns the write owner";
              1048576               =     "Synchronizes access"





    }


    $aceTypes = @{
             
                0 = "Allow";
                1 = "Deny"
 
    }
    
    $exists = $false
   
    $rules=@()

    Write-Host "`n[?] Checking for World-exposed local shares ..`n" -ForegroundColor black -BackgroundColor White ; sleep 2

    try{
 
             Get-WmiObject -class Win32_share -Filter "type=0"|%{
                   
                    $rules=@()
                   
                    $shareName = $_.Name
                 
                    $shareSecurityObj = Get-WmiObject -class Win32_LogicalShareSecuritySetting -Filter "Name='$shareName'"
                   
                    $securityDescriptor = $shareSecurityObj.GetSecurityDescriptor().Descriptor
 
                    ForEach($ace in $securityDescriptor.dacl){
 
                            # Looking for Everyone group (SID="S-1-1-0") permissions 
                            
                            $trusteeSID = (New-Object System.Security.Principal.SecurityIdentifier($ace.trustee.SID, 0)).Value.ToString()
                            
                            if($trusteeSID -eq "S-1-1-0"){

                                    $accessMask  = $ace.accessmask
                            
                                    $permissions =""
                            
                                    foreach($flag in $permissionFlags.Keys){

                                            if($flag -band $accessMask){
                                          
                                                    $permissions+=$permissionFlags[$flag]
                                          
                                                    $permissions+="$"
                                            }
 
                                    }

                                    $rule = New-Object  PSObject -Property @{
                                
                                        "ShareName"    =  $shareName
                                        
                                        "Trustee"      =  $ace.trustee.Name
                                       
                                        "AceType"      =  $aceTypes[[int]$ace.aceType]
                                
                                        "Permissions"  =  $permissions
                                    }
                         


                                    $rules+=$rule

                                    $exists=$true

                            }

                  
            
                    }

                     if($rules.Count -gt 0){
           
                               "[*]-----------------------------------------------------------------------------[*]"
                               
                                $rules| fl ShareName,Trustee,AceType,Permissions
            
                     }

        }

        if(!$exists){
        
                "       [-] No local World-exposed shares were found .`n`n"
        }
    
    
    
    
   }catch{

                "[-] Unable to inspect local shares. "
    }

}


$global:local_member = $false

 function check-LocalMembership{

            <#
                
                .SYNOPSIS
                    
                     Gets domain users and groups with local group membership.
                        
                
                 .Description
                      
                      This function checks local groups on the machine for domain users/groups who are members in a local group.
                      It uses ADSI with the WinNT and LDAP providers to access user and group objects.
                  
                  .NOTE 
                       The machine must be a domain member.
                       This is needed in order to resolve the identity references of domain members.
            
            #>
           
       
         
            
            write-host "`n[?] Checking for domain users with local group membership ..`n" -ForegroundColor Black -BackgroundColor White ; sleep 1

           
            $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"

           
            $adsigroups= $adsi.Children|? {$_.SchemaClassName -eq "group"}

           
            $adsigroups|%{

                          check-GroupLocalMembership $_

            }

            
            if($global:local_member -eq $false){
                    
                   "       [-] Found no domain user or group with local group membership."
              
            
            }
            
            "`n`n"
   
   
   }


   function check-GroupLocalMembership($group) {

                    <#
                            .SYNOPSIS
                                    
                                   Given a specific  ADSI group object, it checks whether it is a local or domain 
                                   group and looks fro its members.

                            .DESCRIPTION
                                   
                                   This function is used by the get-LocalMembership function for inspecting nested
                                   groups membership.
                    
                    
                    #>

                   $groupName=$group.GetType.Invoke().InvokeMember("Name","GetProperty", $null, $group, $null)
                  
                  
                   $GroupMembers = @($group.invoke("Members"))
                   
                  
                   $GroupMembers|% {

                           
                            $adspath = $_.GetType.Invoke().InvokeMember("ADsPath", "GetProperty", $null, $_, $null)

                            $sidBytes = $_.GetType.Invoke().InvokeMember("ObjectSID", "GetProperty", $null, $_, $null)
              
                            $subjectName = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes,0)).Translate([System.Security.Principal.NTAccount])

                            if($_.GetType.Invoke().InvokeMember("class", "GetProperty", $null, $_, $null) -eq "group"){

                                       # check if we have a local group object
                                       
                                       if($adspath -match "/$env:COMPUTERNAME/") {

                                                check-LocalGroupMembership $_

                                       # It is a domain group, no further processing needed 
                                       
                                       }else{
                                             
                                                                          
                                                Write-Host "          [+] Domain group ",$subjectName," is a member in the",$groupName,"local group.`n"

                                                $global:local_member=$true
                                       }


                            }else {
                       
                                      # if not a group, then it must be a user


                                      if( !($adspath -match $env:COMPUTERNAME)){
                                           
                              
                                                Write-Host "          [+] Domain user  ",$subjectName,"is a member of the",$groupName,"local group.`n"
                                        
                                                $global:local_member=$true
                                             
                                      }


                            }

                   }

 }



function check-UACLevel{

            <#
                    .SYNOPSIS
                            Checks current configuration of User Account Control.

                    .Description
                            This functions inspects registry informations related to UAC configuration 
                            and checks whether UAC is enabled and which level of operation is used.

            #>
        
        
        Write-Host "`n[?] Checking for UAC configuration ..`n" -ForegroundColor Black -BackgroundColor White; sleep 2
         
        $UACRegValues = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
              
               if([int]$UACRegValues.EnableLUA -eq 1){
             
                     "       [+] UAC is enabled.`n"
               }
               
               else{
               
                     "       [-] UAC is disabled.`n"
               
               }
                             
              
               Write-Host "            [?]Checking for UAC level ..`n" -ForegroundColor black -BackgroundColor white ; sleep 2
  
               $consentPrompt=$UACregValues.ConsentPromptBehaviorAdmin
              
               $SecureDesktop=$UACregValues.PromptOnSecureDesktop
               
               if( $consentPrompt -eq 0 -and $SecureDesktop -eq 0){
                            
                          "                          [*] UAC Level : Never Notify.`n`n"
              
               }
               elseif($consentPrompt -eq 5 -and $SecureDesktop -eq 0){
                          
                          "                          [*] UAC Level : Notify only when apps try to make changes (No secure desktop).`n`n"
              
               }
               elseif($consentPrompt -eq 5 -and $SecureDesktop -eq 1){
                          
                          "                          [*] UAC Level : Notify only when apps try to make changes (secure desktop on).`n`n"
              
               }
               elseif($consentPrompt -eq 5 -and $SecureDesktop -eq 2){
               
                          "                          [*] UAC Level : Always Notify with secure desktop.`n`n"
               }

              
               sleep 2

}


function check-DLLHijackability{ 


            <#
                    .SYNOPSIS
                            Checks DLL Search mode and inspects permissions for directories in user and system %PATH% .
            
                    .DESCRIPTION
                            This functions tries to identify if DLL Safe Search is used and inspects 
                            write access to directories in the path environment variable .
                            It also looks for any DLLs in these directories excluding the system32 subtree.
            
            
            #>
        
            write-host "`n[?] Checking for DLL hijackability ..`n" -ForegroundColor Black -BackgroundColor White ; sleep 1
            
       
            write-host "       [?] Checking for Safe DLL Search mode ..`n" -ForegroundColor Black -BackgroundColor White ; sleep 1
   
            
            $value = Get-ItemProperty 'HKLM:\SYSTEM\ControlSet001\Control\Session Manager\' -Name SafeDllSearchMode -ErrorAction SilentlyContinue
                   
                   if($value -and ($value.SafeDllSearchMode -eq 0)){
                         
                           
                                "                [+] DLL Safe Search is disabled !`n"      
           
                   }else {
                   
                                "                [+] DLL Safe Search is enabled !`n"
                   
                 
                   }

   
            
                       
            Write-Host "       [?] Checking directories in PATH environment variable ..`n" -ForegroundColor black -BackgroundColor white; sleep 1
           
            $systemPath = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).PATH
           
            $userPath   = Get-Content Env:\Path
           
            
            $userPath.split(";")| %{
  
                $directory = $_
             
                try{
                          
                            $randomfile= "$(Get-Random).txt"
                           
                            New-Item -Path $directory -Name $randomfile -ErrorAction stop > $null
                            
                            $writable=$true

                        
                }catch{
                
                            $writable=$false
                
                
                }finally{
                       
                          if($writable -eq $true){
                          
                                Remove-Item -Path $(Join-Path $directory $randomfile) -ErrorAction SilentlyContinue
                          }
                          
                           if($systemPath -match [regex]::Escape($directory)){
                                
                                     $type= "System Path"
                        
                           }else{
                                    
                                     $type="User   Path"
                               
                           }

                          $item = New-Object psobject -Property @{
                                
                                 "Directory"       = $directory
                                
                                 "Writable"        = $writable
                                
                                 "Path Variable"   = $type
                          
                          }

                          $item
              
                }
            
          
          
          } | ft Directory , Writable, "Path Variable" 
              
          
         ""
     
 }


function get-BinaryWritableServices{
      
        param([switch]$display)
        
        <#
              .SYNOPSIS
                    Gets services whose binaries are writable by current user.
                    
              .DESCRIPTION
                    This function checks services that have writable binaries and returns an array 
                    containing service objects.
                
              .RETURN
                    When invoked without the $display switch, returns a hashtable of {name : pathname}
                    couples.
        
        
        #>
        
        
       
        [array]$writableServices=@()

        # Services to be ignored are those in system32 subtree
       
        $services = Get-WmiObject -Class Win32_Service|?{$_.pathname -ne $null -and $_.pathname -notmatch ".*system32.*" }

        if($services){

                $services | % {

                        # We can't get a clear answer by only using the ACL access property
                        # Howerver We can try to open the binary for writing and catch exception if any

                        try{
                             $pathname = $_.pathname.subString(0, $_.pathname.IndexOf(".exe")+4)
                           
                             [io.file]::OpenWrite($pathname).close()

                             $writableServices+=$_

                        }catch{
                                # what a about an already opened file?

                                     if($_.toString().contains("by another process")){

                                                $writableServices+=$_
                                     }

                        }

               }

       }

       if ($display){

                Write-Host "`n[?] Checking for binary-writable services ..`n" -ForegroundColor Black -BackgroundColor White ; sleep 1

                if($writableServices.Count -gt 0){

                            $writableServices|ft @{Expression={$_.name};Label="Name";width=12}, `
                                               
                                                 @{Expression={$_.pathname};Label="Path"}
                                                 
                                                 ""
                }else{

                         "       [-] Found no binary-writable service."

                }

        }else{

             return $writableServices

        }
        
        "`n`n"

}


function get-UnquotedPathServices {

           param([switch]$display)

           <#

                        .SYNOPSIS
                                Looks for services with unquoted path vulnerability .


                        .Description
                                This function gets all services with unquotted pathnames and displaysm.
                                If display switch is used, it displays the name, state, start mode and pathname informations,
                                otherwise it returns a array of the vulnerable services.


                        .RETURN
                               When invoked without the $display switch, returns a hashtable of {name: pathname}
                               couples.
           #>



      [array]$services = Get-WmiObject -Class Win32_Service| ? {

                                                  $_.pathname.trim() -ne "" -and
                                                
                                                  $_.pathname.trim() -notmatch '^"' -and
                                                
                                                  $_.pathname.subString(0, $_.pathname.IndexOf(".exe")+4) -match ".* .*"

                                            }


      if($display){

                Write-Host "`n[?] Checking for unquoted path services ..`n" -ForegroundColor Black -BackgroundColor White ; sleep 1

                if($services.Count -gt 0){
                             
                              $services|ft  @{Expression={$_.name};Label="Name";width=12}, `
                           
                                            @{Expression={$_.state};Label="Sate";width=12}, `
                           
                                            @{Expression={$_.StartMode};Label="Start Mode";width=12}, `
                           
                                            @{Expression={$_.pathname};Label="Path"} ;
                               
                             ""
                }else{

                        "          [-] Found no service with unquoted pathname."
                }

                "`n`n"
       
       }else{
              
                return $services
       
       }


}



function get-ConfigurableServices{

            param([Switch]$display)

            <#

                        .SYNOPSIS
                               Gets all services that the current user can configure

                        .DESCRIPTION
                                 This function tries to enumerate services for which configuration
                               properties can be modified by the user . For example in our case, we try to modify
                               the displayname of the service unsing the sc.exe utility.

                        .RETURN
                               When invoked without the $display switch, returns a hashtable of {name: pathname}
                               couples.

            #>

            $configurable=@{}

            Get-WmiObject -Class Win32_Service| ? { $_.pathname -notmatch ".*system32.*"}| % {

                  sc.exe config $_.Name DisplayName= $($_.Name)  > $null

                  if($? -eq $true){

                            $configurable[$_.Name] = $_.pathname.substring(0, $_.pathname.indexOf(".exe")+4)
                  }

            }

            if($display){

                  Write-Host "`n[?] Checking for configurable services ..`n" -ForegroundColor Black -BackgroundColor White ; sleep 1
                  
                  if($configurable.Count -gt 0){

                          $configurable.GetEnumerator() | ft  @{Expression={$_.name};Label="Name"}, `
                                                              @{Expression={$_.value};Label="Path"} ;

                  }else {
                                   
                                   "       [-] Found no configurable services."

                  }

                  "`n`n"
            
            }else {

                     return $configurable

            }

 
}
       

function check-HostedServices {
  
        param([Switch]$display)
        <#
        
                .SYNOPSIS
            
                        Checks hosted services running DLLs not located in the system32 subtree.

                .DESCRIPTION
            
                        This functions tries to identify whether there are any configured hosted 
                        services based on DLLs not in system32.
                
                .RETURNS
            
                       When invoked without the $display switch, returns 
                       PSobject array containing the service name, service groupname 
                       and the service DLL path. 
        
        #>
       
       
        $exits=$false
       
        $svcs=@()
        
        $services = Get-WmiObject -Class Win32_service | ?{ $_.pathname -match "svchost\.exe" -and $(Test-Path $("HKLM:\SYSTEM\CurrentControlSet\Services\"+$_.Name+"\Parameters")) -eq $true}
        
        Write-Host "`n[?] Checking hosted services (svchost.exe) ..`n" -ForegroundColor Black -BackgroundColor White ; sleep 1 
       
        if($services){
        
                foreach($service in $services){
                
                        $serviceName  = $service.Name 
              
                        $serviceGroup = $service.pathname.split(" ")[2]
                   
                        $serviceDLLPath=$(Get-ItemProperty $("HKLM:\SYSTEM\CurrentControlSet\Services\"+$service.Name+"\Parameters") -Name ServiceDLL).ServiceDLL
                        
                        if($serviceDLLPath -ne $null -and $serviceDLLPath -notmatch ".*system32.*"){ 
                              
                              $svcs+= New-Object psobject -Property @{
                            
                                    serviceName    = $serviceName
       
                                    serviceGroup   = $serviceGroup
       
                                    serviceDLLPath = $serviceDLLPath
                        
                             }
                       
                             $exits=$true
                       
                        }
               
                }

                
                if($display){   
                         
                         $svcs|ft *
                         
                         "`n`n"
                
                }else{
                         return $svcs
                
                }
        
        
        }
        
        if(! $exits){
        
                   "          [-] Found no user hosted services.`n"
                    
        
        }

  
}

function check-autoruns {

         <#
                 .SYNOPSIS
                    
                         Looks for autoruns specified in different places in the registry.
                         
                 .DESCRIPTION
                    
                         This function inspects common registry keys used for autoruns.
                         It examines the properties of these keys and report any found executables along with their pathnames.
         
                 
         #>

    
         $RegistryKeys = @( 
                            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
                            "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
                            "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
                            "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell",
                            "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell",
                            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\",
                            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\",
                            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
                            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices\",
                            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
                            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
                            "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\load",
                            "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows",
                            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler",
                            "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs"   # DLLs specified in this entry can hijack any process that uses user32.dll 
                            
                             # not sure if it is all we need to check!
                     )


         
         $exits=$false

         Write-Host "`n[?] Cheking registry keys for autoruns ..`n" -ForegroundColor Black -BackgroundColor White ; sleep 1

         $RegistryKeys | %{

                     $key = $_

                     if(Test-Path -Path $key){

                               $executables = @{}

                               [array]$properties = get-item $key | Select-Object -ExpandProperty Property

                               if($properties.Count -gt 0){


                                                     "          [*] $key : "

                                                    foreach($exe in $properties) {

                                                           $executables[$exe]=$($(Get-ItemProperty $key).$exe)

                                                    }

                                                    $executables | ft  @{Expression={$_.Name};Label="Executable"}, `
                                                                       @{Expression={$_.Value};Label="Path"}

                                                    $exits=$true

                                }

                     }


         }



         if($exits -eq $false){

                "          [-] Found no autoruns ."
         }

         "`n`n"


 }

 initialize-audit

