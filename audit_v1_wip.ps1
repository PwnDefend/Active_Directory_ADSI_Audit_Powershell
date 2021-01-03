#get password length
[adsi]"LDAP://DC=Unatco,DC=local" | Format-List minPwdLength
[adsi]"LDAP://DC=Unatco,DC=local" | Format-List *

$DNC = [adsi]"LDAP://DC=Unatco,DC=local"
[PSCustomObject] @{
lockoutThreshold = $DNC.lockoutThreshold.Value
lockoutDuration = $DNC.ConvertLargeIntegerToInt64($DNC.lockoutDuration.Value) / ( -600000000)
lockOutObservationWindow = $DNC.ConvertLargeIntegerToInt64($DNC.lockOutObservationWindow.Value) / ( - 600000000)
}


$DNC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$DNC = [adsi]"DC=Unatco,DC=local"

[PSCustomObject] @{
lockoutThreshold = $DNC.lockoutThreshold.Value
lockoutDuration = $DNC.ConvertLargeIntegerToInt64($DNC.lockoutDuration.Value) / ( -600000000)
lockOutObservationWindow = $DNC.ConvertLargeIntegerToInt64($DNC.lockOutObservationWindow.Value) / ( - 600000000)
}

$ChildItems = ([ADSI]"LDAP://CN=users,DC=Unatco,DC=local")
$ChildItems.psbase.Children |? distinguishedName -Match "krbtgt"

[adsi]"LDAP://CN=krbtgt,CN=users,DC=Liberty,DC=Unatco,DC=local" | FT name, pwdLastSet
[PSCustomObject] @{
name = $user.name.Value
$pw = $user.pwdLastSet.value
#pwdLastSet = [datetime]::FromFileTime($user.ConvertLargeIntegerToInt64($user.pwdLastSet.value))
astLogon = [datetime]::FromFileTime($user.ConvertLargeIntegerToInt64($user.lastLogon.value))
} | Format-List

([adsisearcher]'(objectCategory=computer)').FindAll()

#find all domain controllers (group ID 516)
([adsisearcher]'(&(objectCategory=computer)(primaryGroupID=516))').FindAll()
#find all server 2019 OS computer objects

([adsisearcher]'(&(objectCategory=computer)(operatingSystem=Windows Server 2019*)(primaryGroupID=516))').FindAll()

#find all domain admins
([adsisearcher]'(memberOf=cn=Domain Admins,CN=Users,DC=Liberty,DC=Unatco,DC=local)').FindAll()

#find all user SPNs
([adsisearcher]'(&(objectCategory=user)(servicePrincipalName=*))').FindAll()

#FInd password last set
$as = [adsisearcher]"(&(objectCategory=user)(servicePrincipalName=*))"
$as.PropertiesToLoad.Add('name')
$as.PropertiesToLoad.Add('lastLogon')
$as.PropertiesToLoad.Add('pwdLastSet')
$as.FindAll() | ForEach-Object {
$props = @{'name'= ($_.properties.item('name') | Out-String).Trim()
'pwdLastSet'= ([datetime]::FromFiletime(($_.properties.item('pwdLastSet') | Out-String).Trim())) }
New-Object psObject -Property $props
}


#LDAP CHEAT SHEET
([adsisearcher]'(&(objectCategory=person)(objectClass=user))').FindAll()

([adsisearcher]'(objectCategory=computer)').FindAll()

([adsisearcher]'(objectCategory=group)').FindAll()

([adsisearcher]'(objectCategory=organizationalUnit)').FindAll()

([adsisearcher]'(objectCategory=container)').FindAll()

([adsisearcher]'(objectCategory=domain)').FindAll()

([adsisearcher]'(&(objectCategory=computer)(!(description=*)))').FindAll()

([adsisearcher]'(&(objectCategory=group)(description=*))').FindAll()

([adsisearcher]'(&(objectCategory=person)(objectClass=user)(cn=Jon*))').FindAll()

([adsisearcher]'(telephoneNumber=*)').FindAll()

([adsisearcher]'(&(objectCategory=group)(|(cn=Test*)(cn=Admin*)))').FindAll()

([adsisearcher]'(&(objectCategory=user)(|(cn=svc*)(cn=Adm*)))').FindAll()

([adsisearcher]'(&(objectCategory=person)(objectClass=user)(givenName=*)(sn=*))').FindAll()

([adsisearcher]'(&(objectCategory=person)(objectClass=user)(scriptPath=*))').FindAll()

([adsisearcher]'(sAMAccountName>=x)').FindAll()

([adsisearcher]'(&(sAMAccountName<=a)(!(sAMAccountName=$*)))').FindAll()

([adsisearcher]'(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=66048))').FindAll()

([adsisearcher]'(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))').FindAll()

([adsisearcher]'(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))').FindAll()

([adsisearcher]'(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=544))').FindAll()

#ASREP users
([adsisearcher]'(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))').FindAll()

#Users with no expiration date
([adsisearcher]'(&(objectCategory=person)(objectClass=user)(|(accountExpires=0)(accountExpires=9223372036854775807)))').FindAll()

#accounts that will expire
([adsisearcher]'(&(objectCategory=person)(objectClass=user)(accountExpires>=1)(accountExpires<=9223372036854775806))').FindAll()

#Accounts with unconstrained delegation excluding the DCs
([adsisearcher]'(&(!(primaryGroupID=516)(userAccountControl:1.2.840.113556.1.4.803:=524288)))').FindAll()

#computers whith unconstrained delegation excluding domain controllers
([adsisearcher]'(&(objectCategory=computer)(!(primaryGroupID=516)(userAccountControl:1.2.840.113556.1.4.803:=524288)))').FindAll()

#user accounts configured with unconstrained delegation
([adsisearcher]'(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))').FindAll()

#sensitive user accouunts not trusted for delegation
([adsisearcher]'(userAccountControl:1.2.840.113556.1.4.803:=1048576)').FindAll()

#find all distribution groups
([adsisearcher]'(&(objectCategory=group)(!(groupType:1.2.840.113556.1.4.803:=2147483648)))').FindAll()


#find all security groups
([adsisearcher]'(groupType:1.2.840.113556.1.4.803:=2147483648)').FindAll()

#all builtin groups
([adsisearcher]'(groupType:1.2.840.113556.1.4.803:=1)').FindAll()

#all global groups
([adsisearcher]'(groupType:1.2.840.113556.1.4.803:=2)').FindAll()

#all domain local groups
([adsisearcher]'(groupType:1.2.840.113556.1.4.803:=4)').FindAll()

#all universal groups
([adsisearcher]'(groupType:1.2.840.113556.1.4.803:=8)').FindAll()

#all global security groups
([adsisearcher]'(groupType=-2147483646)').FindAll()

#all universal security groups
([adsisearcher]'(groupType=-2147483640)').FindAll()

#domain local security groups
([adsisearcher]'(groupType=-2147483644)').FindAll()

#domain global distibution groups
([adsisearcher]'(groupType=2)').FindAll()

#user accounts with SPN but no the TGT accounts
([adsisearcher]'(&(objectCategory=user)(!(samAccountName=krbtgt)(servicePrincipalName=*)))').FindAll()

#admin accounts that must change password at next logon
([adsisearcher]'(&(objectCategory=person)(objectClass=user)(pwdLastSet=0))').FindAll()

#users where primary domain isn't 'domain users'
([adsisearcher]'(&(objectCategory=person)(objectClass=user)(!(primaryGroupID=513)))').FindAll()

#computers with primary group of domain controllers
([adsisearcher]'(&(objectCategory=computer)(primaryGroupID=515))').FindAll()

#computers that are not domain controllers
([adsisearcher]'(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))').FindAll()

#find all domain controllers
([adsisearcher]'(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))').FindAll()

#find all server objects
([adsisearcher]'(&(objectCategory=computer)(operatingSystem=*server*))').FindAll()

#All members of domain admins
([adsisearcher]'(memberOf=cn=DomainAdmins,cn=Users,DC=Unatco,DC=local)').FindAll()

#All members of domain admins including nested groups
([adsisearcher]'(memberOf:1.2.840.113556.1.4.1941:=cn=DomainAdmins,CN=Users,DC=Unatco,DC=local)').FindAll()

#all groups for a specific users
([adsisearcher]'(member:1.2.840.113556.1.4.1941:=CN=JonJones,OU=LHW,dc=contoso,dc=com)').FindAll()

#all objects with AdminSHHolder
([adsisearcher]'(adminCount=1)').FindAll()

#all trusted domains
([adsisearcher]'(objectClass=trustedDomain)').FindAll()

#all GPOs
([adsisearcher]'(objectCategory=groupPolicyContainer)').FindAll()

#All RODC
([adsisearcher]'(userAccountControl:1.2.840.113556.1.4.803:=67108864)').FindAll()

#All exchange servers
([adsisearcher]'(objectCategory=msExchExchangeServer)').FindAll()


#list all dns records
([adsisearcher]'(objectClass=dnsnode)').FindAll()

#Computers with LAPS passwords
([adsisearcher]'(&(objectCategory=computer)(ms-MCSAdmPwd=*))').FindAll().properties

#Users where bad password count is greater than or equal to 1
([adsisearcher]'(&(objectCategory=user)(badpwdcount>=1))').FindAll()

#all service accounts that are members of builtin groups that have adminSDHolder attributes
([adsisearcher]'(&(objectClass=user)(!(samAccountName=krbtgt)(servicePrincipalName=*)(adminCount=1)))').FindAll()


#all accounts that do not require a password (wtf ;) )
([adsisearcher]'(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))').FindAll()

#accounts that have Kerberos DES enabled
([adsisearcher]'(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152))').FindAll()

#accounts that have store password using reverisble encryption (this isn't a good look)
([adsisearcher]'(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))').FindAll()

#accounts that have never logged in
([adsisearcher]'(&(objectCategory=person)(objectClass=user)(lastlogon=0))').FindAll()

#accounts that have never logged in, ecludinng accounts with an SPN
([adsisearcher]'(&(objectCategory=person)(objectClass=user)(!(servicePrincipalName=*)(lastlogon=0)))').FindAll()

#Empty Global security groups
([adsisearcher]'(&(objectCategory=group)(groupType=-2147483646)(!(member=*)))').FindAll()

#User objects that have 'password' as a string in their description
([adsisearcher]'(&(objectCategory=person)(objectClass=user)(description=password*))').FindAll()


#List Ad SUbnets from sites and services
$ADSI = ([ADSI]"LDAP://CN=Subnets,CN=Sites,CN=Configuration,DC=Unatco,DC=local")
$ADSI.psbase.Children | Format-Table name
