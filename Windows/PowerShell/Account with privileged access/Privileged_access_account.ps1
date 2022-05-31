################## Function to Expand Group Membership ################
function getMemberExpanded
{
    param ($dn)
    $colOfMembersExpanded=@()
    $adobject = [adsi]"LDAP://$dn"
    $colMembers = $adobject.properties.item("member")
    Foreach ($objMember in $colMembers)
    {
        $objMembermod = $objMember.replace("/","\/")
        $objAD = [adsi]"LDAP://$objmembermod"
        $attObjClass = $objAD.properties.item("objectClass")
        if ($attObjClass -eq "group")
        {
            getmemberexpanded $objMember
        }
        else
        {
            $colOfMembersExpanded += $objMember
        }
    }
    $colOfMembersExpanded
}

########################### Function to Calculate Password Age ##############
Function getUserAccountAttribs
{
    param($objADUser,$parentGroup)
    $objADUser = $objADUser.replace("/","\/")
    $adsientry=new-object directoryservices.directoryentry("LDAP://$objADUser")
    $adsisearcher=new-object directoryservices.directorysearcher($adsientry)
    $adsisearcher.pagesize=1000
    $adsisearcher.searchscope="base"
    $colUsers=$adsisearcher.findall()
    foreach($objuser in $colUsers)
    {
        $dn = $objuser.properties.item("distinguishedname")
        $sam = $objuser.properties.item("samaccountname")
        
        $record = "" | select-object SamAccountName,DistinguishedName,MemberOf
        $record.SamAccountName = [string]$sam
        $record.DistinguishedName = [string]$dn
        $record.MemberOf = [string]$parentGroup
    }
    $record
}

####### Function to find all Privileged Groups in the Forest ##########
Function getForestPrivGroups
{
    $colOfDNs = @()
    $Forest = [System.DirectoryServices.ActiveDirectory.forest]::getcurrentforest()
    $RootDomain = [string]($forest.rootdomain.name)
    $forestDomains = $forest.domains
    $colDomainNames = @()
    ForEach ($domain in $forestDomains)
    {
        $domainname = [string]($domain.name)
        $colDomainNames += $domainname
    }

    $ForestRootDN = FQDN2DN $RootDomain
    $colDomainDNs = @()
    ForEach ($domainname in $colDomainNames)
    {
        $domainDN = FQDN2DN $domainname
        $colDomainDNs += $domainDN
    }
    $GC = $forest.FindGlobalCatalog()
    $adobject = [adsi]"GC://$ForestRootDN"
    $RootDomainSid = New-Object System.Security.Principal.SecurityIdentifier($AdObject.objectSid[0], 0)
    $RootDomainSid = $RootDomainSid.toString()
    $colDASids = @()
    ForEach ($domainDN in $colDomainDNs)
    {
        $adobject = [adsi]"GC://$domainDN"
        $DomainSid = New-Object System.Security.Principal.SecurityIdentifier($AdObject.objectSid[0], 0)
        $DomainSid = $DomainSid.toString()
        $daSid = "$DomainSID-512"
        $colDASids += $daSid
        $cpSid = "$DomainSID-517"
        $colDASids += $cpSid
    }
    $colPrivGroups = @("S-1-5-32-544";"S-1-5-32-548";"S-1-5-32-549";"S-1-5-32-551";"S-1-5-32-550";"$rootDomainSid-519";"$rootDomainSid-518")
    $colPrivGroups += $colDASids
    $searcher = $gc.GetDirectorySearcher()
    ForEach($privGroup in $colPrivGroups)
    {
        $searcher.filter = "(objectSID=$privGroup)"
        $Results = $Searcher.FindAll()
        ForEach ($result in $Results)
        {
        $dn = $result.properties.distinguishedname
        $colOfDNs += $dn
        }
    }
    $colofDNs
}

########################## Function to Generate Domain  Distinguished Name from FQDN ########
Function FQDN2DN
{
    Param ($domainFQDN)
    $colSplit = $domainFQDN.Split(".")
    $FQDNdepth = $colSplit.length
    $DomainDN = ""
    For ($i=0;$i -lt ($FQDNdepth);$i++)
    {
        If ($i -eq ($FQDNdepth - 1)) {$Separator=""}
        else {$Separator=","}
        [string]$DomainDN += "DC=" + $colSplit[$i] + $Separator
    }
    $DomainDN
}

########################## MAIN ###########################

$forestPrivGroups = GetForestPrivGroups
Foreach ($privGroup in $forestPrivGroups)
{
    $uniqueMembers = @()
    $colOfMembersExpanded = @()
    $members = getmemberexpanded $privGroup
    If ($members)
    {
        $uniqueMembers = $members | sort-object -unique
        Foreach ($uniqueMember in $uniqueMembers)
        {
            $objAttribs = getUserAccountAttribs $uniqueMember $privGroup
            $objAttribs
        }
    }
}