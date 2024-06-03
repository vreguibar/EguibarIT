﻿$Variables.WellKnownSIDs = [ordered] @{
    'S-1-0'                                      = 'null authority'
    'S-1-0-0'                                    = 'nobody'
    'S-1-1'                                      = 'world authority'
    'S-1-1-0'                                    = 'everyone'
    'S-1-16-0'                                   = 'untrusted mandatory level'
    'S-1-16-12288'                               = 'high mandatory level'
    'S-1-16-16384'                               = 'system mandatory level'
    'S-1-16-20480'                               = 'protected process mandatory level'
    '*S-1-16-28672'                              = 'secure process mandatory level'
    'S-1-16-4096'                                = 'low mandatory level'
    'S-1-16-8192'                                = 'medium mandatory level'
    'S-1-16-8448'                                = 'medium plus mandatory level'
    'S-1-2'                                      = 'local authority'
    'S-1-3'                                      = 'creator authority'
    'S-1-3-0'                                    = 'creator owner'
    'S-1-3-1'                                    = 'creator group'
    'S-1-3-2'                                    = 'creator owner server'
    'S-1-3-3'                                    = 'creator group server'
    'S-1-4'                                      = 'nonunique authority'
    'S-1-5'                                      = 'nt authority'
    'S-1-5-1'                                    = 'dialup'
    'S-1-5-2'                                    = 'network'
    'S-1-5-3'                                    = 'batch'
    'S-1-5-19'                                   = 'nt authority (localservice)'
    'S-1-5-18'                                   = 'LocalSystem'
    'S-1-5-20'                                   = 'network service'
    'S-1-5-21-4195037842-338827918-94892514-526' = 'key admins'
    'S-1-5-4'                                    = 'interactive'
    'S-1-5-6'                                    = 'service'
    'S-1-5-7'                                    = 'anonymous'
    'S-1-5-8'                                    = 'proxy'
    'S-1-5-9'                                    = 'enterprise controllers'
    'S-1-5-10'                                   = 'self'
    'S-1-5-11'                                   = 'authenticated users'
    'S-1-5-113'                                  = 'local account'
    'S-1-5-114'                                  = 'local account and member of administrators group'
    'S-1-5-12'                                   = 'restricted code'
    'S-1-5-13'                                   = 'terminal server users'
    'S-1-5-14'                                   = 'remote interactive logon'
    'S-1-5-15'                                   = 'this organization'
    'S-1-5-17'                                   = 'iis_usrs'
    'S-1-5-21-500'                               = 'Administrator'
    'S-1-5-21-501'                               = 'Guest'
    'S-1-5-21-502'                               = 'KRBTGT'
    'S-1-5-21-512'                               = 'Domain Admins'
    'S-1-5-21-513'                               = 'Domain Users'
    'S-1-5-21-514'                               = 'Domain Guests'
    'S-1-5-21-515'                               = 'Domain Computers'
    'S-1-5-21-516'                               = 'Domain Controllers'
    'S-1-5-21-517'                               = 'Cert Publishers'
    'S-1-5-21-518'                               = 'Schema Admins'
    'S-1-5-21-519'                               = 'Enterprise Admins'
    'S-1-5-21-520'                               = 'Group Policy Creator Owners'
    'S-1-5-21-522'                               = 'Cloneable Domain Controllers'
    'S-1-5-21-526'                               = 'Key Admins'
    'S-1-5-21-527'                               = 'Enterprise Key Admins'
    'S-1-5-21-553'                               = 'RAS and IAS Servers'
    'S-1-5-21-571'                               = 'Allowed RODC Password Replication Group'
    'S-1-5-21-572'                               = 'Denied RODC Password Replication Group'
    'S-1-5-32-544'                               = 'administrators'
    'S-1-5-32-545'                               = 'users'
    'S-1-5-32-546'                               = 'guests'
    'S-1-5-32-547'                               = 'power users'
    'S-1-5-32-548'                               = 'account operators'
    'S-1-5-32-549'                               = 'server operators'
    'S-1-5-32-550'                               = 'print operators'
    'S-1-5-32-551'                               = 'backup operators'
    'S-1-5-32-552'                               = 'replicators'
    'S-1-5-32-554'                               = 'Builtin\pre-windows 2000 compatible access'
    'S-1-5-32-555'                               = 'Builtin\remote desktop users'
    'S-1-5-32-556'                               = 'Builtin\network configuration operators'
    'S-1-5-32-557'                               = 'Builtin\incoming forest trust builders'
    'S-1-5-32-558'                               = 'Builtin\performance monitor users'
    'S-1-5-32-559'                               = 'Builtin\performance log users'
    'S-1-5-32-560'                               = 'Builtin\windows authorization access group'
    'S-1-5-32-561'                               = 'Builtin\terminal server license servers'
    'S-1-5-32-562'                               = 'Builtin\distributed com users'
    'S-1-5-32-568'                               = 'Builtin\iis_iusrs'
    'S-1-5-32-569'                               = 'Builtin\cryptographic operators'
    'S-1-5-32-573'                               = 'Builtin\event log readers'
    'S-1-5-32-575'                               = 'Builtin\rds remote access servers'
    'S-1-5-32-577'                               = 'Builtin\rds management servers'
    'S-1-5-32-578'                               = 'Builtin\hyper-v administrators'
    'S-1-5-32-579'                               = 'Builtin\access control assistance operators'
    'S-1-5-32-580'                               = 'Builtin\remote management users'
    'S-1-5-32-581'                               = 'system managed accounts group'
    'S-1-5-32-582'                               = 'storage replica administrators'
    'S-1-5-64-10'                                = 'ntlm authentication'
    'S-1-5-64-14'                                = 'schannel authentication'
    'S-1-5-64-21'                                = 'digest authentication'
    'S-1-5-80'                                   = 'nt service'
    'S-1-5-80-0'                                 = 'all services'
    'S-1-5-83-0'                                 = 'virtual machines'
}
New-Variable -Name WellKnownSIDs -Value $Variables.WellKnownSIDs -Scope Script -Force
# Search by Key to get Value
# $WellKnownSIDs['S-1-5-11']
# Search by Value to get Key
# $WellKnownSIDs.keys.where{$WellKnownSIDs[$_] -eq 'authenticated users'}