control 'SV-271179' do
  title 'SQL Server must provide nonprivileged users with error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'Any DBMS or associated application providing too much information in error messages on the screen or printout risks compromising the data and security of the system. The structure and content of error messages need to be carefully considered by the organization and development team.

Databases can inadvertently provide a wealth of information to an attacker through improperly handled error messages. In addition to sensitive business or personal information, database errors can provide host names, IP addresses, usernames, and other system information not required for troubleshooting but very useful to someone targeting the system.

Carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.'
  desc 'check', 'Review application behavior and custom database code (stored procedures, triggers), to determine whether error messages contain information beyond what is needed for explaining the issue to general users.

If database error messages contain PII data, sensitive business data, or information useful for identifying the host system or database structure, this is a finding.'
  desc 'fix', 'Adjust database code to remove any information not required for explaining the error to an end user.

Consider enabling trace flag 3625 to mask certain system-level error information returned to nonadministrative users.

1. Launch SQL Server Configuration Manager >> SQL Services.
2. Open the instance properties.
3. Select the "Service Parameters" tab.
4. Enter "-T3625". 
5. Click "Add" and then click "OK".
6. Restart SQL instance.'
  impact 0.5
  tag check_id: 'C-75222r1108151_chk'
  tag severity: 'medium'
  tag gid: 'V-271179'
  tag rid: 'SV-271179r1108921_rule'
  tag stig_id: 'SQLD-22-002400'
  tag gtitle: 'SRG-APP-000266-DB-000162'
  tag fix_id: 'F-75129r1108920_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
