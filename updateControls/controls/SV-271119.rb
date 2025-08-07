control 'SV-271119' do
  title 'SQL Server must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc 'Authentication with a DOD-approved PKI certificate does not necessarily imply authorization to access the DBMS. To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DOD-approved PKIs, all DOD systems, including databases, must be properly configured to implement access control policies. 

Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. 

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system. 

This requirement is applicable to access control enforcement applications, a category that includes database management systems. If SQL Server does not follow applicable policy when approving access, it may be in conflict with networks or other applications in the information system. This may result in users either gaining or being denied access inappropriately and in conflict with applicable policy.'
  desc 'check', 'If the database is tempdb, this is Not Applicable.

Check SQL Server settings to determine whether users are restricted from accessing objects and data they are not authorized to access.

Review the system documentation to determine the required levels of protection for securables in the database by type of user. 

Review the permissions in place in the database. 

If the permissions do not match the documented requirements, this is a finding.

Use the supplemental file "Database permission assignments to users and roles.sql".'
  desc 'fix', 'Configure SQL Server settings and access controls to permit user access only to objects and data that the user is authorized to view or interact with, and to prevent access to all other objects and data.

Use GRANT, REVOKE, DENY, ALTER ROLE … ADD MEMBER … and/or ALTER ROLE …. DROP MEMBER statements to add and remove permissions on database-level securables, bringing them into line with the documented requirements.'
  impact 0.7
  tag check_id: 'C-75162r1107971_chk'
  tag severity: 'high'
  tag gid: 'V-271119'
  tag rid: 'SV-271119r1107973_rule'
  tag stig_id: 'SQLD-22-000300'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-75069r1107972_fix'
  tag 'documentable'
  tag legacy: ['SV-81847', 'V-67357', 'SV-93771', 'V-79065']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  describe 'Test has no automation procedure, checks must be performed manually' do
    skip 'This check must be performed manually'
  end
end
