control 'SV-271172' do
  title 'SQL Server must isolate security functions from nonsecurity functions.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions. 

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. 

Database Management Systems typically separate security functionality from nonsecurity functionality via separate databases or schemas. Database objects or code implementing security functionality should not be commingled with objects or code implementing application logic. When security and nonsecurity functionality are commingled, users who have access to nonsecurity functionality may be able to access security functionality.'
  desc 'check', 'Determine elements of security functionality (lists of permissions, additional authentication information, stored procedures, application specific auditing, etc.) being housed inside SQL Server.

For any elements found, check SQL Server to determine if these objects or code implementing security functionality are located in a separate security domain, such as a separate database, schema, or table created specifically for security functionality.

Review the system documentation to determine if the necessary database changes cannot be made and that the blockers are also documented. If the necessary changes are documented as not possible, this is not a finding.

Review the database structure to determine where security-related functionality is stored. If security-related database objects or code is not kept separate, this is a finding.'
  desc 'fix', 'Check documentation and locate security-related database objects and code in a separate database, schema, table, or other separate security domain from database objects and code implementing application logic.

Schemas are analogous to separate namespaces or containers used to store database objects. Security permissions apply to schemas, making them an important tool for separating and protecting database objects based on access rights. Schemas reduce the work required, and improve the flexibility, for security-related administration of a database.

User-schema separation allows for more flexibility in managing database object permissions. A schema is a named container for database objects, which allows the user group objects into separate namespaces.

Where possible, locate security-related database objects and code in a separate database, schema, or other separate security domain from database objects and code implementing application logic. In all cases, use GRANT, REVOKE, DENY, ALTER ROLE … ADD MEMBER … and/or ALTER ROLE …. DROP MEMBER statements to add and remove permissions on server-level and database-level security-related objects to provide effective isolation.

Consider submitting a request to the vendor for changes to a COTS database when database structure does not isolate security functions and cannot be altered directly by the database administrators without loss of official support.'
  impact 0.5
  tag check_id: 'C-75215r1109193_chk'
  tag severity: 'medium'
  tag gid: 'V-271172'
  tag rid: 'SV-271172r1109195_rule'
  tag stig_id: 'SQLD-22-001900'
  tag gtitle: 'SRG-APP-000233-DB-000124'
  tag fix_id: 'F-75122r1109194_fix'
  tag 'documentable'
  tag legacy: ['SV-93797', 'V-79091']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
