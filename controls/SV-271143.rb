control 'SV-271143' do
  title 'SQL Server must limit privileges to change software modules, to include stored procedures, functions, and triggers, and links to software external to SQL Server.'
  desc 'If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', 'Obtain a listing of schema ownership from the server documentation.

Execute the following query to obtain a current listing of schema ownership.

SELECT S.name AS schema_name, P.name AS owning_principal
FROM sys.schemas S
JOIN sys.database_principals P ON S.principal_id = P.principal_id
ORDER BY schema_name

If any schema is owned by an unauthorized database principal, this is a finding.'
  desc 'fix', 'Transfer ownership of database schemas to authorized database principals.

ALTER AUTHORIZATION ON SCHEMA::[<Schema Name>] TO [<Principal Name>]'
  impact 0.5
  tag check_id: 'C-75186r1108043_chk'
  tag severity: 'medium'
  tag gid: 'V-271143'
  tag rid: 'SV-271143r1108045_rule'
  tag stig_id: 'SQLD-22-001200'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-75093r1108044_fix'
  tag 'documentable'
  tag legacy: ['SV-93783', 'V-79077']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
