control 'SV-271201' do
  title 'SQL Server must implement cryptographic mechanisms to prevent unauthorized modification or disclosure of organization-defined information at rest (to include, at a minimum, PII and classified information) on organization-defined information system components.'
  desc 'DBMSs handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may be native to the DBMS or implemented via additional software or operating system/file system settings, as appropriate to the situation.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).

The decision whether and what to encrypt rests with the data owner and is also influenced by the physical measures taken to secure the equipment and media on which the information resides.'
  desc 'check', "Review the system documentation to determine whether the organization has defined the information at rest that is to be protected from disclosure or modification, which must include, at a minimum, PII and classified information. 

If no information is identified as requiring such protection, this is not a finding. 

Review the configuration of SQL Server, Windows, and additional software as relevant. 

If full-disk encryption is required, and Windows or the storage system is not configured for this, this is a finding. 

If database transparent data encryption (TDE) is called for, check whether it is enabled: 

SELECT
DB_NAME(database_id) AS [Database Name], CASE encryption_state WHEN 0 THEN 'No database encryption key present, no encryption' 
WHEN 1 THEN 'Unencrypted' 
WHEN 2 THEN 'Encryption in progress' 
WHEN 3 THEN 'Encrypted' 
WHEN 4 THEN 'Key change in progress' 
WHEN 5 THEN 'Decryption in progress' 
WHEN 6 THEN 'Protection change in progress' 
END AS [Encryption State]
FROM sys.dm_database_encryption_keys

For each user database for which encryption is called for and it is marked Unencrypted, this is a finding. 

If table/column encryption and/or a separation between those who own the data (and can view it) and those who manage the data (but should have no access) is required for PII or similar types of data, use Always Encrypted. The details for configuring Always Encrypted are located here: https://msdn.microsoft.com/en-us/library/mt163865.aspx.

Review the definitions and contents of the relevant tables/columns for the Always Encryption settings, if any of the information defined as requiring cryptographic protection is not encrypted this is a finding."
  desc 'fix', 'Where full-disk encryption is required, configure Windows and/or the storage system to provide this. 

Where TDE is required, create a master key, obtain a certificate protected by the master key, create a database encryption key and protect it by the certificate, and then set the database to use encryption. For guidance from MSDN on how to do this, refer to: https://msdn.microsoft.com/en-us/library/bb934049.aspx. 

Where table/column encryption is required, enable encryption on the tables/columns in question. For guidance from the Microsoft Developer Network on how to do this with Always Encrypted, refer to: https://msdn.microsoft.com/en-us/library/mt163865.aspx.'
  impact 0.7
  tag check_id: 'C-75244r1109209_chk'
  tag severity: 'high'
  tag gid: 'V-271201'
  tag rid: 'SV-271201r1109210_rule'
  tag stig_id: 'SQLD-22-003300'
  tag gtitle: 'SRG-APP-000428-DB-000386'
  tag fix_id: 'F-75151r1108218_fix'
  tag 'documentable'
  tag legacy: ['SV-81899', 'V-67409', 'SV-93821', 'V-79115']
  tag cci: ['CCI-002475', 'CCI-002476']
  tag nist: ['SC-28 (1)']

  data_at_rest_encryption_required = input('data_at_rest_encryption_required')

  query = %{
    SELECT
          d.name AS [Database Name],
          CASE e.encryption_state
                WHEN 0 THEN 'No database encryption key present, no encryption'
                WHEN 1 THEN 'Unencrypted'
                WHEN 2 THEN 'Encryption in progress'
                WHEN 3 THEN 'Encrypted'
                WHEN 4 THEN 'Key change in progress'
                WHEN 5 THEN 'Decryption in progress'
                WHEN 6 THEN 'Protection change in progress'
          END AS [Encryption State]
    FROM sys.dm_database_encryption_keys e
    RIGHT JOIN sys.databases d ON DB_NAME(e.database_id) = d.name
    WHERE d.name IN ('#{input('db_name')}')
  }

  sql_session = mssql_session(user: input('user'),
                              password: input('password'),
                              host: input('host'),
                              instance: input('instance'),
                              port: input('port'),
                              db_name: input('db_name'))

  unless data_at_rest_encryption_required
    impact 0.0
    desc 'If the application owner and Authorizing Official have
    determined that encryption of data at rest is NOT required, this is not a
    finding.'
  end

  describe "Database: #{input('db_name')} encryption state" do
    subject { sql_session.query(query).column('encryption state').uniq }
    it { should cmp 'Encrypted' }
  end

  describe 'The following checks must be performed manually' do
    skip "The following checks must be performed manually:
      If full-disk encryption is required, and Windows or the storage system is not
      configured for this, this is a finding.

      If database transparent data encryption (TDE) is called for, check whether it
      is enabled:
      In SQL Server Management Studio, Object Explorer, expand the instance and
      right-click on the database name; select properties.  Select the Options page,
      State section, Encryption Enabled parameter.

      If the value displayed is False, this is a finding.

      If column encryption, done via SQL Server features, is required, review the
      definitions and contents of the relevant tables and columns.

      If any of the information defined as requiring cryptographic protection is not
      encrypted in a manner that provides the required level of protection, this is a
      finding.

      If table/column encryption and/or a separation between those who own the data
      (and can view it) and those who manage the data (but should have no access) is
      required for PII or similar types of data, use Always Encrypted. The details
      for configuring Always Encrypted are located here:
      https://msdn.microsoft.com/en-us/library/mt163865.aspx.

      Review the definitions and contents of the relevant tables/columns for the
      Always Encryption settings, if any of the information defined as requiring
      cryptographic protection is not encrypted this is a finding."
  end
end
