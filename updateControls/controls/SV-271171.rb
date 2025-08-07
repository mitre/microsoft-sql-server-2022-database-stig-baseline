control 'SV-271171' do
  title 'The certificate used for encryption must be backed up and stored in a secure location that is not on the SQL Server.'
  desc 'Backup and recovery of the certificate used for encryption is critical to the complete recovery of the database. Not having this key can lead to loss of data during recovery.'
  desc 'check', 'If the application owner and authorizing official have determined that encryption of data at rest is not required, this is not a finding.

Review procedures for and evidence of backup of the certificate used for encryption in the System Security Plan. 

If the procedures or evidence does not exist, this is a finding. 

If the procedures do not indicate that a backup of the certificate used for encryption is stored in a secure location that is not on the SQL Server, this is a finding. 

If procedures do not indicate access restrictions to the certificate backup, this is a finding.'
  desc 'fix', "Document and implement procedures to safely back up and store the Certificate used for encryption. Include in the procedures methods to establish evidence of backup and storage, and careful, restricted access and restoration of the Certificate. Also, include provisions to store the backup off-site. 

BACKUP CERTIFICATE 'CertificateName' TO FILE = 'path_to_file' WITH PRIVATE KEY (FILE = 'path_to_pvk', ENCRYPTION BY PASSWORD = 'password'); 

As this requires a password, ensure it is not exposed to unauthorized persons or stored as plain text."
  impact 0.5
  tag check_id: 'C-75214r1108127_chk'
  tag severity: 'medium'
  tag gid: 'V-271171'
  tag rid: 'SV-271171r1109192_rule'
  tag stig_id: 'SQLD-22-001800'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-75121r1109191_fix'
  tag 'documentable'
  tag legacy: ['SV-93795', 'V-79089']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
