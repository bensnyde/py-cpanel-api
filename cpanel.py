from httplib import HTTPSConnection
from base64 import b64encode

class Cpanel:
        def __init__(self, url, username, password):
                self.url = url
                self.authHeader = {'Authorization':'Basic ' + b64encode(username+':'+password).decode('ascii')}

        def cQuery(self, queryStr):
                """
                Queries specified WHM server's JSON API with specified query string.

                Arguments
                ---
                queryStr:str - HTTP GET formatted query string.

                Returns JSON response from server
                """
                conn = HTTPSConnection(self.url, 2087)
                conn.request('GET', '/json-api/'+queryStr, headers=self.authHeader)
                response = conn.getresponse()
                data = response.read()
                conn.close()
                return data

        def createAccount(self, username, domain, *args):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/CreateAccount -
                This function creates a hosting account and sets up its associated domain information.
                """
                return self.cQuery('createacct?username='+username+'&domain='+domain)

        def changeAccountPassword(self, username, password, update_db_password=True):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ChangePassword -
                This function changes the password of a domain owner (cPanel) or reseller (WHM) account.
                """
                return self.cQuery('passwd?user='+username+'&pass='+password+'&db_pass_update='+update_db_password)

        def limitAccountBandwidth(self, username, bwlimit):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/LimitBandwidth -
                This function modifies the bandwidth usage (transfer) limit for a specific account.
                """
                return self.cQuery('limitbw?user='+username+'&bwlimit='+bwlimit)

        def listAccounts(self, *args):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ListAccounts -
                This function lists all accounts on the server, and also allows you to search for a specific account or set of accounts.
                """
                return self.cQuery('lictaccts')

        def modifyAccount(self, username, *args):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ModifyAccount -
                This function modifies settings for an account.
                """
                return self.cQuery('modifyacct?user='+username)

        def changeAccountDiskQuota(self, username, quota):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/EditQuota -
                This function changes an account's disk space usage quota.
                """
                return self.cQuery('editquota?user='+username+'&quota='+quota)

        def getAccountSummary(self, username):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ShowAccountInformation -
                This function displays pertinent information about a specific account.
                """
                return self.cQuery('accountsummary?user='+username)

        def suspendAccount(self, username, reason=""):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SuspendAccount -
                This function will allow you to prevent a cPanel user from accessing his or her account.
                """
                return self.cQuery('suspendacct?user='+username+'&reason='+reason)

        def listSuspendedAccounts(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ListSuspended -
                This function will generate a list of suspended accounts.
                """
                return self.cQuery('listsuspended')

        def terminateAccount(self, username, keep_dns=False):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/TerminateAccount -
                This function permanently removes a cPanel account.
                """
                return self.cQuery('removeacct?user='+username+'&keepdns='+keep_dns)

        def unsuspendAccount(self, username):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/UnsuspendAcount -
                This function will unsuspend a suspended account.
                """
                return self.cQuery('unsuspendacct?user='+username)

        def changeAccountPackage(self, username, package):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ChangePackage -
                This function changes the hosting package associated with a cPanel account.
                """
                return self.cQuery('changepackage?user='+username+'&pkg='+package)

        def getDomainUserdata(self, domain):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/DomainUserData -
                This function lets you obtain user data for a specific domain.
                """
                return self.cQuery('domainuserdata?domain='+domain)

        def changeDomainIpAddress(self, domain, ip_address):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetSiteIp -
                This function allows you to change the IP address of a website hosted on your server
                """
                return self.cQuery('setsiteip?domain='+domain+'&ip='+ip_address)

        def changeAccountIpAddress(self, username, ip_address):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetSiteIp -
                This function allows you to change the IP address of a user account hosted on your server
                """
                return self.cQuery('setsiteip?user='+username+'&ip='+ip_address)

        def restoreAccountBackup(self, username, backup_type="daily", all_services=True, ip=True, mail=True, mysql=True, subs=True):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreAccount -
                This function allows you to restore a user's account from a backup file.
                """
                if(backup_type == "daily" || backup_type == "weekly" || backup_type == "monthly"):
                        return self.cQuery('restoreaccount?api.version=1&user='+username+'&type='+backup_type+'&all='+all_services)

        def setAccountDigestAuthentication(self, username, password, enable_digest=True):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetDigestAuth -
                This function enables or disables Digest Authentication for a user account.
                """
                return self.cQuery('set_digest_auth?user='+username+'&password='+password+'&enabledigest='+enable_digest+'&api.version=1')

        def getAccountDigestAuthentication(self, username):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/HasDigestAuth -
                This function will check whether a cPanel user has digest authentication enabled.
                """
                return self.cQuery('has_digest_auth?user='+username)






        def getPrivileges(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ViewPrivileges -
                This function will generate a list of features you are allowed to use in WHM. Each feature will display either a 1 or 0.
                """
                return self.cQuery('myprivs')



        def restoreAccountBackupQueued(self, username, restore_point, give_ip=False, mysql=True, subdomains=True, mail_config=True):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueAdd -
                This function allows you to restore a user's account from a backup file.
                """
                return self.cQuery('restore_queue_add_task?user='+username+'&restore_point='+restore_point
                        +'&give_ip='+give_ip+'&mysql='+mysql+'&subdomains='+subdomains+'&mail_config='+mail_config)

        def activateRestoreQueue(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueActivate -
                This function allows you to activate the restore queue and start a process to restore all queued accounts.
                """
                return self.cQuery('restore_queue_activate')

        def getRestoreQueueState(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueIsActive -
                This function allows you to see if the queue is actively in the restoration process for certain accounts.
                """
                return self.cQuery('restore_queue_is_active')

        def getRestoreQueuePending(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueList -
                This function allows you to list all queued accounts to be restored.
                """
                return self.cQuery('restore_queue_list_pending')

        def getRestoreQueueActive(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueListActive -
                This function allows you to list all accounts currently in the restoration process.
                """
                return self.cQuery('restore_queue_list_active')

        def getRestoreQueueCompleted(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueListCompleted -
                This function allows you to list all completed restorations, successful restores, failed restores, and the restore log.
                """
                return self.cQuery('restore_queue_list_completed')

        def clearRestoreQueuePendingTask(self, username):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueClearPendingTask -
                This function allows you to clear a single pending account from the Restoration Queue.
                """
                return self.cQuery('restore_queue_clear_pending_task?user='+username)

        def clearRestoreQueuePendingTasks(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueClearAllPendingTasks -
                This function allows you to clear all pending accounts from the restore queue.
                """
                return self.cQuery('restore_queue_clear_all_pending_tasks')

        def clearRestoreQueueCompletedTask(self, username):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueClearCompletedTask -
                This function allows you to clear a single completed account from the Restoration Queue. The account
                may have completed successfully, or the account may have failed to successfully complete.
                """
                return self.cQuery('restore_queue_clear_completed_task?user='+username)

        def clearRestoreQueueCompletedTasks(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueClearAllCompletedTasks -
                This function allows you to clear all successfully completed accounts from the Restoration Queue.
                """
                return self.cQuery('restore_queue_clear_all_completed_tasks')

        def clearRestoreQueueFailedTasks(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueClearAllFailedTasks -
                This function allows you to clear all failed tasks from the Restoration Queue.
                """
                return self.cQuery('restore_queue_clear_all_failed_tasks')

        def clearRestoreQueueAll(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestoreQueueClearAllTasks -
                This function allows you to clear all open, unresolved, or pending tasks from the Restoration Queue.
                """
                return self.cQuery('restore_queue_clear_all_tasks')






        def getBackupConfig(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupConfigGet -
                This function allows you to receive detailed data from your backup destination configuration file.
                """
                return self.cQuery('backup_config_get')

        def setBackupConfig(self, *args):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupConfigSet -
                This function allows you to save the data from the backup configuration page and put the data in /var/cpanel/bakcups/config
                """
                return self.cQuery('backup_config_set')

        def setBackupConfigAllUsers(self, state=True):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupSkipUsersAll -
                This function allows you to choose which Backup Configuration to use, and enable or disable backups for all users.
                """
                return self.cQuery('backup_skip_users_all?state='+state)

        def getBackupConfigAllUsers(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupSkipUsersAllStatus -
                This function allows you to retrieve the value from the status log file in the backup_skip_users_all api call.
                """
                return self.cQuery('backup_skip_users_all_status')

        def getBackupListFiles(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupSetList -
                This function allows you to find all backup files available on the server. This
                function also returns a list of users and dates so that the Restore Account(s) feature in WHM can show them.
                """
                return self.cQuery('backup_set_list')

        def getBackupListDates(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupDateList -
                This function allows you to retrieve a list of all dates with a backup file saved.
                """
                return self.cQuery('backup_date_list')

        def getBackupsByDate(self, date):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupUserList -
                This function returns a list all users with a backup file saved on a specific date that you choose.
                """
                return self.cQuery('backup_user_list?restore_point='+date)

        def validateBackupDestination(self, destination_id, disable_on_fail=False):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupdDestinationValidatet -
                This function allows you to run a validation routine on a specified backup destination.
                """
                return self.cQuery('backup_destination_validate?id='+destination_id+'&disableonfail='+disable_on_fail)

        def addBackupDestination(self, backup_type, *args):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupDestinationAdd -
                This function allows you to create a backup destination and save it to a config file.
                """
                if(backup_type == "FTP" || backup_type == "Local" || backup_type == "SFTP" || backup_type == "WebDav" || backup_type == "Custom"):
                        return self.cQuery('backup_destination_add?type='+backup_type)

        def setBackupDestination(self, destination_id, *args):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupDestinationSet -
                This function allows you to modify the setup and data for a backup destination.
                """
                return self.cQuery('backup_destination_set?id='+destination_id)

        def deleteBackupDestination(self, destination_id):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupDestinationDelete -
                This function allows you to remove the backup destination config file.
                """
                return self.cQuery('backup_destination_delete?id='+destination_id)

        def getBackupDestinationDetails(self, destination_id):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupDestinationGet -
                This function allows you to retrieve detailed data for a specific backup destination from the backup destination config file.
                """
                return self.cQuery('backup_destination_get?id='+destination_id)

        def listBackupDestionations(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/BackupDestinationList -
                This function allows you to list all backup destinations, including their configuration information.
                """
                return self.cQuery('backup_destination_list')






        def addPackage(self, name, *args):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/AddPackage -
                This function adds a new hosting package.
                """
                return self.cQuery('addpkg?name='+name)

        def deletePackage(self, name):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/DeletePackage -
                This function deletes a specific hosting package.
                """
                return self.cQuery('killpkg?pkg='+name)

        def editPackage(self, name, *args):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/EditPackage -
                This function edits all aspects of a specific hosting package.
                """
                return self.cQuery('editpkg?name='+name)

        def listPackages(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ListPackages -
                This function lists all hosting packages available for use by the WHM user who is currently logged in.
                """
                return self.cQuery('listpkgs')

        def listFeatures(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/XmlGetFeatureList -
                This function will retrieve a list of available features.
                """
                return self.cQuery('getfeaturelist')




        def restartService(self, service):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RestartService -
                This function restarts a service (daemon) on the server.
                """
                return self.cQuery('restartservice?service='+service)

        def getServiceStatus(self, service):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ServiceStatus -
                This function tells you which services (daemons) are installed and enabled on, and monitored by, your server.
                """
                return self.cQuery('servicestatus?service='+service)

        def configureService(self, service, enabled=True, monitored=True):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ConfigureService -
                This function allows you to enable or disable a service, and enable or disable monitoring of that
                service in the same manner as the WHM Service Manager.
                """
                return self.cQuery('configureservice?service='+service+'&enabled='+enabled+'&monitored='+monitored)




        def getSSLDetails(self, domain):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/FetchSSL -
                This function displays the SSL certificate, private key, and CA bundle/intermediate certificate associated with a specified domain.
                """
                return self.cQuery('fetchsslinfo?domain='+domain)

        def generateSSL(self, xemail, host, country, state, city, co, cod, email, password):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/GenerateSSL -
                This function generates an SSL certificate.
                """
                return self.cQuery('generatessl?xemail='+xemail+'&host='+host+'&country='+country+
                        '&state='+state+'&city='+city+'&co='+co+'&cod='+cod+'&email='+email+'&pass='+password)

        def installSSL(self, username, domain, cert, key, cab, ip):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/InstallSSL -
                This function installs an SSL certificate.
                """
                return self.cQuery('installssl?user='+username+'&domain='+domain+'&cert='+cert+'&key='+key+'&cab='+cab+'&ip='+ip)

        def listSSL(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ListSSL -
                This function will list all domains on the server that have SSL certificates installed.
                """
                return self.cQuery('listcrts')



        def setPrimaryDomain(self, servername, vtype="std"):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetPrimaryDomain -
                This function allows WHM users to set the primary domain on an IP address and port (ssl or std)
                for their accounts' sites. The primary domain refers to the virtual host that will be served when
                the IP address is accessed directly.
                """
                return self.cQuery('set_primary_servername?api.version=1&servername='+servername+'&type='+vtype)

        def checkSNI(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/CheckSNISupport -
                This function allows WHM users to see if the server supports SNI, which allows for multiple SSL certificates per IP address and port number.
                """
                return self.cQuery('is_sni_supported?api.version=1')


        def installServiceSSL(self, service, crt, key, cabundle):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/InstallServiceSslCertificate -
                This function allows WHM users to install a new certificate on a service.
                These services are ftp, exim, dovecot, courier, and cpanel.
                """
                return self.cQuery('install_service_ssl_certificate?service='+service+'&crt='+crt+'&key='+key+'&cabundle='+cabundle+'&api.version=1')

        def regenerateServiceSSL(self, service):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ResetServiceSslCerificate -
                This function allows WHM users to regenerate a self-signed certificate and assign the certificate to a service.
                These services are ftp, exim, dovecot, courier, and cpanel.
                """
                return self.cQuery('reset_service_ssl_certificate?api.version=1&service='+service)

        def getServiceSSL(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/FetchServiceCertificates -
                This function allows WHM users to retrieve a list of services and their corresponding certificates.
                These services are ftp, exim, dovecot, courier, and cpanel.
                """
                return self.cQuery('fetch_service_ssl_components')





        def demoteReseller(self, username):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RemoveResellerPrivileges -
                This function removes reseller status from an account.
                """
                return self.cQuery('unsetupreseller?user='+username)

        def promoteReseller(self, username, make_owner=False):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/AddResellerPrivileges -
                This function gives reseller status to an existing account.
                """
                return self.cQuery('setupreseller?user='+username+'&makeowner='+make_owner)

        def createResellerACL(self, acllist, *args):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/CreateResellerACLList -
                This function creates a new reseller ACL list.
                """
                return self.cQuery('saveacllist?acllist='+acllist)

        def listResellerACL(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ListCurrentResellerACLLists -
                This function lists the saved reseller ACL lists on the server.
                """
                return self.cQuery('listacls')

        def listResellers(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ListResellerAccounts -
                This function lists the usernames of all resellers on the server.
                """
                return self.cQuery('listresellers')

        def getResellerDetails(self, reseller):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ListResellersAccountsInformation -
                This function shows account statistics for a specific reseller's accounts.
                """
                return self.cQuery('resellerstats?reseller='+reseller)

        def getResellerIPs(self, username):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/GetResellerips -
                This function will retrieve a list of IP Addresses that are available to a specified reseller.
                """
                return self.cQuery('getresellerips?user='+username)

        def setResellerACL(self, reseller, *args):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetResellersACLList -
                This function specifies the ACL for a reseller, or modifies specific ACL items for a reseller.
                """
                return self.cQuery('setacls?reseller='+reseller)

        def deleteReseller(self, reseller, terminate_reseller=True):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/TerminateResellerandAccounts -
                This function will terminate a reseller's main account, as well as all accounts owned by the reseller.
                """
                verify = '%20all%20the%20accounts%20owned%20by%20the%20reseller%20'+reseller
                return self.cQuery('terminatereseller?reseller='+reseller+'&terminatereseller='+terminate_reseller+'&verify='+verify)

        def allocateResellerIP(self, username, *args):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetResellerIps -
                This function will add IP addresses to a reseller account.
                """
                return self.cQuery('setresellerips?user='+username)

        def setResellerResourceLimits(self, username, *args):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetResellerLimits -
                This function allows you to specify the amount of bandwidth and disk space a reseller is able to use.
                """
                return self.cQuery('setresellerlimits?user='+username)

        def setResellerPackage(self, username, *args):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetResellerPkgLimit -
                This function allows you to control which packages resellers are able to use.
                """
                return self.cQuery('setresellerpackagelimit?user='+username)

        def setResellerMainIP(self, username, ip):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetResellerMainIp -
                This function will assign a main, shared IP address to a reseller.
                """
                return self.cQuery('setresellermainip?user='+username+'&ip='+ip)

        def suspendReseller(self, username, reason=""):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SuspendReseller -
                This function will allow you to suspend a reseller's account.
                """
                return self.cQuery('suspendreseller?user='+username+'&reason='+reason)

        def unsuspendReseller(self, username):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/UnsuspendReseller -
                This function allows you to unsuspend a reseller's account.
                """
                return self.cQuery('unsuspendreseller?user='+username)

        def setResellerNameservers(self, username, nameservers=""):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetResellerNameservers -
                This function allows you to define a reseller's nameservers.
                """
                return self.cQuery('setresellernameservers?user='+username+'&nameservers='+nameservers)

        def listResellerAccounts(self, username):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/AcctCounts -
                This function lists the total number of accounts owned by a reseller, as well as
                how many suspended accounts the reseller owns, and what the reseller's account creation limit is, if any.
                """
                return self.cQuery('acctcounts?user='+username)




        def getServerHostname(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/DisplayServerHostname -
                This function lists the server's hostname.
                """
                return self.cQuery('gethostname')

        def getServerVersion(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/DisplaycPanelWHMVersion -
                This function will display the version of cPanel & WHM running on the server.
                """
                return self.cQuery('version')

        def getServerLoads(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/LoadAvg -
                This function will display your server's load average.
                """
                return self.cQuery('loadavg')

        def getServerLoadsDetailed(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/XmlSystemLoadAvg -
                This function will calculate and return the system's load average.
                """
                return self.cQuery('systemloadavg?api.version=1')

        def getServerLanguages(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/GetLangList -
                This function retrieves a list of the languages available on your server.
                """
                return self.cQuery('getlanglist')




        def rebootServer(self, force=False):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/RebootServer -
                This function can restart a server gracefully or forcefully.
                """
                return self.cQuery('reboot?force='+force)

        def addServerIP(self, ips, netmask):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/AddIPs -
                Add new IP address(es) to WebHost Manager.
                """
                return self.cQuery('addips?api.version=1&ips='+ips+'&netmask='+netmask)

        def deleteServerIP(self, ip, *args):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/DeleteIPAddress -
                This function deletes an IP address from the server.
                """
                return self.cQuery('delip?ip='+ip)

        def listServerIPs(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ListIPAddresses -
                This function lists all IP addresses bound to network interfaces on the server.
                """
                return self.cQuery('listips')

        def setServerHostname(self, hostname):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetHostname -
                This function lets you change the server's hostname.
                """
                return self.cQuery('sethostname?hostname='+hostname)

        def setServerResolvers(self, nameserver1, nameserver2="", nameserver3=""):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetResolvers -
                This function configures the nameservers that your server will use to resolve domain names.
                """
                return self.cQuery('setresolvers?nameserver1='+nameserver1+'&nameserver2='+nameserver2+'&nameserver3='+nameserver3)

        def showBandwidthUsage(self, *args):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/ShowBw -
                This function will display bandwidth information by account.
                """
                return self.cQuery('showbw')

        def setNvVar(self, nvkey, nvval):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/NvSet -
                cPanel and WHM store "non-volatile" data on your server. You can use the nvset
                function to create these non-volatile variables and values, setting them to anything you wish.
                """
                return self.cQuery('nvset?key='+nvkey+'&value='+nvval)

        def getNvVar(self, nvkey):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/NvGet -
                cPanel and WHM store "non-volatile" data on your server. You can use the nvget function to view the value of a non-volatile variable.
                """
                return self.cQuery('nvget?key='+nvkey)

        def setServerSupportTier(self, tier="stable"):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetTier -
                This function will set your server to the specified support tier.
                """
                return self.cQuery('getpkginfo?tier='+tier)

        def getServerSupportTier(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/GetAvailabletiers -
                This function will retrieve a list of all available support tiers of cPanel and WHM.
                """
                return self.cQuery('get_available_tiers')

        def generateAccessHash(self, *args):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/AccessHash -
                You can use this function to retrieve an access hash for the root user.
                Authenticated resellers may also retrieve an access hash if he or she has the all ACL.
                """
                return self.cQuery('accesshash?api.version=1')

        def getKeyDocuments(self, module, key, section=""):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/FetchDocKey -
                This function call allows you to retrieve documentation about a key referenced within a specified module.
                """
                return self.cQuery('fetch_doc_key?module='+module+'&key='+key)

        def validateEximConfigSpecified(self, cfg_text, section=""):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/EximValidateSyntax -
                This function will evaluate and validate Exim configuration file syntax. This
                function requires raw text from the configuration file as input.
                """
                return self.cQuery('validate_exim_configuration_syntax?cfg_text='+cfg_text)

        def validateEximConfig(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/EximValidateConfig -
                This function validates the system's current Exim configuration.
                """
                return self.cQuery('validate_current_installed_exim_config')

        def checkRepairEximConfig(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/EximConfigurationCheck -
                This function will check and, if it encounters any errors, attempt to repair your Exim configuration.
                """
                return self.cQuery('exim_configuration_check')

        def removeInProgressEximEdit(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/EximRemoveDryRunConfig -
                This function allows you to remove dry run files after a failed Exim update attempt.
                """
                return self.cQuery('remove_in_progress_exim_config_edit')

        def getTweakSettingsValue(self, key, module="Main"):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/GetTweakSetting -
                You can use this function to retrieve the value of an option available on the WHM Tweak Settings
                screen. The keys and values needed to perform this function are in the /var/cpanel/cpanel.config file.
                """
                return self.cQuery('get_tweaksetting?api.version=1&key='+key+'&module='+module)

        def setTweakSettingsValue(self, key, val, module="Main"):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetTweakSetting -
                You can use this function to change the value of an option available on the WHM Tweak Settings
                screen. The keys and values needed to perform this function are in the /var/cpanel/cpanel.config file.
                """
                return self.cQuery('set_tweaksetting?api.version=1&key='+key+'&value='+val+'&module='+module)

        def getDeliveryRecords(self, *args):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/EmailTrackSearch -
                This function retrieves email delivery records.
                """
                return self.cQuery('emailtrack_search?api.version=1')

        def setServerUpdateFrequency(self, updates="manual"):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetCpanelupdates -
                This function will set the frequency that updates will run on the server.
                """
                return self.cQuery('set_cpanel_updates?updates='+updates)

        def getAppConfigApps(self):
                """
                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/GetAppconfigapplicationlist -
                This function allows you to retrieve a list of applications that are registered with AppConfig.
                """
                return self.cQuery('get_appconfig_application_list')
