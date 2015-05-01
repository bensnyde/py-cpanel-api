"""
    Python library for WHM API 1

        https://documentation.cpanel.net/display/SDK/Guide+to+WHM+API+1

        ** Note: there are many more WHM/Cpanel functions available that are not implemented below.

    @author     Benton Snyder
    @website    http://bensnyde.me
    @email      benton@bensnyde.me
    @created    7/24/13
    @updated    5/1/15
"""
from httplib import HTTPSConnection
from base64 import b64encode

class Cpanel:
    def __init__(self, url, username, password):
        self.url = url
        self.authHeader = {'Authorization':'Basic ' + b64encode(username+':'+password).decode('ascii')}

    def __cQuery(self, queryStr):
        """Query WHM

                Queries specified WHM Server's JSON API.

        Parameters
            queryStr:str - HTTP GET formatted query string.
        Returns
            JSON response from server
        """
        conn = HTTPSConnection(self.url, 2087)
        conn.request('GET', '/json-api/'+queryStr, headers=self.authHeader)
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return data

    def createAccount(self, username, domain, *args):
        """Create Cpanel Account

            This function creates a hosting account and sets up its associated domain information.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+createacct
        """
        return self.__cQuery('createacct?username='+username+'&domain='+domain)

    def changeAccountPassword(self, username, password, update_db_password=True):
        """Set Cpanel Account Password

            This function changes the password of a domain owner (cPanel) or reseller (WHM) account.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+passwd
        """
        return self.__cQuery('passwd?user='+username+'&pass='+password+'&db_pass_update='+update_db_password)

    def limitAccountBandwidth(self, username, bwlimit):
        """Set Cpanel Account Bandwidth Limit

            This function modifies the bandwidth usage (transfer) limit for a specific account.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+limitbw
        """
        return self.__cQuery('limitbw?user='+username+'&bwlimit='+bwlimit)

    def listAccounts(self, *args):
        """List Cpanel Accounts

            This function lists all accounts on the server, and also allows you to search for a specific account or set of accounts.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+listaccts
        """
        return self.__cQuery('lictaccts')

    def modifyAccount(self, username, *args):
        """Edit Cpanel Account

            This function modifies settings for an account.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+modifyacct
        """
        return self.__cQuery('modifyacct?user='+username)

    def changeAccountDiskQuota(self, username, quota):
        """Set Cpanel Account Disk Quota

            This function changes an account's disk space usage quota.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+editquota
        """
        return self.__cQuery('editquota?user='+username+'&quota='+quota)

    def getAccountSummary(self, username):
        """Get Cpanel Account Summary

            This function displays pertinent information about a specific account.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+accountsummary
        """
        return self.__cQuery('accountsummary?user='+username)

    def suspendAccount(self, username, reason=""):
        """Suspend Cpanel Account

            This function will allow you to prevent a cPanel user from accessing his or her account.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+suspendacct
        """
        return self.__cQuery('suspendacct?user='+username+'&reason='+reason)

    def listSuspendedAccounts(self):
        """List Suspended Cpanel Accounts

            This function will generate a list of suspended accounts.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+listsuspended
        """
        return self.__cQuery('listsuspended')

    def terminateAccount(self, username, keep_dns=False):
        """Terminate Cpanel Account

            This function permanently removes a cPanel account.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+removeacct
        """
        return self.__cQuery('removeacct?user='+username+'&keepdns='+keep_dns)

    def unsuspendAccount(self, username):
        """Unsuspend Cpanel Account

            This function will unsuspend a suspended account.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+unsuspendacct
        """
        return self.__cQuery('unsuspendacct?user='+username)

    def changeAccountPackage(self, username, package):
        """Change Cpanel Account Package

            This function changes the hosting package associated with a cPanel account.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+changepackage
        """
        return self.__cQuery('changepackage?user='+username+'&pkg='+package)

    def getDomainUserdata(self, domain):
        """Get User Data By Domain

            This function lets you obtain user data for a specific domain.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+domainuserdata
        """
        return self.__cQuery('domainuserdata?domain='+domain)

    def changeDomainIpAddress(self, domain, ip_address):
        """Set Domain's IP Address

            This function allows you to change the IP address of a website hosted on your server

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+setsiteip
        """
        return self.__cQuery('setsiteip?domain='+domain+'&ip='+ip_address)

    def changeAccountIpAddress(self, username, ip_address):
        """Set Cpanel Account IP Address

            This function allows you to change the IP address of a user account hosted on your server

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+setsiteip
        """
        return self.__cQuery('setsiteip?user='+username+'&ip='+ip_address)

    def restoreAccountBackup(self, username, backup_type="daily", all_services=True, ip=True, mail=True, mysql=True, subs=True):
        """Restore Cpanel Account From Backup

            This function allows you to restore a user's account from a backup file.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+restoreaccount
        """
        if backup_type not in ["daily", "weekly", "monthly"]:
                raise Exception("Invalid backup_type.")

        return self.__cQuery('restoreaccount?api.version=1&user='+username+'&type='+backup_type+'&all='+all_services)

    def setAccountDigestAuthentication(self, username, password, enable_digest=True):
        """Toggle Cpanel Account's Digest Authentication

            This function enables or disables Digest Authentication for a user account.

                http://docs.cpanel.net/twiki/bin/view/SoftwareDevelopmentKit/SetDigestAuth -
        """
        return self.__cQuery('set_digest_auth?user='+username+'&password='+password+'&enabledigest='+enable_digest+'&api.version=1')

    def getAccountDigestAuthentication(self, username):
        """Get Cpanel Account's Digest Authentication

            This function will check whether a cPanel user has digest authentication enabled.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+set_digest_auth
        """
        return self.__cQuery('has_digest_auth?user='+username)


    def getPrivileges(self):
        """Get Privileges

            This function will generate a list of features you are allowed to use in WHM. Each feature will display either a 1 or 0.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+myprivs
        """
        return self.__cQuery('myprivs')

    def restoreAccountBackupQueued(self, username, restore_point, give_ip=False, mysql=True, subdomains=True, mail_config=True):
        """Start Restore Cpanel Account From Backup Job

            This function allows you to restore a user's account from a backup file.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+restore_queue_add_task
        """
        return self.__cQuery('restore_queue_add_task?user='+username+'&restore_point='+restore_point
                +'&give_ip='+give_ip+'&mysql='+mysql+'&subdomains='+subdomains+'&mail_config='+mail_config)

    def activateRestoreQueue(self):
        """Activate Restore Job Queue

            This function allows you to activate the restore queue and start a process to restore all queued accounts.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+restore_queue_activate
        """
        return self.__cQuery('restore_queue_activate')

    def getRestoreQueueState(self):
        """Get Restore Job Queue State

            This function allows you to see if the queue is actively in the restoration process for certain accounts.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+restore_queue_is_active
        """
        return self.__cQuery('restore_queue_is_active')

    def getRestoreQueueActive(self):
        """Get Active Jobs From Restore Queue

            This function allows you to list all accounts currently in the restoration process.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+restore_queue_list_active
        """
        return self.__cQuery('restore_queue_list_active')

    def getRestoreQueueCompleted(self):
        """Get Completed Jobs From Restore Queue

            This function allows you to list all completed restorations, successful restores, failed restores, and the restore log.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+restore_queue_list_completed
        """
        return self.__cQuery('restore_queue_list_completed')

    def clearRestoreQueuePendingTask(self, username):
        """Clear A Pending Job From Restore Queue

            This function allows you to clear a single pending account from the Restoration Queue.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+restore_queue_clear_pending_task
        """
        return self.__cQuery('restore_queue_clear_pending_task?user='+username)

    def clearRestoreQueuePendingTasks(self):
        """Clear All Pending Jobs From Restore Queue

            This function allows you to clear all pending accounts from the restore queue.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+restore_queue_clear_all_pending_tasks
        """
        return self.__cQuery('restore_queue_clear_all_pending_tasks')

    def clearRestoreQueueCompletedTask(self, username):
        """Clear A Completed Job From Restore Queue

            This function allows you to clear a single completed account from the Restoration Queue. The account
            may have completed successfully, or the account may have failed to successfully complete.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+restore_queue_clear_completed_task
        """
        return self.__cQuery('restore_queue_clear_completed_task?user='+username)

    def clearRestoreQueueCompletedTasks(self):
        """Clear All Completed Jobs From Restore Queue

            This function allows you to clear all successfully completed accounts from the Restoration Queue.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+restore_queue_clear_all_completed_tasks
        """
        return self.__cQuery('restore_queue_clear_all_completed_tasks')

    def clearRestoreQueueFailedTasks(self):
        """Clear Failed Jobs From Restore Queue

            This function allows you to clear all failed tasks from the Restoration Queue.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+restore_queue_clear_all_failed_tasks
        """
        return self.__cQuery('restore_queue_clear_all_failed_tasks')

    def clearRestoreQueueAll(self):
        """Clear All Jobs From Restore Queue

            This function allows you to clear all open, unresolved, or pending tasks from the Restoration Queue.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+restore_queue_clear_all_tasks
        """
        return self.__cQuery('restore_queue_clear_all_tasks')

    def getBackupConfig(self):
        """Get Backup Configuration

            This function allows you to receive detailed data from your backup destination configuration file.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+backup_config_get
        """
        return self.__cQuery('backup_config_get')

    def setBackupConfig(self, *args):
        """Set Backup Configuration

            This function allows you to save the data from the backup configuration page and put the data in /var/cpanel/bakcups/config

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+backup_config_set
        """
        return self.__cQuery('backup_config_set')

    def setBackupConfigAllUsers(self, state=True):
        """Set Backup Config For All Users

            This function allows you to choose which Backup Configuration to use, and enable or disable backups for all users.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+backup_skip_users_all
        """
        return self.__cQuery('backup_skip_users_all?state='+state)

    def getBackupConfigAllUsers(self):
        """Get Backup Config For All Users

            This function allows you to retrieve the value from the status log file in the backup_skip_users_all api call.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+backup_skip_users_all_status
        """
        return self.__cQuery('backup_skip_users_all_status')

    def getBackupListFiles(self):
        """Get Backed Up Files

            This function allows you to find all backup files available on the server. This
            function also returns a list of users and dates so that the Restore Account(s) feature in WHM can show them.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+backup_set_list
        """
        return self.__cQuery('backup_set_list')

    def getBackupListDates(self):
        """Get Backed Up File Dates

            This function allows you to retrieve a list of all dates with a backup file saved.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+backup_date_list
        """
        return self.__cQuery('backup_date_list')

    def getBackupsByDate(self, date):
        """Get Backups By Date

            This function returns a list all users with a backup file saved on a specific date that you choose.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+backup_user_list
        """
        return self.__cQuery('backup_user_list?restore_point='+date)

    def validateBackupDestination(self, destination_id, disable_on_fail=False):
        """Validate Backup Destination

            This function allows you to run a validation routine on a specified backup destination.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+backup_destination_validate
        """
        return self.__cQuery('backup_destination_validate?id='+destination_id+'&disableonfail='+disable_on_fail)

    def addBackupDestination(self, backup_type, *args):
        """Add Backup Destination

            This function allows you to create a backup destination and save it to a config file.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+backup_destination_add
        """
        if backup_type not in ["FTP", "Local", "SFTP", "WebDav", "Custom"]:
                raise Exception("Invalid backup_type")

        return self.__cQuery('backup_destination_add?type='+backup_type)

    def setBackupDestination(self, destination_id, *args):
        """Set Backup Destination

            This function allows you to modify the setup and data for a backup destination.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+backup_destination_set
        """
        return self.__cQuery('backup_destination_set?id='+destination_id)

    def deleteBackupDestination(self, destination_id):
        """Delete Backup Destination

            This function allows you to remove the backup destination config file.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+backup_destination_delete
        """
        return self.__cQuery('backup_destination_delete?id='+destination_id)

    def getBackupDestinationDetails(self, destination_id):
        """Get Backup Destination Details

            This function allows you to retrieve detailed data for a specific backup destination from the backup destination config file.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+backup_destination_get
        """
        return self.__cQuery('backup_destination_get?id='+destination_id)

    def listBackupDestionations(self):
        """List Backup Destinations

            This function allows you to list all backup destinations, including their configuration information.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+backup_destination_list
        """
        return self.__cQuery('backup_destination_list')

    def addPackage(self, name, *args):
        """Add Hosting Package

            This function adds a new hosting package.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+addpkg
        """
        return self.__cQuery('addpkg?name='+name)

    def deletePackage(self, name):
        """Delete Hosting Package

            This function deletes a specific hosting package.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+killpkg
        """
        return self.__cQuery('killpkg?pkg='+name)

    def editPackage(self, name, *args):
        """Edit Hosting Package

            This function edits all aspects of a specific hosting package.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+editpkg
        """
        return self.__cQuery('editpkg?name='+name)

    def listPackages(self):
        """List Hosting Packages

            This function lists all hosting packages available for use by the WHM user who is currently logged in.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+listpkgs
        """
        return self.__cQuery('listpkgs')

    def listFeatures(self):
        """List WHM Features

            This function will retrieve a list of available features.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+getfeaturelist
        """
        return self.__cQuery('getfeaturelist')

    def restartService(self, service):
        """Restart Service

            This function restarts a service (daemon) on the server.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+restartservice
        """
        return self.__cQuery('restartservice?service='+service)

    def getServiceStatus(self, service):
        """Get Service Status

            This function tells you which services (daemons) are installed and enabled on, and monitored by, your server.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+servicestatus
        """
        return self.__cQuery('servicestatus?service='+service)

    def configureService(self, service, enabled=True, monitored=True):
        """Configure Service

            This function allows you to enable or disable a service, and enable or disable monitoring of that
            service in the same manner as the WHM Service Manager.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+configureservice
        """
        return self.__cQuery('configureservice?service='+service+'&enabled='+enabled+'&monitored='+monitored)

    def getSSLDetails(self, domain):
        """Get SSL Details

            This function displays the SSL certificate, private key, and CA bundle/intermediate certificate associated with a specified domain.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+fetchsslinfo
        """
        return self.__cQuery('fetchsslinfo?domain='+domain)

    def generateSSL(self, xemail, host, country, state, city, co, cod, email, password):
        """Generate SSL Certificate

            This function generates an SSL certificate.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+generatessl
        """
        return self.__cQuery('generatessl?xemail='+xemail+'&host='+host+'&country='+country+
                '&state='+state+'&city='+city+'&co='+co+'&cod='+cod+'&email='+email+'&pass='+password)

    def installSSL(self, username, domain, cert, key, cab, ip):
        """Install SSL Certificate

            This function installs an SSL certificate.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+installssl
        """
        return self.__cQuery('installssl?user='+username+'&domain='+domain+'&cert='+cert+'&key='+key+'&cab='+cab+'&ip='+ip)

    def listSSL(self):
        """List SSL Certificates

            This function will list all domains on the server that have SSL certificates installed.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+listcrts
        """
        return self.__cQuery('listcrts')

    def setPrimaryDomain(self, servername, vtype="std"):
        """Set Cpanel Account's Primary Domain

            This function allows WHM users to set the primary domain on an IP address and port (ssl or std)
            for their accounts' sites. The primary domain refers to the virtual host that will be served when
            the IP address is accessed directly.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+set_primary_servername
        """
        return self.__cQuery('set_primary_servername?api.version=1&servername='+servername+'&type='+vtype)

    def checkSNI(self):
        """Check For SNI

            This function allows WHM users to see if the server supports SNI, which allows for multiple SSL certificates per IP address and port number.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+is_sni_supported
        """
        return self.__cQuery('is_sni_supported?api.version=1')


    def installServiceSSL(self, service, crt, key, cabundle):
        """Install SSL Certificate to System Service

            This function allows WHM users to install a new certificate on a service.
            These services are ftp, exim, dovecot, courier, and cpanel.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+install_service_ssl_certificate
        """
        return self.__cQuery('install_service_ssl_certificate?service='+service+'&crt='+crt+'&key='+key+'&cabundle='+cabundle+'&api.version=1')

    def regenerateServiceSSL(self, service):
        """Regenerate System Service's SSL Certificate

            This function allows WHM users to regenerate a self-signed certificate and assign the certificate to a service.
            These services are ftp, exim, dovecot, courier, and cpanel.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+reset_service_ssl_certificate
        """
        return self.__cQuery('reset_service_ssl_certificate?api.version=1&service='+service)

    def getServiceSSL(self):
        """Get System Service's SSL Certificate

            This function allows WHM users to retrieve a list of services and their corresponding certificates.
            These services are ftp, exim, dovecot, courier, and cpanel.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+fetch_service_ssl_components
        """
        return self.__cQuery('fetch_service_ssl_components')

    def demoteReseller(self, username):
        """Demote Reseller

            This function removes reseller status from an account.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+unsetupreseller
        """
        return self.__cQuery('unsetupreseller?user='+username)

    def promoteReseller(self, username, make_owner=False):
        """Promote Reseller

            This function gives reseller status to an existing account.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+setupreseller
        """
        return self.__cQuery('setupreseller?user='+username+'&makeowner='+make_owner)

    def createResellerACL(self, acllist, *args):
        """Create Reseller ACL

            This function creates a new reseller ACL list.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+saveacllist
        """
        return self.__cQuery('saveacllist?acllist='+acllist)

    def listResellerACL(self):
        """List Reseller ACL

            This function lists the saved reseller ACL lists on the server.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+listacls
        """
        return self.__cQuery('listacls')

    def listResellers(self):
        """List Resellers

            This function lists the usernames of all resellers on the server.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+listresellers
        """
        return self.__cQuery('listresellers')

    def getResellerDetails(self, reseller):
        """Get Reseller Details

            This function shows account statistics for a specific reseller's accounts.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+resellerstats
        """
        return self.__cQuery('resellerstats?reseller='+reseller)

    def getResellerIPs(self, username):
        """Get Reseller IP Addresses

            This function will retrieve a list of IP Addresses that are available to a specified reseller.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+getresellerips
        """
        return self.__cQuery('getresellerips?user='+username)

    def setResellerACL(self, reseller, *args):
        """Set Reseller ACL

            This function specifies the ACL for a reseller, or modifies specific ACL items for a reseller.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+setacls
        """
        return self.__cQuery('setacls?reseller='+reseller)

    def deleteReseller(self, reseller, terminate_reseller=True):
        """Delete Reseller

            This function will terminate a reseller's main account, as well as all accounts owned by the reseller.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+terminatereseller
        """
        verify = '%20all%20the%20accounts%20owned%20by%20the%20reseller%20'+reseller
        return self.__cQuery('terminatereseller?reseller='+reseller+'&terminatereseller='+terminate_reseller+'&verify='+verify)

    def allocateResellerIP(self, username, *args):
        """Allocate IP Addresses To Reseller

            This function will add IP addresses to a reseller account.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+setresellerips
        """
        return self.__cQuery('setresellerips?user='+username)

    def setResellerResourceLimits(self, username, *args):
        """Set Reseller Resource Limits

            This function allows you to specify the amount of bandwidth and disk space a reseller is able to use.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+setresellerlimits
        """
        return self.__cQuery('setresellerlimits?user='+username)

    def setResellerPackage(self, username, *args):
        """Set Reseller Package

            This function allows you to control which packages resellers are able to use.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+setresellerpackagelimit
        """
        return self.__cQuery('setresellerpackagelimit?user='+username)

    def setResellerMainIP(self, username, ip):
        """Set Reseller Primary IP Address

            This function will assign a main, shared IP address to a reseller.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+setresellermainip
        """
        return self.__cQuery('setresellermainip?user='+username+'&ip='+ip)

    def suspendReseller(self, username, reason=""):
        """Suspend Reseller

            This function will allow you to suspend a reseller's account.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+suspendreseller
        """
        return self.__cQuery('suspendreseller?user='+username+'&reason='+reason)

    def unsuspendReseller(self, username):
        """Unsuspend Reseller

            This function allows you to unsuspend a reseller's account.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+unsuspendreseller
        """
        return self.__cQuery('unsuspendreseller?user='+username)

    def setResellerNameservers(self, username, nameservers=""):
        """Set Reseller Nameserver Records

            This function allows you to define a reseller's nameservers.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+setresellernameservers
        """
        return self.__cQuery('setresellernameservers?user='+username+'&nameservers='+nameservers)

    def listResellerAccounts(self, username):
        """List Reseller's Owned Accounts

            This function lists the total number of accounts owned by a reseller, as well as
            how many suspended accounts the reseller owns, and what the reseller's account creation limit is, if any.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+acctcounts
        """
        return self.__cQuery('acctcounts?user='+username)

    def getServerHostname(self):
        """Get Server Hostname

            This function lists the server's hostname.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+gethostname
        """
        return self.__cQuery('gethostname')

    def getServerVersion(self):
        """Get Server Version

            This function will display the version of cPanel & WHM running on the server.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+version
        """
        return self.__cQuery('version')

    def getServerLoads(self):
        """Get Server Loads

            This function will display your server's load average.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+loadavg
        """
        return self.__cQuery('loadavg')

    def getServerLoadsDetailed(self):
        """Get Detailed Server Loads

            This function will calculate and return the system's load average.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+systemloadavg
        """
        return self.__cQuery('systemloadavg?api.version=1')

    def rebootServer(self, force=False):
        """Reboot Server

            This function can restart a server gracefully or forcefully.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+reboot
        """
        return self.__cQuery('reboot?force='+force)

    def addServerIP(self, ips, netmask):
        """Add IP Address to Server

            Add new IP address(es) to WebHost Manager.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+addips
        """
        return self.__cQuery('addips?api.version=1&ips='+ips+'&netmask='+netmask)

    def deleteServerIP(self, ip, *args):
        """Delete IP Address From Server

            This function deletes an IP address from the server.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+delip
        """
        return self.__cQuery('delip?ip='+ip)

    def listServerIPs(self):
        """List Server IP Addresses

            This function lists all IP addresses bound to network interfaces on the server.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+listips
        """
        return self.__cQuery('listips')

    def setServerHostname(self, hostname):
        """Set Server Hostname

            This function lets you change the server's hostname.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+sethostname
        """
        return self.__cQuery('sethostname?hostname='+hostname)

    def setServerResolvers(self, nameserver1, nameserver2="", nameserver3=""):
        """Set Server DNS Resolvers

            This function configures the nameservers that your server will use to resolve domain names.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+setresolvers
        """
        return self.__cQuery('setresolvers?nameserver1='+nameserver1+'&nameserver2='+nameserver2+'&nameserver3='+nameserver3)

    def showBandwidthUsage(self, *args):
        """Show Bandwidth Usage

            This function will display bandwidth information by account.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+showbw
        """
        return self.__cQuery('showbw')

    def setNvVar(self, nvkey, nvval):
        """Set Non-Volatile Variable

            cPanel and WHM store "non-volatile" data on your server. You can use the nvset
            function to create these non-volatile variables and values, setting them to anything you wish.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+nvset
        """
        return self.__cQuery('nvset?key='+nvkey+'&value='+nvval)

    def getNvVar(self, nvkey):
        """Get Non-Volatile Variable

            cPanel and WHM store "non-volatile" data on your server. You can use the nvget function to view the value of a non-volatile variable.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+nvget
        """
        return self.__cQuery('nvget?key='+nvkey)

    def setServerSupportTier(self, tier="stable"):
        """Set Server Support Tier

            This function will set your server to the specified support tier.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+set_tier
        """
        return self.__cQuery('set_tier?tier='+tier)

    def getServerSupportTier(self):
        """Get Server Support Tier

            This function will retrieve a list of all available support tiers of cPanel and WHM.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+get_available_tiers
        """
        return self.__cQuery('get_available_tiers')

    def generateAccessHash(self, *args):
        """Generate Access Hash

            You can use this function to retrieve an access hash for the root user.
            Authenticated resellers may also retrieve an access hash if he or she has the all ACL.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+accesshash
        """
        return self.__cQuery('accesshash?api.version=1')

    def validateEximConfigSpecified(self, cfg_text, section=""):
        """Validate Specified Exim Configuration

            This function will evaluate and validate Exim configuration file syntax. This
            function requires raw text from the configuration file as input.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+validate_exim_configuration_syntax
        """
        return self.__cQuery('validate_exim_configuration_syntax?cfg_text='+cfg_text)

    def validateEximConfig(self):
        """Validate Exim Configuration

            This function validates the system's current Exim configuration.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+validate_current_installed_exim_config
        """
        return self.__cQuery('validate_current_installed_exim_config')

    def checkRepairEximConfig(self):
        """Check and Repair Exim Configuration

            This function will check and, if it encounters any errors, attempt to repair your Exim configuration.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+exim_configuration_check
        """
        return self.__cQuery('exim_configuration_check')

    def removeInProgressEximEdit(self):
        """Remove In-Progress Exim Configuration Edit

            This function allows you to remove dry run files after a failed Exim update attempt.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+remove_in_progress_exim_config_edit
        """
        return self.__cQuery('remove_in_progress_exim_config_edit')

    def getTweakSettingsValue(self, key, module="Main"):
        """Get WHM Tweak Settings Value

            You can use this function to retrieve the value of an option available on the WHM Tweak Settings
            screen. The keys and values needed to perform this function are in the /var/cpanel/cpanel.config file.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+get_tweaksetting
        """
        return self.__cQuery('get_tweaksetting?api.version=1&key='+key+'&module='+module)

    def setTweakSettingsValue(self, key, val, module="Main"):
        """Set WHM Tweak Settings Value

            You can use this function to change the value of an option available on the WHM Tweak Settings
            screen. The keys and values needed to perform this function are in the /var/cpanel/cpanel.config file.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+set_tweaksetting
        """
        return self.__cQuery('set_tweaksetting?api.version=1&key='+key+'&value='+val+'&module='+module)

    def getDeliveryRecords(self, *args):
        """Get Mail Delivery Reports

            This function retrieves email delivery records.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+emailtrack_search
        """
        return self.__cQuery('emailtrack_search?api.version=1')

    def setServerUpdateFrequency(self, updates="manual"):
        """Set Server Update Frequency

            This function will set the frequency that updates will run on the server.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+set_cpanel_updates
        """
        return self.__cQuery('set_cpanel_updates?updates='+updates)

    def getAppConfigApps(self):
        """Get AppConfig Apps

            This function allows you to retrieve a list of applications that are registered with AppConfig.

                https://documentation.cpanel.net/display/SDK/WHM+API+1+Functions+-+get_appconfig_application_list
        """
        return self.__cQuery('get_appconfig_application_list')
