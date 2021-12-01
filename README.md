# ASL-RuntimeTerror
Applied Security Laboratory - project repo for ETHZ course

Every services are run without any specific actions on the VM at boot.

Be careful, we have three different keyboard layouts through the VM. Feel free to modify them. It should be trivial.

---

## Credentials on VMs
firewall:FireWalkWithMe_8723 (root:DoYouWantToPlayWithFire?)
backupp:PlanB6IsAlwaysNeeded (root:Exchange82FilesNow)
dbase:dataJop9_11LP (root:dbaseRoOT9971_)
ca-server:Respect7Ma2Authority! (root:YouCanTrust_Me24)
webserver:spell9MyName_1 (root:look8OverThere_73)
aslclient:TestingIsFun (root:EvenMorePossibilities)

### dbase mysql passwords
root:NobodyKnowsThisString
webServer:IWantUserDataNOW
backupServer:BackMeUpDaddy
admin:adminByChoice

---

## Web Server Access URL

* User login with username and password: https://192.168.20.10:8443/login
* User login with certificate: https://192.168.20.10:8443/login_certificate
* Admin login with certificate: https://192.168.20.10:8443/login_admin
* Log out and clear the session: https://192.168.20.10:8443/logout
* Get and update user data: https://192.168.20.10:8443/user_data
* Get new certificate for the current user: https://192.168.20.10:8443/issue_certificate
* Revoke currently used certificate: https://192.168.20.10:8443/revoke_certificate
* Get CA statistics for admin: https://192.168.20.10:8443/admin_stats