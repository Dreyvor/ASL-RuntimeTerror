Steps to take to configure the database server. Note: if you have the modified imovies_users.dump script, you do not need to add lines to it.

1. Install wget, if not present:
	<sudo apt-get install wget>
	
2. Download release package from https://dev.mysql.com/downloads/repo/apt/

3. Run following command with downloaded package:
	<sudo dpkg -i PATH_TO_PACKAGE>
	
   Currently: Package in use is mysql-apt-config_0.8.20-1_all.deb
   	<sudo dpkg -i /PATH/mysql-apt-config_0.8.20-1_all.deb>
   	
4. Update apt (mandatory!):
	<sudo apt-get update>
	
5. Install mysql server (note the root password):
	<sudo apt-get install mysql-server> (password: NobodyKnowsThisString)

6. Check status of server:
	<systemctl status mysql>

7. Install ssh meta package:
	<sudo apt-get install ssh>

8. Install tcpd and inetd:
	<sudo apt install tcpd>
	<sudo apt-get install inetutils-inetd>

9. For MySQL use iptables:
	Donwload persistent iptables:
	<sudo apt-get install iptables-persistent>
	
10. Add iptables rules and save them:
	<iptables -A INPUT -p tcp --dport 3306 -s 192.168.10.1 -j ACCEPT
	iptables -A INPUT -p tcp --dport 3306 -s 192.168.10.20 -j ACCEPT
	iptables -A INPUT -p tcp --dport 3306 -j DROP
	sudo /etc/init.d/netfilter-persistent save>
	
12. Add CA certificate, signed server certificate, and key to /etc/mysql/my.cnf: (Note: to replace keys used by mysql, move them to /var/lib/mysql)
	[mysqld]
	<ssl_ca=/path/to/ca.pem
	ssl_cert=/path/to/server-cert.pem
	ssl_key=/path/to/server-key.pem
	require_secure_transport=ON>

13. Enable use of keyring for data-at-rest encryption:
	<early-plugin-load=/usr/lib/mysql/plugin/keyring_file.so>
	
14. Download imovies_users.dump from course website.

15. Add following lines before the CREATE TABLE statement:

	CREATE DATABASE IF NOT EXISTS imovies_db;
	USE imovies_db;

16. Change the CREATE TABLE statement to end with the following line:

	) ENCRYPTION='Y' ENGINE=INNODB DEFAULT CHARSET=latin1;

17. Create database users and grant permissions (add lines to imovies_users.dump):

	CREATE USER 'webServer'@192.168.10.1 IDENTIFIED BY 'webServer';
	GRANT UPDATE, INSERT, SELECT ON imovies_db.* TO 'webServer'@192.168.10.1;
	CREATE USER 'backupServer'@192.168.10.20 IDENTIFIED BY 'backupServer';
	GRANT UPDATE, INSERT, SELECT ON imovies_db.* TO 'backupIP'@192.168.10.20;
	CREATE USER admin IDENTIFIED BY 'adminPW';
	GRANT ALL PRIVILEGES ON imovies_db.* TO admin;

18. Login to mysql as root:
	<mysql -u root -p>

19. Run the SQL script:
	<source /PATH/imovies_users.dump>
	
20. Configure machine to always use TLSv1.3. Make sure that the following lines are present in /etc/ssl/openssl.cnf:
	<MinProtocol=TLSv1.3
	Ciphersuites=TLS_CHACHA20_POLY1305_SHA256>

21. Add the following lines to /etc/mysql/my.cnf:
	<tls_version=TLSv1.3
	tls_ciphersuites=TLS_CHACHA20_POLY1305_SHA256>
	
22. Set static IP address. Change line in /etc/network/interfaces from
	<iface enp0s3 inet dhcp>
	to
	<iface enp0s3 inet static
		address 192.168.10.30
		network 192.168.10.0
		netmask 255.255.255.0
		gateway 192.168.10.1>
	
	and change lines in /etc/network/interfaces.d/* from
	<auto eth0
	iface eth0 inet dhcp>
	to
	<allow-hotplug eth0
	iface eth0 inet static
		address 192.168.10.30
		network 192.168.10.0
		netmask 255.255.255.0
		gateway 192.168.10.1>
		
23. Enable query log for mysql. Add the following lines to /etc/mysql/my.cnf:
	<general_log_file=/var/lib/mysql/query.log
	general_log=ON
	log_output=file>