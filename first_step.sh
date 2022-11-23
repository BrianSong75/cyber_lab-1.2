#! /usr/bin/env bash

#maksing sure the script stops when there is an error
set -e

#create ip address files
cat << EOF > /tmp/phase1_ip.txt
192.168.0.220	elk.cyber.lab
192.168.0.230	farm0.cyber.lab
192.168.0.240	farm1.cyber.lab
192.168.0.250	farm2.cyber.lab
192.168.0.210	jbox.cyber.lab
EOF

cat << EOF > /tmp/phase2_ip.txt
192.168.0.231	ws1.cyber.lab
192.168.0.232	ws2.cyber.lab
192.168.0.241	ws3.cyber.lab
192.168.0.233	vpn.cyber.lab
192.168.0.242	lb.cyber.lab
192.168.0.243	log.cyber.lab
EOF

#create the sysadm user at Farm2
if [[ $( grep -ie sysadm /etc/passwd ) == 0 ]]
then
	useradd -m -G root,wheel,adm,users,sys -s /bin/bash -p $(openssl passwd -crypt nada) sysadm
	echo "sysadm	ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/sudoer_sysadm
	chmod -c 0440 /etc/sudoers.d/sudoer_sysadm && chown -c root:root /etc/sudoers.d/sudoer_sysadm && visudo -c

	sudo -u sysadm mkdir -v ~sysadm/.ssh/
	sudo -u sysadm ssh-keygen -q -t ed25519 -b 4096 -P "" -f ~sysadm/.ssh/id_ed25519
elif [[ ! -f /etc/sudoers.d/sudoer_sysadm ]]
then
	echo "sysadm 	ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/sudoer_sysadm
	chmod -c 0440 /etc/sudoers.d/sudoer_sysadm && chown -c root:root /etc/sudeors.d/sudoer_sysadm && visudo -c

	if [[ ! -d ~sysadm/.ssh ]]
	then
		sudo -u sysadm mkdir -v ~sysadm/.ssh
		if [[ ! -f ~sysadm/.ssh/id_ed25519 ]]
		then
			sudo -u sysadm ssh-keygen -q -t ed25519 -b 4096 -P "" -f ~sysadm/.ssh/id_ed25519
		fi
	fi
elif [[ ! -d ~sysadm/.ssh ]]
then
	sudo -u sysadm mkdir -v ~sysadm/.ssh
	sudo -u sysadm ssh-keygen -q -t ed25519 -b 4096 -P "" -f ~sysadm/.ssh/id_ed25519
elif [[ ! -f ~sysadm/.ssh/id_ed25519 ]]
then
	sudo -u sysadm ssh-keygen -q -t ed25519 -b 4096 -P "" -f ~sysadm/.ssh/id_ed25519
fi

#create CA keys for SSH comm
if [ ! -d ~root/.ssh/.CA ]
then
	mkdir -vp ~root/.ssh/.CA
fi

for i in CA_svr CA_clnt CA_sys
do
	if [ ! -f ~root/.ssh/.CA/$i ]
	then
		ssh-keygen -q -t ed25519 -b 4096 -P "" -f ~root/.ssh/.CA/$i
	fi
done

#create ssh Pubkey for root
if [ ! -f ~root/.ssh/id_ed25519 ]
then
	sudo -u root ssh-keygen -q -t ed25519 -b 4096 -P "" -f ~root/.ssh/id_ed25519
fi

#setting up arrays for names
declare -a names1=( $(awk -F"\t" '{ print $2 }' phase1_ip.txt*) )
declare -a names=( $(awk -F"\t" '{ print $2 }' phase*) )

#update /etc/hosts
for i in "${names[@]}"
do
	if [[ -z $(grep -ie $i /etc/hosts) ]]
	then
		grep -hie $i phase* >> /etc/hosts
	else
		sed -r -i.$i -e '/'"$i"'/c '"$(grep -hie $i phase*)" /etc/hosts
	fi
done

#ssh connections to other nodes by pubkey offering
for i in "${names1[@]}"
do
	if [[ -z $(grep -ie $i ~root/.ssh/known_hosts) ]]
	then
		ssh-copy-id root@$i
	fi
done

#update ~root/.ssh/config
printf "%b" "Host *\n" "\tPubkeyAuthentication yes\n" "\tIdentityFile ~/.ssh/id_ed25519\n" "\tServerAliveInterval 30\n" "\tServerAliveCountMax 10\n" "\tForwardX11 yes\n" > ~root/.ssh/config
awk -F"\t" '{ print $2 }' phase* | awk -F"." '{ print "Host",$1,"\n\tHostName",$0,"\n\tUser root" }' >> ~root/.ssh/config
printf "%b" "Host minion\n" "\tHostName jbox.cyber.lab\n" "\tUser minion\n" >> ~root/.ssh/config

#create minion user for jbox
scp -B jbox:/etc/passwd ./
if [[ -z $(grep -ie minion ./passwd) ]]
then
	ssh -t jbox "useradd -m -s /bin/bash -G wheel,root,adm,sys,users -p $(openssl passwd -crypt nada) minion"
	echo "minion	ALL=(ALL) NOPASSWD:ALL" > sudoer_minion && scp -B ./sudoer_minion jbox:/etc/sudoers.d/
	ssh -t jbox "chmod -c 0440 /etc/sudoers.d/sudoer_minion && chown -c root:root /etc/sudoers.d/sudoer_minion && visudo -c"
fi
if [[ $(ssh -t jbox "test -d ~minion/.ssh"; echo $?) == 1 ]]
then
	ssh -t jbox "mkdir -v ~minion/.ssh && chown -Rc minion:minion ~minion/.ssh"
fi
ssh-copy-id minion
if [[ $(ssh -t minion "test -f ~/.ssh/id_ed25519"; echo $?) == 1 ]]
then
	ssh -t minion 'ssh-keygen -q -t ed25519 -b 4096 -P "" -f ~/.ssh/id_ed25519'
fi

#update minion@jbox:/etc/hosts
scp -B jbox:/etc/hosts ./

for i in "${names[@]}"
do
	if [[ -z $(grep -ie $i ./hosts) ]]
	then
		grep -hie $i phase* >> ./hosts
	else
		sed -r -i.$i -e '/'"$i"'/c '"$(grep -hie $i phase*)" ./hosts
		mv -v ./hosts.$i /tmp/
	fi
done

scp -B ./hosts jbox:/etc/

#create ansibot user for each phase1 node
for i in "${names1[@]}"
do
	scp -B root@$i:/etc/passwd ./
	if [[ -z $(grep -ie ansibot ./passwd) ]]
	then
		ssh -t root@$i "useradd -m -s /bin/bash -G root,users,sys,adm,wheel -p $(openssl passwd -crypt nada) ansibot"
		echo "ansibot	ALL=(ALL) NOPASSWD:ALL" > ./sudoer_ansibot && scp -B ./sudoer_ansibot root@$i:/etc/sudoers.d/
		ssh -t root@$i "chmod -c 0440 /etc/sudoers.d/sudoer_ansibot && chown -c root:root /etc/sudoers.d/sudoer_ansibot && visudo -c"
	fi
done

#creating ssh shortcuts for minion@jbox & sysadm@Farm2
printf "%b" "\nHost *.cyber.lab\n" "PasswordAuthentication no\n" "CertificateFile ~sysadm/.ssh/id_ed25519-cert.pub\n" "IdentityFile ~sysadm/.ssh/id_ed25519\n" "ServerAliveInterval 30\n" "ServerAliveCountMax 10\n" "Host minion\n" "\tHostName jbox.cyber.lab\n" "\tUser minion\n" > ~sysadm/.ssh/config

printf "%b" "\nHost *.cyber.lab\n" "PasswordAuthentication no\n" "CertificateFile ~minion/.ssh/id_ed25519-cert.pub\n" "IdentityFile ~minion/.ssh/id_ed25519\n" "ServerAliveInterval 30\n" "ServerAliveCountMax 10\n" > ./config
awk -F"\t" '{ print $2 }' phase* | awk -F"." '{ print "Host",$1,"\n\tHostName",$0,"\n\tUser ansibot\n" }' >> ./config
scp -B ./config minion:~/.ssh/

#############################################################################################################################################################################
#setup ssh CA connections among nodes
#1. signing sysadm@Farm2 key for connection with minion
ssh-keygen -s ~root/.ssh/.CA/CA_sys -I sysadm@Farm2 -n minion -V +53w ~sysadm/.ssh/id_ed25519.pub

#2. signing CA server keys for each ssh servers
for i in "${names1[@]}"
do
	scp -B root@$i:/etc/ssh/ssh_host_ed25519_key.pub ./
	ssh-keygen -s ~root/.ssh/.CA/CA_svr -I $(echo $i | awk -F"." '{ print $1 }') -h -n $i -V +53w ssh_host_ed25519_key.pub
	scp -B ssh_host_ed25519_key-cert.pub root@$i:/etc/ssh/
done

#3. signing minion@jbox key for connection with all
scp -B minion:~/.ssh/id_ed25519.pub ./
ssh-keygen -s ~root/.ssh/.CA/CA_clnt -I minion@jbox -n ansibot -V +53w ./id_ed25519.pub
scp -B ./id_ed25519-cert.pub minion:~/.ssh/

#4. update known_hosts for sysadm
echo -e "@cert-authority *.cyber.lab $(cat ~root/.ssh/.CA/CA_svr.pub)" > ~sysadm/.ssh/known_hosts

#5. update known_hosts for minion
scp -B ~sysadm/.ssh/known_hosts minion:~/.ssh/

#6. copy CA keys to servers
for i in "${names1[@]}"
do
	scp -B ~root/.ssh/.CA/CA_clnt.pub root@$i:/etc/ssh/
done
scp -B ~root/.ssh/.CA/CA_sys.pub jbox:/etc/ssh/

#7. update sshd_config in each ssh servers
printf "%b" "Banner /etc/ssh/banner.txt\n" "HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub\n" "ClientAliveInterval 30\n" "ClientAliveCountMax 10\n" > ./sshd_mod
for i in "${names1[@]}"
do
	scp -B root@$i:/etc/ssh/sshd_config ./
	declare -a sshd=( $( awk -F" " '{ print $1 }' ./sshd_mod ) )
	for v in "${sshd[@]}"
	do
		if [[ -z $(grep -ie $v ./sshd_config) ]]
		then
			grep -ie $v ./sshd_mod >> ./sshd_config
		else
			sed -r -i.$v -e '/'"$v"'/c '"$(grep -ie $v ./sshd_mod)" ./sshd_config
			mv -v ./sshd_config.$v /tmp/
		fi
	done
	if [[ -z $( grep -ie ansibot ./sshd_config ) ]]
	then
		printf "%b" "\nMatch User ansibot\n" "\tTrustedUserCAKeys /etc/ssh/CA_clnt.pub\n" >> ./sshd_config
	else
		sed -r -i.ansibot -e '/ansibot/,+1{/TrustedUserCAKeys/d};/ansibot/a \\tTrustedUserCAKeys /etc/ssh/CA_clnt.pub\n' ./sshd_config
		mv -v ./sshd_config.ansibot /tmp/
	fi
	sed -r -i.$i -e '/rsa/s/^HostKey/#HostKey/' -e '/ecdsa/s/^HostKey/#HostKey/' -e '/PasswordAuthentication/s/yes/no/g' -e '/PubkeyAuthentication/s/^#//' ./sshd_config && mv -v ./sshd_config.$i /tmp/
	printf "%b" "\n\n\n\nWelcome to $i!\n" > banner.txt
	scp -B ./sshd_config ./banner.txt root@$i:/etc/ssh/
done
scp -B jbox:/etc/ssh/sshd_config ./
if [[ -z $(grep -ie minion ./sshd_config) ]]
then
	printf "%b" "Match User minion\n" "\tTrustedUserCAKeys /etc/ssh/CA_sys.pub\n" >> sshd_config
else
	sed -r -i.minion -e '/minion/,+1{/TrustedUserCAKeys/d};/minion/a \\tTrustedUserCAKeys /etc/ssh/CA_sys.pub\n' ./sshd_config
	mv -v ./sshd_config.minion /tmp/
fi
scp -B ./sshd_config jbox:/etc/ssh/

#8. reload sshd_config in each nodes
for i in "${names1[@]}"
do
	ssh -t root@$i "systemctl restart sshd.service"
done
#############################################################################################################################################################################

#install ansible at jbox
if [[ $(ssh -t jbox "test -f /usr/bin/ansible"; echo $?) == 1 ]]
then
	ssh -t jbox "dnf install -y epel* && sudo dnf update -y --disablerepo epel-next && sudo dnf install -y ansible --repo epel"
fi

#update ansible.cfg
scp -B ~root/ansible/ansible.cfg root@$i:/etc/ansible/

#move all playbook role structure to minion
rsync -av ~root/ansible minion:~/

#systemwide updates
ssh -t root@$i "dnf install -y epel* && dnf update -y --disablerepo epel-next"

sudo -u sysadm -i

#############################################################################################################################################################################
#############################################################################################################################################################################
