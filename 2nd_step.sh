#! /usr/bin/env bash

#stop the script if there is an error
set -e

#copy root ssh pubkey to VMs
declare -a names2=( $(awk -F"\t" '{ print $2 }' phase2_ip.txt) )
for i in "${names2[@]}"
do ssh-copy-id root@$i
done

#copy & sign ssh server keys from VMs + copy ssh host certification
for i in "${names2[@]}"
do
	scp -B root@$i:/etc/ssh/ssh_host_ed25519_key.pub ./
	ssh-keygen -s ~root/.ssh/.CA/CA_svr -I $(echo $i | awk -F"." '{ print $1 }') -h -n $i -V +53w ssh_host_ed25519_key.pub
	scp -B ./ssh_host_ed25519_key-cert.pub root@$i:/etc/ssh/
done

#update sshd_config in each VM
for i in "${names2[@]}"
do
	scp -B root@$i:/etc/ssh/sshd_config ./
	sed -r -i.HostKey -e '/rsa/s/^HostKey/#HostKey/' -e '/ecdsa/s/^HostKey/#HostKey/' ./sshd_config
	sed -r -i.banner -e '/PasswordAuthentication/s/yes/no/' -e '/Banner/cBanner /etc/ssh/banner.txt' ./sshd_config
	sed -r -i.client -e '/ClientAliveInterval/cClientAliveInterval 30' -e '/ClientAliveCountMax/cClientAliveCountMax 10' ./sshd_config
	if [[ -z $(grep -ie HostCertificate ./sshd_config) ]]
	then
		printf "%b" "\nHostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub\n" >> ./sshd_config
	else
		sed -r -i.hostcert -e '/HostCertificate/cHostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub' ./sshd_config
	fi
	if [[ -z $(grep -ie TrustedUserCAKeys ./sshd_config) ]]
	then
		printf "%b" "\nTrustedUserCAKeys /etc/ssh/CA_clnt.pub\n" >> ./sshd_config
	else
		sed -r -i.trusted -e '/TrustedUserCAKeys/cTrustedUserCAKeys /etc/ssh/CA_clnt.pub' ./sshd_config
	fi
	printf "%b" "\n\n\n\nWelcome to $i!\n" > ./banner.txt
	scp -B ./banner.txt ./sshd_config ~root/.ssh/.CA/CA_clnt.pub root@$i:/etc/ssh/
	ssh -t root@$i "systemctl restart sshd.service"
done

# install X11 forwarding for sshd
for i in "${names2[@]}"
do
	ssh -t root@$i "dnf install -y xorg-x11-xauth"
done

#set default route
for i in $(awk -F"\t" '{ print $2 }' phase2_ip.txt)
do
	ssh -Xt root@$i "ip route change default via 192.168.0.1 proto dhcp src $(grep -ie $i phase2_ip.txt | awk -F"\t" '{ print $1 }') metric 100"
done
