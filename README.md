# oneliners
Useful one line Bash/Python/etc commands


bash loop
```bash
while read in; do echo $in; done < file.txt # for each line in file
```


parse ldapdomaindump output
```bash
# domain_users.grep
cut -d $'\t' -f 3,9 domain_users.grep # extract sAMAccountName  userAccountControl
cut -d $'\t' -f 3,9 domain_users.grep | grep 'DONT_EXPIRE_PASSWD' # check if account is admin, if so - report
cut -d $'\t' -f 3,9 domain_users.grep | grep 'PASSWD_NOTREQD' | grep -v 'ACCOUNT_DISABLED' | awk '{print $1}' # spray empty password

# domain_computers.grep
cut -d $'\t' -f 2,4,5,6 domain_computers.grep # extract sAMAccountName  operatingSystem operatingSystemServicePack      operatingSystemVersion
cut -d $'\t' -f 2,4,5,6 domain_computers.grep | grep -e 2008 -e 2012 # grep older windows server

# domain_policy.grep
cut -d $'\t' -f 7,8,9 domain_policy.grep # extract minPwdLength    pwdHistoryLength        pwdProperties
cut -d $'\t' -f 10 domain_policy.grep # get ms-DS-MachineAccountQuota
```
parse crackmapexec output
```bash
# smb
cat cme_smb_out | grep 'signing:False' | awk '{print $2,$4}' # get hosts and IPs without SMB signing
cat cme_smb_out | grep 'SMBv1:True' | awk '{print $2,$4}' # get hosts and IPs with SMBv1 enabled

# rdp
cat cme_rdp_sample | grep 'nla:False' | awk '{print $2,$4}' # get hosts and IPs without NLA 

# ldap
```
parse testssl.sh output
```bash
# outdated SSL/TLS versions
cat output.json | jq -c '.[] | select(.severity != "INFO")' # works partially, filters only INFO-level
cat testssl.sh_p443-20231108-1930.json | jq -c '.[] | select(.severity != "INFO") | select(.severity != "OK")' # works better, filters INFO and OK
cat testssl.sh_p443-20231108-1930.json | jq -c '.[] | select(.severity != "INFO") | select(.severity != "OK") | select (.id == "TLS1") | .ip' # extract outdated TLS (here TLS1), replace with SSLv3, TLS1, TLS1_1

# weak TLS ciphers in use

```
parse nmap ssh-audit script output

```bash
# nmap file to host and weak encryption algorithms, 
# nmap -p 22 -oA ssh$IP --script ssh2-enum-algos $IP

cat ssh.nmap | grep -i -e 'Nmap scan report for' -e 'arcfour128' -e 'arcfour256' -e '3des-cbc' -e 'aes128-cbc' -e 'aes192-cbc' -e 'aes256-cbc' -e 'blowfish-cbc' -e 'cast128-cbc' # grep weak ciphers per ip
```

parse AndroidManifest.xml for BROWSABLE activities
```bash
# 
xmllint --xpath "//category[@*='android.intent.category.BROWSABLE']/parent::node()/parent::node()/@*[local-name()='name']" AndroidManifest.xml
```

find providers where either `readPermission` or `writePermission` is set
```bash
for app in $(find . -maxdepth 3 -name "AndroidManifest.xml"); do xmllint $app | tr '[:upper:]' '[:lower:]' | grep 'exported="true"'|awk 'xor(/readpermission/,/writepermission/)'| grep --color -e "readpermission" -e "writepermission" && echo "===$app===" ; done
```

semi-useful bash functions to get `base.apk` for packages
```bash
# add to /etc/profile or .bashrc
adb_pull (){
    adb pull $(adb shell pm path "$1" | head -n1 | awk -F: '{print $2}') "$1.apk"
}

adb_pull_all (){
    for app in $(adb shell pm list packages | awk -F: '{print $2}'); do adb_pull $app; done
}
```
