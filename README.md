# HTB-Password_Attacks

## Table of Contents
1. [Password Cracking Techniques](#password-cracking-techniques)
    1. [Introduction to Password Cracking](#introduction-to-password-cracking)
    2. [Introduction to John The Ripper](#introduction-to-john-the-ripper)
    3. [Introduction to Hashcat](#introduction-to-hashcat)
    4. [Writing Custom Wordlists and Rules](#writing-custom-wordlists-and-rules)
    5. [Cracking Protected Files](#cracking-protected-files)
    6. [Cracking Protected Archives](#cracking-protected-archives)

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