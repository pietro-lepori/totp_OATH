Script to store encrypted OATH secrets, in a file, and generate totp tokens.

Written for personal use on the 11th of June 2023, used since.

I don't think it is possible to recover the secrets from the file without the correct password but, once unlocked, the secrets could be available to other users and programs on the same machine.
Note that the entries' names are not encrypted.

# Requirements:
`oathtool`
`openssl`
`python` >= 3.10
Tested only on Alpine Linux and AlmaLinux, ymmv.

# Use with a Microsoft account (i.e. unimi email, since 2023)
Register secret on first access:
```
MS    > I want to use a different authenticator app
MS    > Next
MS    > Can't scan image?
(copy the secret)
shell > python3 oath.py keychain.txt
oath  > add32 Mail unimi
(enter secret and choose password)
oath  > totp 1
(enter password and copy token)
MS    > ... (confirm token)
```

# How to recover the secrets
Don't. Generate a different secret for each authenticator.
E+*g/+CHdE?m'B,FD5Z2+EVNEDdda$FDl)6
