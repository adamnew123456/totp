# What is this?

This is a command-line utility for generating TOTP and HOTP keys, of
the kind used for 2FA with applications like Google Authenticator.

The defaults are aligned with what the Google Authenticator currently
uses, so you should be able to use its secrets with no other
configuration.

# Building

Run msbuild on the solution. The project file is in the new .NET Core
format, so .NET Core is probably required, although the default target
is .NET 4.

# Running

You can run the program in either TOTP mode or HOTP mode.

## TOTP

This used for most 2FA keys found in the wild today. If your key
didn't come with an explicit counter, then it is probably using
TOTP.

    totp -t -s SECRET [-a ALGORITHM] [-d DIGITS] [-p PERIOD]
  
The `-t` argument is required (it signals the use of TOTP), as is the
`-s` argument which contains the secret. The other options are as
follows:

- `-a` The algorithm used to compute TOTP's internal HMAC. `sha1` by default,
  although `sha256` and `sha512` can also be provided.
- `-d` How many digits long the output code is. 6 by default.
- `-p` How many seconds the code is valid. 30 by default.

## HOTP

    totp -h -c COUNTER -s SECRET [-a ALGORITHM] [-d DIGITS]
  
Most arguments are the same as with TOTP, with the exception of `-h`
(it signals the use of HOTP), and the required `-c` argument which
contains the current value of the HOTP counter.
