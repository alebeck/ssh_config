# ssh_config

Like https://github.com/kevinburke/ssh_config, but with some additional features:
 - Partial support for `Match` directive
 - Support for "+", "-" and "^" modifiers 
 - Returns correct `IdentityFiles`
 - Adds a public `MakeDefaultUserSettings` function