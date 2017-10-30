# servercow-dnshook-dehydrated

This is a hook script to be used with dehydrated and Servercow.

This script is safe to be used with `HOOK_CHAIN="yes"`.
A chained call to this script will skip the sleep time until the last record has been added to your zone. Besides that, there are no differences.

A file `scow-hook.auth` must be created in the same directory as this script. Insert your users credentials in the following format:

```
user=dns_api_user
pass=password
```

! Please create an unprivileged user @ Servercow to access the DNS API.

