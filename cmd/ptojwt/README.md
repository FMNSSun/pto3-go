## Usage

```
Usage of ./ptojwt:
  -action string
    	gen[erate] or val[idate] (default "gen")
  -permissions string
    	Permissions (only valid for generate, semi-colon separated)
  -secret string
    	Secret (for HMAC)
  -sub string
    	Subject (sub claim for JWT token)
  -token string
    	JWT Token
```

If `token` or `secret` are empty you'll be promted to enter them on stdin. The secret must be base64 encoded.

## Examples

```
$ ./ptojwt -sub="3423423789" -permissions=read
Enter Secret (b64): dWh1Cg==
Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZWFkIjp0cnVlLCJzdWIiOiIzNDIzNDIzNzg5In0.sUxm_fAJC9_WH2HWjwVFyBxOEbf8V5n8q6Ck_dMR1JE

$ ./ptojwt -action=val
Enter Secret (b64): dWh1Cg==
Enter Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyZWFkIjp0cnVlLCJzdWIiOiIzNDIzNDIzNzg5In0.sUxm_fAJC9_WH2HWjwVFyBxOEbf8V5n8q6Ck_dMR1JE
2018/06/21 13:41:51 Token is valid!
2018/06/21 13:41:51 map[read:true sub:3423423789]
```
