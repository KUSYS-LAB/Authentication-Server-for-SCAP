# Authentication-Server-for-SCAP
The Authentication Server for SCAP project.

The project is under development with the support of KHIDI(https://www.khidi.or.kr/kps).
All description you need will be added soon.

## Set up
Currently we use the mariadb for dbms, so you have to install the mariadb first.
If you have installed the mariadb, you have to create the db and the account.
By default, we use the following db and account. If you want to other account and db, you have to modify `application.properties`.
```
DB: as_web
ID: as_web_admin
PW: as_web_admin
```
Next, the table schemas should be defined. we provide the current version of table scheme(`scheme.sql`) and data(`data.sql`) which should be inserted before staring the our project.
Execute the sql scripts by your self.

This project has the interaction with ca. So the address of the ca should be set up at `ca.domain` in `application.properties`.
Now, all set up.
