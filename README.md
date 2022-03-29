# Redate Leaf Remediation Tool

This is tool Let's Encrypt will use to
remediate the [Oak 2022: Incorrect Entry Timestamps
Incident](https://groups.google.com/a/chromium.org/g/ct-policy/c/sdPvvZSp7Rw/m/6UqU1MN8AQAJ)
by modifying the database for Oak 2022. It consumes a CSV as input that contains
a list of entry indexes, along with the leaf data fetched from Google's mirror
of Oak. It reads data from the DB, checks some assumptions about the structure
of the data and the corruption, then updates the stored timestamp inside the
MerkleTreeLeaf structures.

# Running Unittest

The unittest requires a MySQL or MariaDB backend. The easiest way to run it is:

```
docker network create mysqlnet --internal --subnet 10.44.44.0/24
export MYSQL_ROOT_PASSWORD="$(openssl rand -hex 20)"
export DB="root:${MYSQL_ROOT_PASSWORD}@tcp(10.44.44.44:3306)/trill"
docker run --network mysqlnet --ip 10.44.44.44 -e MYSQL_ROOT_PASSWORD --detach --name mariadb mariadb
# Wait about 10 seconds
mysql -u root --password="${MYSQL_ROOT_PASSWORD}" -h 10.44.44.44 -e 'CREATE DATABASE trill;'
go test ./
```
