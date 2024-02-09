# Organization registry

This repository hosts the functionality around managing *organizations* and users, used
for authentication, and authorization mechanics in other functions.

## Dependencies

### MariaDB server

A MariaDB server is required. Configure via environment variables, the only required ones being

* DATABASE_HOST
* DATABASE_USERNAME
* DATABASE_PASSWORD

> WARNING: connection is unencrypted

The migrations are currently handled handled outside of the service, meaning that the Flyway
migrations needs to be run by another mechanism.