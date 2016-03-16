# GCS Proxy

## Proxy urls:

To access any GCS url, replace the gs:// in the url with
http://server.com/proxy/ where server.com is the domain name (and
possibly port) where this application is installed.

Example:

    gs://world-fishing-827/pelagos/data/tiles/test-grid-temporal/spec.json

is accessible from

    http://server.com/proxy/world-fishing-827/pelagos/data/tiles/test-grid-temporal/spec.json

## Authorization

The authorization system in GCS proxy is built on three concepts:
Users, groups and access control lists (ACLs). Each user can belong to
multiple groups, and each group has an associated access control list.

An ACL is simply a list of paths, each associated with a flag that can
be either Allow or Deny.

A file path to proxy is granted if, among all ACL entry paths that are
prefixes to this path, the longest one has its flag set to Allow, in
any group that the user is a member of.

## Administration

The administration user interface, where users, groups and ACLs can be configured, is accessible from

    http://sever.com/admin

To access it, you have to be an administrator of the google project of the GAE instance that GCS-proxy is running on.
