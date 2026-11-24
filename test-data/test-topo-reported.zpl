# Topology where some link ends have no substrate address (the node reports its own, zl-zipline#226).
# TODO: Extend this with link attributes once we have syntax.


define WebService as a service with user.uid:1234.

allow color:green users to access content:green services.
allow color:brown users to access content:brown services.
allow color:red users to access WebService.

define FooService as a service with user.uid:4567.
allow color:green users to access content:green FooServices.
allow color:purple users to access FooServices.
