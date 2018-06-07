# TFTP: Client/Server

| Project    | Embeddable Non-blocking TFTP Client/Server Library |
| ---------- | -------------------------------------------------- |
| Author     | Richard James Howe                                 |
| Copyright  | 2017-2018 Richard James Howe                       |
| License    | MIT                                                |
| Email      | howe.r.j.89@gmail.com                              |
| Repository | <https://github.com/howerj/tftp>                   |

A [TFTP][] Client/Server, as specified in [RFC 1350][].

This is a work in progress, and is not usable at the moment.

## Goals

* Portable

The functionality required by the TFTP logic should be provided as a bunch of
function pointers which can be given to an instance of the TFTP server or
client. This includes socket and file access functionality. This is to allow
the program to be ported fairly easily to different platforms and perhaps even
embedded ones.

* Non-blocking

The state machine that drives the TFTP client/server should be non-blocking,
it will not wait around for data to arrive but instead inform the user that
there is nothing to do at the moment.

* Easy-to-use

The API should be well documented and the program easy to use.

## Non-Goals

These are **NOT** goals of the project:

* Secure

Any security, like preventing arbitrary directory traversal, should be done by
the programmer in the file-opening callback - preferably by white listing the
files that can be read, and written to.

* Runnable as an **inetd** service

This is project is meant to provide a simple client and server that someone
could use for testing TFTP, not for anything else.

* Implement the Optional Extensions

They're optional!

## To Do

* [x] Implement the client
  * [x] Receive file
  * [x] Send file
* [x] Implement the server
  * [x] Receive file
  * [x] Send file
* [ ] Ensure compliance and battle test it
  * [ ] Make a small test suite
  * [x] Lint everything
  * [ ] Fuzzy it with AFL <http://lcamtuf.coredump.cx/afl/>
  * [ ] Options for introducing errors
  * [ ] Test on remote targets
  * [ ] Test multiple connections
* [ ] Port to Windows
* [ ] Turn into library
* [x] Man pages

[MIT License]: LICENSE
[TFTP]: https://en.wikipedia.org/wiki/Trivial_File_Transfer_Protocol
[RFC 1350]: https://tools.ietf.org/html/rfc1350
