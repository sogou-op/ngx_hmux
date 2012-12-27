Name
====

ngx_hmux - Resin's hmux implementation in nginx

Synopsis
========

    http {
        hmux_temp_path /dev/shm/nginx/hmux_temp/;

        hmux_connect_timeout 2s;
        hmux_read_timeout 6s;

        upstream bk_resin {
          server resin_server1:6802;
          server resin_server2:6802;

          keepalive 20;
        }

        server {
          location /q {
            hmux_pass bk_resin;
          }
        }
    }

Directives
==========

hmux_pass
---------------
**syntax:** *hmux_pass address;*

**default:** *None*

**context:** *location, if in location*

Sets an address of the resin server. An address can be specified as a domain name or an address, and a port, for example,

     hmux_pass localhost:6802;

If a domain name resolves to several addresses, all of them will be used in a round-robin fashion. In addition, an address can be specified as a server group.

Installation
============

    wget "http://nginx.org/download/nginx-1.3.5.tar.gz"
    tar -xzvf nginx-1.3.5.tar.gz
    cd nginx-1.3.5/
    
    patch -p1 < /path/to/ngx_hmux/upstream_export.patch
    
    ./configure --prefix=/usr/local/nginx \
                --add-module=/path/to/ngx_hmux
    
    make -j2
    make install

Compatibility
=============

The following versions of Nginx should work with this module:

* **1.3.x**         (last tested: 1.3.5)
* **1.2.x**
* **1.1.x**         
* **1.0.x**         (last tested: 1.0.2)

Changes
=======

Authors
=======

- Lanshun Zhou *&lt;zls0424@gmail.com&gt;*

Copyright & License
===================

This README template is from agentzh (http://github.com/agentzh).

This module is licensed under the terms of the BSD license.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
