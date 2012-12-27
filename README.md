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

hmux_ack_size
-------------
**syntax:** *hmux_ack_size size;*

**default:** *16k*

**context:** *http, server, location*

hmux_bind
---------
**syntax:** *hmux_bind address;*
            
**default:** *None*
            
**context:** *http, server, location*

Forces outgoing connections to a resin server to originate from the specified local IP address.

hmux_buffer_size
----------------
**syntax:** *hmux_buffer_size size;*

**default:** *4k|8k*

**context:** *http, server, location*

Sets size of the buffer used for reading the first part of a response received from the resin server. By default, the buffer size is equal to the size of one buffer set by the hmux_buffers directive. It can be made smaller however.

hmux_buffering
---------------
**syntax:** *hmux_buffering on | off;*

**default:** *on*

**context:** *http, server, location*

Enables or disables buffering of responses from the resin server.

When buffering is enabled, nginx receives a response from the resin server as soon as possible, saving it into buffers set by the hmux_buffer_size and hmux_buffers directives. If the whole response does not fit into memory, part of it can be saved to a temporary file on disk. Writes to temporary files are controlled by the hmux_max_temp_file_size and hmux_temp_file_write_size directives.

When buffering is disabled, a response is passed to a client synchronously, immediately as it is received. nginx will not try to read the whole response from the resin server. The maximum size of the data that nginx can receive from the server at a time is set by the hmux_buffer_size directive.

hmux_buffers
------------
**syntax:** *hmux_buffers number size;*

**default:** *8 4k|8k*

**context:** *http, server, location*

Sets the number and size of buffers used for reading a response from the resin server, for a single connection. By default, the buffer size is equal to one memory page. This is either 4K or 8K, depending on a platform.

hmux_busy_buffers_size
----------------------
**syntax:** *hmux_busy_buffers_size size;*
            
**default:** *8k|16k*
            
**context:** *http, server, location*

When buffering of responses from the resin server is enabled, limits the total size of buffers that can be busy sending a response to the client while the response is not yet fully read. In the mean time, the rest of the buffers can be used for reading a response and, if needed, buffering part of a response to a temporary file. By default, size is limited by two buffers set by the hmux_buffer_size and hmux_buffers directives.

hmux_connect_timeout
--------------------
**syntax:** *hmux_connect_timeout time;*
            
**default:** *60s*
            
**context:** *http, server, location*

Defines a timeout for establishing a connection with the resin server. It should be noted that this timeout cannot usually exceed 75 seconds.

hmux_flush
----------
**syntax:** *hmux_flush off | on | always;*

**default:** *on*

**context:** *http, server, location*

hmux_headers_hash_bucket_size
-----------------------------
**syntax:** *hmux_headers_hash_bucket_size size;*
            
**default:** *64*
                                          
**context:** *http, server, location*

hmux_headers_hash_max_size
--------------------------
**syntax:** *hmux_headers_hash_max_size size;*
            
**default:** *512*
                                          
**context:** *http, server, location*

hmux_hide_header
----------------
**syntax:** *hmux_hide_header field;*
            
**default:** *None*

**context:** *http, server, location*

By default, nginx does not pass the header fields "Date", "Server", "X-Pad", and "X-Accel-..." from the response of a resin server to a client. The hmux_hide_header directive sets additional fields that will not be passed. If, on the contrary, the passing of fields needs to be permitted, the hmux_pass_header directive can be used.

hmux_ignore_client_abort
------------------------
**syntax:** *hmux_ignore_client_abort on | off;*
            
**default:** *off*
            
**context:** *http, server, location*

Determines should the connection with a resin server be closed if a client closes a connection without waiting for a response.

hmux_intercept_errors
---------------------
**syntax:** *hmux_intercept_errors on | off;*
            
**default:** *off*
            
**context:** *http, server, location*

Determines whether responses with codes greater than or equal to 400 should be passed to a client or be redirected to nginx for processing using the error_page directive.

hmux_max_temp_file_size
-----------------------
**syntax:** *hmux_max_temp_file_size size;*

**default:** *1024m*

**context:** *http, server, location*

When buffering of responses from the resin server is enabled, and the whole response does not fit into memory buffers set by the hmux_buffer_size and hmux_buffers directives, part of a response can be saved to a temporary file. This directive sets the maximum size of a temporary file. The size of data written to a temporary file at a time is set by the hmux_temp_file_write_size directive.

Value of zero disables buffering of responses to temporary files.

hmux_next_upstream
------------------
**syntax:** *hmux_next_upstream error | timeout | invalid_header | http_500 | http_502 | http_503 | http_504 | http_404 | off ...;*
            
**default:** *error timeout*
            
**context:** *http, server, location*

Specifies in which cases a request should be passed to the next server:

*error*
    an error occurred while establishing a connection with the server, passing it a request, or reading the response header;
    
*timeout*
    a timeout has occurred while establishing a connection with the server, passing it a request, or reading the response header;
    
*invalid_header*
    a server returned empty or invalid response;
    
*http_500*
    a server returned a response with the code 500;
    
*http_502*
    a server returned a response with the code 502;
    
*http_503*
    a server returned a response with the code 503;
    
*http_504*
    a server returned a response with the code 504;
    
*http_404*
    a server returned a response with the code 404;
    
*off*
    disables passing a request to the next server.
    
It should be understood that passing a request to the next server is only possible if a client was not sent anything yet. That is, if an error or a timeout occurs in the middle of transferring a response, fixing this is impossible.

hmux_pass
---------------
**syntax:** *hmux_pass address;*

**default:** *None*

**context:** *location, if in location*

Sets an address of the resin server. An address can be specified as a domain name or an address, and a port, for example,

     hmux_pass localhost:6802;

If a domain name resolves to several addresses, all of them will be used in a round-robin fashion. In addition, an address can be specified as a server group.

hmux_pass_header
----------------
**syntax:** *hmux_pass_header field;*

**default:** *None*

**context:** *http, server, location*

Permits to pass otherwise disabled header fields from a resin server to a client.

hmux_read_timeout
-----------------
**syntax:** *hmux_read_timeout time;*

**default:** *60s*

**context:** *http, server, location*

Defines a timeout for reading a response from the resin server. A timeout is only set between two successive read operations, not for the transmission of the whole response. If a resin server does not transmit anything within this time, a connection is closed.

hmux_send_timeout
-----------------
**syntax:** *hmux_send_timeout time;*
            
**default:** *60s*
            
**context:** *http, server, location*

Sets a timeout for transmitting a request to the resin server. A timeout is only set between two successive write operations, not for the transmission of the whole request. If a resin server does not receive anything within this time, a connection is closed.

hmux_set_header
---------------
**syntax:** *hmux_set_header field value;*
            
**default:** *hmux_set_header SCRIPT_URI $hmux_request_uri;*
             *hmux_set_header SCRIPT_URL $scheme://$host$hmux_server_port$hmux_request_uri;*
            
**context:** *http, server, location*

Allows to redefine or append fields to the request header passed to the resin server. A value can contain text, variables, and their combination. These directives are inherited from the previous level if and only if there are no hmux_set_header directives defined on the current level. By default, only two fields are redefined:

    hmux_set_header SCRIPT_URI $hmux_request_uri;*
    hmux_set_header SCRIPT_URL $scheme://$host$hmux_server_port$hmux_request_uri;*

hmux_temp_file_write_size
-------------------------
**syntax:** *hmux_temp_file_write_size size;*

**default:** *8k|16k*

**context:** *http, server, location*

Limits the size of data written to a temporary file at a time, when buffering of responses from the resin server to temporary files is enabled. By default, size is limited by two buffers set by the hmux_buffer_size and hmux_buffers directives. The maximum size of a temporary file is set by the hmux_max_temp_file_size directive.

hmux_temp_path
--------------
**syntax:** *hmux_temp_path path [level1 [level2 [level3]]];* 

**default:** *hmux_temp*

**context:** *http, server, location*

Defines a directory for storing temporary files with data received from resin servers. Up to three-level subdirectory hierarchy can be used underneath the specified directory. 

Embedded Variables
==================

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

I borrowed a lot of descriptions from the documentation of Nginx. This part is copyrighted by the Nginx Team. (http://nginx.org/en/docs/http/ngx_http_proxy_module.html)

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
