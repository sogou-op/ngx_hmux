#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HMUX_DEFAULT_PORT       6802
#define NGX_HMUX_CHANNEL_LEN        3

#define NGX_HMUX_STRING_LEN(a)      (3 + (a))
#define NGX_HMUX_WRITE_CMD(p, cmd, len)                           \
  *(p)++ = cmd;                                                   \
  *(p) ++ = ((len) >> 8) & 0xFF;                                  \
  *(p) ++ = (len) & 0xFF

#define NGX_HMUX_WRITE_STR(p, cmd, str)                           \
  NGX_HMUX_WRITE_CMD(p, cmd, (str).len);                          \
  p = ngx_copy(p, (str).data, (str).len)

#define NGX_HMUX_IS_HEADER(header, test)                          \
    (header.key.len == sizeof(test) - 1 &&                        \
    ngx_strncmp(header.lowcase_key, test, sizeof(test) - 1) == 0)

#define HMUX_CHANNEL        'C' 
#define HMUX_ACK            'A'
#define HMUX_ERROR          'E'
#define HMUX_YIELD          'Y'
#define HMUX_QUIT           'Q'
#define HMUX_EXIT           'X'
  
#define HMUX_DATA           'D'
#define HMUX_URL            'U'
#define HMUX_STRING         'S'
#define HMUX_HEADER         'H'
#define HMUX_META_HEADER    'M'
#define HMUX_PROTOCOL       'P'

#define CSE_NULL            '?'
#define CSE_PATH_INFO       'b'
#define CSE_PROTOCOL        'c'
#define CSE_REMOTE_USER     'd'
#define CSE_QUERY_STRING    'e'
#define CSE_SERVER_PORT     'g'
#define CSE_REMOTE_HOST     'h'
#define CSE_REMOTE_ADDR     'i'
#define CSE_REMOTE_PORT     'j'
#define CSE_REAL_PATH       'k'
#define CSE_AUTH_TYPE       'n'
#define CSE_URI             'o'
#define CSE_CONTENT_LENGTH  'p'
#define CSE_CONTENT_TYPE    'q'
#define CSE_IS_SECURE       'r'
#define CSE_SESSION_GROUP   's'
#define CSE_CLIENT_CERT     't'
#define CSE_SERVER_TYPE     'u'

#define HMUX_METHOD         'm'
#define HMUX_FLUSH          'f'
#define HMUX_SERVER_NAME    'v'
#define HMUX_STATUS         's'
#define HMUX_CLUSTER        'c'
#define HMUX_SRUN           's'
#define HMUX_SRUN_BACKUP    'b'
#define HMUX_SRUN_SSL       'e'
#define HMUX_UNAVAILABLE    'u'
#define HMUX_WEB_APP_UNAVAILABLE 'U'

#define CSE_HEADER          'H'
#define CSE_VALUE           'V'

#define CSE_STATUS          'S'
#define CSE_SEND_HEADER     'G'

#define CSE_PING            'P'
#define CSE_QUERY           'Q'

#define CSE_ACK             'A'
#define CSE_DATA            'D'
#define CSE_FLUSH           'F'
#define CSE_KEEPALIVE       'K'
#define CSE_END             'Z'
#define CSE_CLOSE           'X'

typedef struct {
  ngx_http_upstream_conf_t        upstream;

  ngx_http_complex_value_t        *complex_upstream;

  size_t                          send_buffer_size;
} ngx_http_hmux_loc_conf_t;

typedef struct {
  ngx_str_t                       key;
  ngx_str_t                       value;

  ngx_uint_t                      body_chunk_size;

  unsigned                        key_done:1;

  ngx_uint_t                      cmd_state;
  ngx_uint_t                      cmd_len;
  u_char                          cmd;
} ngx_http_hmux_ctx_t;

static void *ngx_http_hmux_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_hmux_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_hmux_pass(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);

static ngx_int_t ngx_http_hmux_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_hmux_eval(ngx_http_request_t *r,
    ngx_http_hmux_loc_conf_t *hlcf);

static ngx_int_t ngx_http_hmux_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_hmux_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_hmux_process_header(ngx_http_request_t *r);
static void ngx_http_hmux_abort_request(ngx_http_request_t *r);
static void ngx_http_hmux_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static ngx_int_t ngx_http_hmux_chunked_filter(ngx_event_pipe_t *p,
    ngx_buf_t *buf);
static ngx_int_t ngx_http_hmux_input_filter_init(void *data);
static ngx_int_t ngx_http_hmux_non_buffered_chunked_filter(void *data,
        ssize_t bytes);

static ngx_command_t ngx_http_hmux_commands[] = {

  { ngx_string("hmux_pass"),
    NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
    ngx_http_hmux_pass,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },

  { ngx_string("hmux_pass_header"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_array_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, upstream.pass_headers),
    NULL },

  { ngx_string("hmux_hide_header"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_array_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, upstream.hide_headers),
    NULL },

  { ngx_string("hmux_buffers"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
    ngx_conf_set_bufs_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, upstream.bufs),
    NULL },


  { ngx_string("hmux_buffering"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, upstream.buffering),
    NULL },

  { ngx_string("hmux_buffer_size"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_size_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, upstream.buffer_size),
    NULL },

  ngx_null_command
};

static ngx_http_module_t ngx_http_hmux_module_ctx = {
  NULL,                                     /* preconfiguration */
  NULL,                                     /* postconfiguration */

  NULL,                                     /* create main configuration */
  NULL,                                     /* init main configuration */

  NULL,                                     /* create server configuration */
  NULL,                                     /* merge server configuration */

  ngx_http_hmux_create_loc_conf,            /* create location configration */
  ngx_http_hmux_merge_loc_conf              /* merge location configration */
};

ngx_module_t ngx_http_hmux_module = {
  NGX_MODULE_V1,
  &ngx_http_hmux_module_ctx,                 /* module context */
  ngx_http_hmux_commands,                    /* module directives */
  NGX_HTTP_MODULE,                          /* module type */
  NULL,                                     /* init master */
  NULL,                                     /* init module */
  NULL,                                     /* init process */
  NULL,                                     /* init thread */
  NULL,                                     /* exit thread */
  NULL,                                     /* exit process */
  NULL,                                     /* exit master */
  NGX_MODULE_V1_PADDING
};

static ngx_str_t  ngx_http_hmux_hide_headers[] = {
  ngx_string("Status"),
  ngx_string("X-Accel-Expires"),
  ngx_string("X-Accel-Redirect"),
  ngx_string("X-Accel-Limit-Rate"),
  ngx_string("X-Accel-Buffering"),
  ngx_string("X-Accel-Charset"),
  ngx_null_string
};

static ngx_int_t ngx_http_hmux_handler(ngx_http_request_t *r){
  ngx_int_t                 rc;
  ngx_http_upstream_t       *u;
  ngx_http_hmux_ctx_t       *ctx;
  ngx_http_hmux_loc_conf_t  *hlcf;
  
  if (ngx_http_upstream_create(r) != NGX_OK) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_hmux_ctx_t));
  if (ctx == NULL) {
    return NGX_ERROR;
  }

  ngx_http_set_ctx(r, ctx, ngx_http_hmux_module);

  hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hmux_module);

  if (hlcf->complex_upstream != NULL){
    if (ngx_http_hmux_eval(r, hlcf) != NGX_OK){
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
  }

  u = r->upstream;

  ngx_str_set(&u->schema, "hmux://");
  u->output.tag = (ngx_buf_tag_t) &ngx_http_hmux_module;

  u->conf = &hlcf->upstream;

  u->create_request = ngx_http_hmux_create_request;
  u->reinit_request = ngx_http_hmux_reinit_request;
  u->process_header = ngx_http_hmux_process_header;
  u->abort_request = ngx_http_hmux_abort_request;
  u->finalize_request = ngx_http_hmux_finalize_request;

  r->state = 0;

  u->buffering = hlcf->upstream.buffering;

  u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
  if (u->pipe == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  u->pipe->input_filter = ngx_http_hmux_chunked_filter;
  u->pipe->input_ctx = r;

  u->input_filter_init = ngx_http_hmux_input_filter_init;
  u->input_filter = ngx_http_hmux_non_buffered_chunked_filter;
  u->input_filter_ctx = r;

  rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

  if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
    return rc;
  }

  return NGX_DONE;
}

static ngx_int_t
ngx_http_hmux_eval(ngx_http_request_t *r, ngx_http_hmux_loc_conf_t *hlcf)
{
  ngx_str_t             hmux;
  ngx_url_t             url;
  ngx_http_upstream_t  *u;

  if (ngx_http_complex_value(r, hlcf->complex_upstream, &hmux) != NGX_OK)
  {
    return NGX_ERROR;
  }

  if (hmux.len == 0){
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        "empty hmux server for \"%V\"", &hlcf->complex_upstream->value);
    return NGX_ERROR;
  }

  u = r->upstream;

  ngx_memzero(&url, sizeof(ngx_url_t));

  url.url = hmux;
  url.default_port = NGX_HMUX_DEFAULT_PORT;
  url.no_resolve = 1;

  if (hmux.len > 7
      && ngx_strncasecmp(hmux.data, (u_char *) "hmux://", 7) == 0)
  {
    url.url.data += 7;
    url.url.len -= 7;
  }

  if (ngx_parse_url(r->pool, &url) != NGX_OK) {
    if (url.err) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
          "%s in upstream \"%V\"", url.err, &url.url);
    }

    return NGX_ERROR;
  }

  u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
  if (u->resolved == NULL) {
    return NGX_ERROR;
  }

  if (url.addrs && url.addrs[0].sockaddr) {
    u->resolved->sockaddr = url.addrs[0].sockaddr;
    u->resolved->socklen = url.addrs[0].socklen;
    u->resolved->naddrs = 1;
    u->resolved->host = url.addrs[0].name;

  } else {
    u->resolved->host = url.host;
    u->resolved->port = (in_port_t) (url.no_port ? 
        NGX_HMUX_DEFAULT_PORT : url.port);
    u->resolved->no_port = url.no_port;
  }

  return NGX_OK;
}

static ngx_int_t ngx_http_hmux_create_request(ngx_http_request_t *r) {
  size_t                        len, uri_len;
  uintptr_t                     escape;
  ngx_uint_t                    i, unparsed_uri;

  ngx_list_part_t               *part;
  ngx_table_elt_t               *header;

  ngx_buf_t                     *b;
  ngx_chain_t                   *cl, *body;
  ngx_http_upstream_t           *u;

  u = r->upstream;

  len = NGX_HMUX_CHANNEL_LEN + 1;

  // env
  escape = 0;
  unparsed_uri = 0;

  if (r->valid_unparsed_uri && r == r->main)
  {
    unparsed_uri = 1;
  } else {
    if (r->quoted_uri || r->space_in_uri || r->internal) {
      escape = 2 * ngx_escape_uri(NULL, r->uri.data, r->uri.len,
          NGX_ESCAPE_URI);
    }
  }

  uri_len = r->uri.len + escape;

  if (uri_len == 0) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        "zero length URI to hmux");
    return NGX_ERROR;
  }
  
  len += NGX_HMUX_STRING_LEN(uri_len) +
    NGX_HMUX_STRING_LEN(r->method_name.len) +
    NGX_HMUX_STRING_LEN(r->http_protocol.len);

  if (r->args.len) {
    len += NGX_HMUX_STRING_LEN(r->args.len);
  }

  len += NGX_HMUX_STRING_LEN(r->headers_in.server.len) +
    NGX_HMUX_STRING_LEN(sizeof("65535") - 1) +
    NGX_HMUX_STRING_LEN(r->connection->addr_text.len) +
    NGX_HMUX_STRING_LEN(r->connection->addr_text.len) +
    NGX_HMUX_STRING_LEN(sizeof("65535") - 1);

  if (ngx_http_auth_basic_user(r) != NGX_DECLINED) {
    len += NGX_HMUX_STRING_LEN(r->headers_in.user.len) + 
      NGX_HMUX_STRING_LEN(sizeof("Basic") - 1);
  }

  // headers
  part = &r->headers_in.headers.part;
  header = part->elts;

  for (i = 0; /* void */; i++) {

    if (i >= part->nelts) {
      if (part->next == NULL) {
        break;
      }

      part = part->next;
      header = part->elts;
      i = 0;
    }

    len += NGX_HMUX_STRING_LEN(header[i].key.len) + 
      + NGX_HMUX_STRING_LEN(header[i].value.len);
  }

  // added_headers
  // Empty

  b = ngx_create_temp_buf(r->pool, len);
  if (b == NULL) {
    return NGX_ERROR;
  }

  cl = ngx_alloc_chain_link(r->pool);
  if (cl == NULL) {
    return NGX_ERROR;
  }

  cl->buf = b;

  b->last = ngx_cpymem(b->last, "C\x00\x01", 3);

  NGX_HMUX_WRITE_CMD(b->last, HMUX_URL, uri_len);

  u->uri.data = b->last;

  if (unparsed_uri){
    b->last = ngx_copy(b->last, r->uri.data, r->uri.len);
  } else {
    if (escape) {
      ngx_escape_uri(b->last, r->uri.data, r->uri.len, NGX_ESCAPE_URI);
      b->last += uri_len;
    } else {
      b->last = ngx_copy(b->last, r->uri.data, r->uri.len);
    }
  }

  u->uri.len = b->last - u->uri.data;

  NGX_HMUX_WRITE_STR(b->last, HMUX_METHOD, r->method_name);
  NGX_HMUX_WRITE_STR(b->last, CSE_PROTOCOL, r->http_protocol);

  if (r->args.len) {
    NGX_HMUX_WRITE_STR(b->last, CSE_QUERY_STRING, r->args);
  }

  NGX_HMUX_WRITE_STR(b->last, HMUX_SERVER_NAME, r->headers_in.server);
  // server port

  NGX_HMUX_WRITE_STR(b->last, CSE_REMOTE_HOST, r->connection->addr_text);
  NGX_HMUX_WRITE_STR(b->last, CSE_REMOTE_ADDR, r->connection->addr_text);
  // remote port
  
  if (r->headers_in.user.len){
    NGX_HMUX_WRITE_STR(b->last, CSE_REMOTE_USER, r->headers_in.user);
    NGX_HMUX_WRITE_CMD(b->last, CSE_AUTH_TYPE, sizeof("Basic") - 1);
    b->last = ngx_cpymem(b->last, "Basic", sizeof("Basic") - 1);
  }

  // headers
  part = &r->headers_in.headers.part;
  header = part->elts;

  for (i = 0; /* void */; i++) {

    if (i >= part->nelts) {
      if (part->next == NULL) {
        break;
      }

      part = part->next;
      header = part->elts;
      i = 0;
    }

    if (NGX_HMUX_IS_HEADER(header[i], "content-type")) {
      NGX_HMUX_WRITE_STR(b->last, CSE_CONTENT_TYPE, header[i].value);
      continue;
    }

    if (NGX_HMUX_IS_HEADER(header[i], "content-length")) {
      NGX_HMUX_WRITE_STR(b->last, CSE_CONTENT_LENGTH, header[i].value);
      continue;
    }

    if (NGX_HMUX_IS_HEADER(header[i], "expect")) {
      continue;
    }

    NGX_HMUX_WRITE_STR(b->last, HMUX_HEADER, header[i].key);
    NGX_HMUX_WRITE_STR(b->last, HMUX_STRING, header[i].value);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "http hmux header: \"%V: %V\"",
        &header[i].key, &header[i].value);
  }

  body = u->request_bufs;
  u->request_bufs = cl;

#if 0
  send_body_size = 0;

  while (body) {
    b = ngx_alloc_buf(r->pool);
    if (b == NULL) {
      return NGX_ERROR;
    }

    ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));

    cl->next = ngx_alloc_chain_link(r->pool);
    if (cl->next == NULL) {
      return NGX_ERROR;
    }

    cl = cl->next;
    cl->buf = b;

    body = body->next;
  }
#endif

  *b->last ++ = HMUX_QUIT;

  b->flush = 1;
  cl->next = NULL;

  return NGX_OK;
}

static ngx_int_t ngx_http_hmux_reinit_request(ngx_http_request_t *r) {
  ngx_http_hmux_ctx_t     *ctx;

  ctx = ngx_http_get_module_ctx(r, ngx_http_hmux_module);

  if (ctx == NULL) {
    return NGX_OK;
  }

  ctx->key_done = 0;
  ctx->cmd_state = 0;
  ctx->body_chunk_size = 0;

  return NGX_OK;
}

static ngx_int_t ngx_http_hmux_process_cmd(ngx_http_request_t *r,
    ngx_http_hmux_ctx_t *ctx, ngx_buf_t *b, ngx_uint_t allow_underscores)
{
  u_char                ch, *p;
  enum {
    sw_start = 0,
    sw_len_hi,
    sw_len_lo,
    sw_read_len,
    sw_string_start,
  } state;

  state = ctx->cmd_state;
  
  for (p = b->pos; p < b->last; p ++){
    ch = *p;

    switch (state){
      case sw_start:
        ctx->cmd = ch;

        switch (ch){
          default:
            if ((ch & 0x80) == 0){
              break;
            }
          case HMUX_QUIT:
          case HMUX_EXIT:
            ctx->cmd_len = 0;
            goto done;
        }

        state = sw_len_hi;
        break;

      case sw_len_hi:
        ctx->cmd_len = ch << 8;
        state = sw_len_lo;
        break;

      case sw_len_lo:
        ctx->cmd_len |= ch;

        switch (ctx->cmd){
          case HMUX_CHANNEL:
          case HMUX_FLUSH:
          case CSE_SEND_HEADER:
          case HMUX_ACK:
            goto done;

          case HMUX_DATA:
            ctx->body_chunk_size = ctx->cmd_len;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "http hmux new data chunk: %i", ctx->body_chunk_size);
            goto done;

          default:
            state = sw_read_len;
            break;
        }
        break;

      case sw_read_len:
        if (b->last - p < ctx->cmd_len){
          goto again;
        }

        if (ctx->key_done){
          ctx->value.data = p;
          ctx->value.len = ctx->cmd_len;
          p += ctx->cmd_len - 1;

          goto done;
        }

        ctx->key.data = p;
        ctx->key.len = ctx->cmd_len;
        ctx->key_done = 1;
        p += ctx->cmd_len - 1;

        switch (ctx->cmd){
          case HMUX_HEADER:
          case HMUX_META_HEADER:
            state = sw_string_start;
            break;
          default:
            goto done;
        }
        break;

      case sw_string_start:
        state = sw_len_hi;
        break;
    }
  }

again:
  b->pos = p;
  ctx->cmd_state = state;

  return NGX_AGAIN;

done:
  b->pos = p + 1;
  ctx->key_done = 0;
  ctx->cmd_state = sw_start;

  return NGX_OK;
}

static ngx_int_t ngx_http_hmux_process_header(ngx_http_request_t *r) {
  ngx_int_t                       rc, code;
  ngx_table_elt_t                 *h;
  ngx_http_upstream_t             *u;
  ngx_http_hmux_ctx_t             *ctx;
  ngx_http_upstream_header_t      *hh;
  ngx_http_upstream_main_conf_t   *umcf;

  ctx = ngx_http_get_module_ctx(r, ngx_http_hmux_module);
  if (ctx == NULL) {
    return NGX_ERROR;
  }

  umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

  u = r->upstream;

  for ( ;; ){
    rc = ngx_http_hmux_process_cmd(r, ctx, &r->upstream->buffer, 1);

    if (rc == NGX_AGAIN){
      return NGX_AGAIN;
    }

    if (rc == NGX_OK){
      switch (ctx->cmd){
        case HMUX_STATUS:
          code = ngx_atoi(ctx->key.data, 3);
          if (code == NGX_ERROR){
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "upstream sent invalid status \"%V\"",
                &ctx->key);
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
          }

          if (u->state) {
            u->state->status = code;
          }

          u->headers_in.status_n = code;

          u->headers_in.status_line.len = ctx->key.len;

          u->headers_in.status_line.data = ngx_pnalloc(r->pool, ctx->key.len);
          if (u->headers_in.status_line.data == NULL) {
            return NGX_ERROR;
          }

          ngx_memcpy(u->headers_in.status_line.data, ctx->key.data, ctx->key.len);

          ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
              "http hmux status %ui \"%V\"",
              u->headers_in.status_n, &u->headers_in.status_line);

          break;

        case HMUX_DATA:
          ngx_str_set(&ctx->key, "Transfer-Encoding");
          ngx_str_set(&ctx->value, "chunked");
          
        case HMUX_HEADER:
          h = ngx_list_push(&u->headers_in.headers);
          if (h == NULL) {
            return NGX_ERROR;
          }

          h->key.len = ctx->key.len;
          h->value.len = ctx->value.len;

          h->key.data = ngx_pnalloc(r->pool,
              h->key.len + 1 + h->value.len + 1
              + h->key.len);
          if (h->key.data == NULL) {
            return NGX_ERROR;
          }

          h->value.data = h->key.data + h->key.len + 1;
          h->lowcase_key = h->key.data + h->key.len + 1
            + h->value.len + 1;

          ngx_cpystrn(h->key.data, ctx->key.data,
              h->key.len + 1);
          ngx_cpystrn(h->value.data, ctx->value.data,
              h->value.len + 1);

          h->hash = ngx_hash_strlow(h->lowcase_key, ctx->key.data,
              ctx->key.len);

          hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
              h->lowcase_key, h->key.len);

          if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
            return NGX_ERROR;
          }

          ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
              "http hmux header: \"%V: %V\"",
              &h->key, &h->value);
          break;

        case HMUX_META_HEADER: //IGNORE
        case HMUX_CHANNEL:
        case HMUX_FLUSH:
        case CSE_SEND_HEADER:
        case HMUX_ACK:
        default:
          ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
              "http hmux ignore cmd: '%c' %02d %i",
              ctx->cmd, ctx->cmd, ctx->cmd_len);
          break;
      }

      if (ctx->cmd == HMUX_DATA) {
        return NGX_OK;
      }

      continue;
    }


    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        "upstream sent invalid header");

    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
  }
}

static ngx_int_t ngx_http_hmux_input_filter_init(void *data) {
  ngx_http_request_t    *r = data;
  ngx_http_upstream_t   *u;
  ngx_http_hmux_ctx_t   *ctx;

  u = r->upstream;

  ctx = ngx_http_get_module_ctx(r, ngx_http_hmux_module);

  u->pipe->length = ctx->body_chunk_size + 1;

  u->length = -1;

  return NGX_OK;
}

static ngx_int_t
ngx_http_hmux_chunked_filter(ngx_event_pipe_t *p, ngx_buf_t *buf){
  ngx_http_request_t      *r;
  ngx_int_t               rc;
  ngx_buf_t               *b, **prev;
  ngx_chain_t             *cl;
  ngx_http_hmux_ctx_t     *ctx;

  if (buf->pos == buf->last) {
    return NGX_OK;
  }

  r = p->input_ctx;

  ctx = ngx_http_get_module_ctx(r, ngx_http_hmux_module);

  b = NULL;
  prev = &buf->shadow;

  do {
    if (ctx->body_chunk_size) {
      ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
          "http hmux fill data chunk: %i, bytes: %i",
          ctx->body_chunk_size, buf->last - buf->pos);

      if (p->free) {
        cl = p->free;
        b = cl->buf;
        p->free = cl->next;
        ngx_free_chain(p->pool, cl);

      } else {
        b = ngx_alloc_buf(p->pool);
        if (b == NULL) {
          return NGX_ERROR;
        }
      }

      ngx_memzero(b, sizeof(ngx_buf_t));

      b->pos = buf->pos;
      b->start = buf->start;
      b->end = buf->end;
      b->tag = p->tag;
      b->temporary = 1;
      b->recycled = 1;

      *prev = b;
      prev = &b->shadow;

      cl = ngx_alloc_chain_link(p->pool);
      if (cl == NULL) {
        return NGX_ERROR;
      }

      cl->buf = b;
      cl->next = NULL;

      if (p->in) {
        *p->last_in = cl;
      } else {
        p->in = cl;
      }
      p->last_in = &cl->next;

      b->num = buf->num;

      ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
          "input buf #%d %p", b->num, b->pos);

      if (buf->last - buf->pos >= ctx->body_chunk_size) {
        buf->pos += ctx->body_chunk_size;
        b->last = buf->pos;
        ctx->body_chunk_size = 0;

        continue;
      }

      ctx->body_chunk_size -= buf->last - buf->pos;
      buf->pos = buf->last;
      b->last = buf->last;

      continue;
    }

    rc = ngx_http_hmux_process_cmd(r, ctx, buf, 1);

    if (rc == NGX_OK){
      switch (ctx->cmd) {
        case HMUX_QUIT:
          ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
              "http hmux send quit");

          p->length = 0;
          p->upstream_done = 1;
          r->upstream->keepalive = 1;

          break;

        case HMUX_FLUSH:
          break;

        case HMUX_DATA:
          break;

        default:
          ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
              "http hmux ignore cmd after content: '%c' %02d %i",
              ctx->cmd, ctx->cmd, ctx->cmd_len);
          return NGX_ERROR;
      }
    }

    if (rc == NGX_AGAIN) {
      if (buf->pos != buf->last) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http hmux invalid cmd after content: '%c' %02d s:%i",
            ctx->cmd, ctx->cmd, ctx->cmd_state);
        return NGX_ERROR;
      }

      break;
    }
  } while (buf->pos != buf->last);

  if (ctx->body_chunk_size) {
    p->length = ctx->body_chunk_size + 1; /* + HMUX_QUIT */
  } else if (!p->upstream_done) {
    p->length = -1;
  }

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
      "http hmux chunked, length %d", p->length);

  if (b) {
    b->shadow = buf;
    b->last_shadow = 1;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
        "input buf %p %z", b->pos, b->last - b->pos);

    return NGX_OK;
  }

  /* there is no data record in the buf, add it to free chain */

  if (ngx_event_pipe_add_free_buf(p, buf) != NGX_OK) {
    return NGX_ERROR;
  }

  return NGX_OK;
}

static ngx_buf_t *ngx_http_hmux_append_out_chain(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_chain_t ***lll){
  ngx_chain_t          *cl, **ll;

  ll = lll ? *lll : NULL;
  
  if (ll == NULL) {
    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
      ll = &cl->next;
    }
  }

  cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
  if (cl == NULL) {
    return NULL;
  }

  *ll = cl;

  cl->buf->flush = 1;
  cl->buf->memory = 1;

  if (lll != NULL) {
    *lll = &cl->next;
  }

  return cl->buf;
}

static ngx_int_t ngx_http_hmux_non_buffered_chunked_filter(void *data,
    ssize_t bytes) {
  ngx_http_request_t   *r = data;

  u_char               *last;
  ssize_t               len;
  ngx_int_t             rc;
  ngx_buf_t            *b, *nb;
  ngx_chain_t          **ll;
  ngx_http_upstream_t  *u;
  ngx_http_hmux_ctx_t  *ctx;

  ctx = ngx_http_get_module_ctx(r, ngx_http_hmux_module);

  u = r->upstream;

  b = &u->buffer;

  b->pos = b->last;
  b->last += bytes;

  ll = NULL;

  for ( ;; ){
    if (ctx->body_chunk_size) {
      ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
          "http hmux fill data chunk: %i, bytes: %i", ctx->body_chunk_size, bytes);

      len = ngx_min(bytes, ctx->body_chunk_size);

      nb = ngx_http_hmux_append_out_chain(r, u, &ll);
      if (nb == NULL) {
        return NGX_ERROR;
      }

      nb->pos = b->pos;

      b->pos += len;
      nb->last = b->pos;
      nb->tag = u->output.tag;

      bytes -= len;

      ctx->body_chunk_size -= len;

      if (!bytes) {
        return NGX_OK;
      }
    }

    last = b->pos;

    rc = ngx_http_hmux_process_cmd(r, ctx, b, 1);

    bytes -= b->pos - last;

    if (rc == NGX_OK){
      switch (ctx->cmd){
        case HMUX_QUIT:
          ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
              "http hmux get hmux quit");

          u->length = 0;
          u->keepalive = 1;

          return NGX_OK;

        case HMUX_FLUSH:
          break;

        case HMUX_DATA:
          break;

        default:
          ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
              "http hmux ignore cmd after content: '%c' %02d %i",
              ctx->cmd, ctx->cmd, ctx->cmd_len);
          break;
      }
      continue;
    }

    if (rc == NGX_AGAIN) {
      if (b->pos != b->last){
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http hmux invalid cmd after content: '%c' %02d s:%i",
            ctx->cmd, ctx->cmd, ctx->cmd_state);
        return NGX_ERROR;
      }

      break;
    }
  }

  return NGX_OK;
}

static void
ngx_http_hmux_abort_request(ngx_http_request_t *r)
{
  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
      "abort http hmux request");

  return;
}


static void
ngx_http_hmux_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
      "finalize http hmux request");

  return;
}

static void *ngx_http_hmux_create_loc_conf(ngx_conf_t *cf){
  ngx_http_hmux_loc_conf_t    *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hmux_loc_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  conf->upstream.buffering = NGX_CONF_UNSET;

  conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
  conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
  conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

  conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

  conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
  conf->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
  conf->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;

  conf->send_buffer_size = NGX_CONF_UNSET_SIZE;

  conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
  conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

  /* the hardcoded values */
  conf->upstream.cyclic_temp_file = 0;
  conf->upstream.ignore_client_abort = 0;
  conf->upstream.send_lowat = 0;
  conf->upstream.bufs.num = 0;
  conf->upstream.busy_buffers_size = 0;
  conf->upstream.max_temp_file_size = 0;
  conf->upstream.temp_file_write_size = 0;
  conf->upstream.intercept_errors = 1;
  conf->upstream.intercept_404 = 1;
  conf->upstream.pass_request_headers = 0;

  ngx_str_set(&conf->upstream.module, "hmux");

  return conf;
}

static char *ngx_http_hmux_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child)
{
  ngx_http_core_loc_conf_t      *clcf;
  ngx_hash_init_t               hash;
  size_t                        size;

  ngx_http_hmux_loc_conf_t      *prev = parent;
  ngx_http_hmux_loc_conf_t      *conf = child;

  ngx_conf_merge_value(conf->upstream.buffering,
      prev->upstream.buffering, 1);

  ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
      prev->upstream.connect_timeout, 60000);

  ngx_conf_merge_msec_value(conf->upstream.send_timeout,
      prev->upstream.send_timeout, 60000);

  ngx_conf_merge_msec_value(conf->upstream.read_timeout,
      prev->upstream.read_timeout, 60000);

  ngx_conf_merge_size_value(conf->upstream.buffer_size,
      prev->upstream.buffer_size,
      (size_t) ngx_pagesize);

  ngx_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
      8, ngx_pagesize);

  if (conf->upstream.bufs.num < 2) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "there must be at least 2 \"hmux_buffers\"");
    return NGX_CONF_ERROR;
  }

  size = conf->upstream.buffer_size;
  if (size < conf->upstream.bufs.size) {
    size = conf->upstream.bufs.size;
  }

  ngx_conf_merge_size_value(conf->upstream.busy_buffers_size_conf,
                              prev->upstream.busy_buffers_size_conf,
                              NGX_CONF_UNSET_SIZE);

  if (conf->upstream.busy_buffers_size_conf == NGX_CONF_UNSET_SIZE) {
    conf->upstream.busy_buffers_size = 2 * size;
  } else {
    conf->upstream.busy_buffers_size =
      conf->upstream.busy_buffers_size_conf;
  }

  if (conf->upstream.busy_buffers_size < size) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "\"hmux_busy_buffers_size\" must be equal or bigger than "
        "maximum of the value of \"hmux_buffer_size\" and "
        "one of the \"hmux_buffers\"");

    return NGX_CONF_ERROR;
  }

  if (conf->upstream.busy_buffers_size
      > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
  {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "\"hmux_busy_buffers_size\" must be less than "
        "the size of all \"hmux_buffers\" minus one buffer");

    return NGX_CONF_ERROR;
  }


  ngx_conf_merge_size_value(conf->upstream.temp_file_write_size_conf,
      prev->upstream.temp_file_write_size_conf,
      NGX_CONF_UNSET_SIZE);

  if (conf->upstream.temp_file_write_size_conf == NGX_CONF_UNSET_SIZE) {
    conf->upstream.temp_file_write_size = 2 * size;
  } else {
    conf->upstream.temp_file_write_size =
      conf->upstream.temp_file_write_size_conf;
  }

  if (conf->upstream.temp_file_write_size < size) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "\"hmux_temp_file_write_size\" must be equal or bigger than "
        "maximum of the value of \"hmux_buffer_size\" and "
        "one of the \"hmux_buffers\"");

    return NGX_CONF_ERROR;
  }

  ngx_conf_merge_size_value(conf->upstream.max_temp_file_size_conf,
      prev->upstream.max_temp_file_size_conf,
      NGX_CONF_UNSET_SIZE);

  if (conf->upstream.max_temp_file_size_conf == NGX_CONF_UNSET_SIZE) {
    conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
  } else {
    conf->upstream.max_temp_file_size =
      conf->upstream.max_temp_file_size_conf;
  }

  if (conf->upstream.max_temp_file_size != 0
      && conf->upstream.max_temp_file_size < size)
  {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "\"hmux_max_temp_file_size\" must be equal to zero to disable "
        "the temporary files usage or must be equal or bigger than "
        "maximum of the value of \"hmux_buffer_size\" and "
        "one of the \"hmux_buffers\"");

    return NGX_CONF_ERROR;
  }

  ngx_conf_merge_size_value(conf->send_buffer_size,
      prev->send_buffer_size,
      16 * 1024);

  ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
      prev->upstream.next_upstream,
      (NGX_CONF_BITMASK_SET
       |NGX_HTTP_UPSTREAM_FT_ERROR
       |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

  if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
    conf->upstream.next_upstream = NGX_CONF_BITMASK_SET |
      NGX_HTTP_UPSTREAM_FT_OFF;
  }

  hash.max_size = 512;
  hash.bucket_size = ngx_align(64, ngx_cacheline_size);
  hash.name = "hmux_hide_headers_hash";

  if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream,
        &prev->upstream, ngx_http_hmux_hide_headers, &hash)
      != NGX_OK)
  {
    return NGX_CONF_ERROR;
  }

  if (conf->upstream.upstream == NULL) {
    conf->upstream.upstream = prev->upstream.upstream;
  }

  if (conf->complex_upstream == NULL) {
    conf->complex_upstream = prev->complex_upstream;
  }

  if (conf->upstream.upstream || conf->complex_upstream) {
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    if (clcf->handler == NULL && clcf->lmt_excpt) {
      clcf->handler = ngx_http_hmux_handler;
    }
  }

  return NGX_CONF_OK;
}

static char *ngx_http_hmux_pass(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf)
{
  ngx_http_hmux_loc_conf_t            *hlcf = conf;

  ngx_url_t                           u;
  ngx_str_t                           *value, *url;
  ngx_uint_t                          n;
  ngx_http_core_loc_conf_t           *clcf;
  ngx_http_compile_complex_value_t    ccv;

  if (hlcf->upstream.upstream || hlcf->complex_upstream) {
    return "is duplicate";
  }

  clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

  clcf->handler = ngx_http_hmux_handler;

  if (clcf->name.data[clcf->name.len - 1] == '/') {
    clcf->auto_redirect = 1;
  }

  value = cf->args->elts;

  url = &value[1];

  if (url->len > 7 && ngx_strncasecmp(url->data, (u_char *)"hmux://", 7) == 0) {
    url->len -= 7;
    url->data += 7;
  }

  n = ngx_http_script_variables_count(url);

  if (n) {
    hlcf->complex_upstream = ngx_palloc(cf->pool,
        sizeof(ngx_http_complex_value_t));

    if (hlcf->complex_upstream == NULL){
      return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = url;
    ccv.complex_value = hlcf->complex_upstream;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
      return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
  }

  ngx_memzero(&u, sizeof(ngx_url_t));

  u.url = value[1];
  u.default_port = NGX_HMUX_DEFAULT_PORT;
  u.no_resolve = 1;

  hlcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
  if (hlcf->upstream.upstream == NULL) {
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}
