#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HMUX_FLUSH_OFF          0
#define NGX_HMUX_FLUSH_ON           1
#define NGX_HMUX_FLUSH_ALWAYS       2

#define NGX_HMUX_DEFAULT_PORT       6802
#define NGX_HMUX_CHANNEL_LEN        3
#define NGX_HMUX_ACK_CMD_LEN        3
#define NGX_HMUX_DATA_MAX_SIZE      ((1 << 16) - 1)
#define NGX_BUF_FLEN_FIELD          end

#define NGX_HMUX_STRING_LEN(a)      (3 + (a))
#define NGX_HMUX_WRITE_CMD(p, cmd, len)                           \
  *(p)++ = cmd;                                                   \
  *(p) ++ = ((len) >> 8) & 0xFF;                                  \
  *(p) ++ = (len) & 0xFF

#define NGX_HMUX_WRITE_STR(p, cmd, str)                           \
  NGX_HMUX_WRITE_CMD(p, cmd, (str).len);                          \
  p = ngx_copy(p, (str).data, (str).len)

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

  size_t                          ack_size;

  ngx_uint_t                      flush;

  ngx_array_t                     *flushes;

  ngx_array_t                     *headers_set_len;
  ngx_array_t                     *headers_set;
  ngx_hash_t                      headers_set_hash;

  ngx_array_t                     *headers_source;

  ngx_uint_t                      headers_hash_max_size;
  ngx_uint_t                      headers_hash_bucket_size;
} ngx_http_hmux_loc_conf_t;

typedef struct {
  ngx_str_t                       key;
  ngx_str_t                       value;

  ngx_uint_t                      body_chunk_size;

  off_t                           rest;
  ngx_chain_t                     *in;
  ngx_array_t                     *segments;
  ngx_int_t                       segment_idx;

  unsigned                        key_done:1;

  ngx_uint_t                      cmd_state;
  ngx_uint_t                      cmd_len;
  u_char                          cmd;
} ngx_http_hmux_ctx_t;

typedef struct {
  u_char                          cmd;
  ngx_str_t                       value;
  ngx_uint_t                      if_empty_skip;
} ngx_http_hmux_param_t;

static ngx_int_t ngx_http_variable_hmux_request_uri(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_variable_hmux_server_port(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

void ngx_http_upstream_next(ngx_http_request_t *r, ngx_http_upstream_t *u,
    ngx_uint_t ft_type);
void ngx_http_upstream_finalize_request(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_int_t rc);

static ngx_int_t ngx_http_hmux_add_vars(ngx_conf_t *cf);

static void *ngx_http_hmux_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_hmux_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_hmux_merge_headers(ngx_conf_t *cf,
    ngx_http_hmux_loc_conf_t *conf, ngx_http_hmux_loc_conf_t *prev);

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

static void ngx_http_hmux_upstream_send_body_handler(ngx_http_request_t *r,
    ngx_http_upstream_t *u);

static ngx_conf_bitmask_t  ngx_http_hmux_next_upstream_masks[] = {
  { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
  { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
  { ngx_string("invalid_header"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
  { ngx_string("http_500"), NGX_HTTP_UPSTREAM_FT_HTTP_500 },
  { ngx_string("http_502"), NGX_HTTP_UPSTREAM_FT_HTTP_502 },
  { ngx_string("http_503"), NGX_HTTP_UPSTREAM_FT_HTTP_503 },
  { ngx_string("http_504"), NGX_HTTP_UPSTREAM_FT_HTTP_504 },
  { ngx_string("http_404"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
  { ngx_string("updating"), NGX_HTTP_UPSTREAM_FT_UPDATING },
  { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
  { ngx_null_string, 0 }
};

static ngx_conf_enum_t  ngx_http_hmux_flush[] = {
  { ngx_string("off"),    NGX_HMUX_FLUSH_OFF},
  { ngx_string("on"),     NGX_HMUX_FLUSH_ON},
  { ngx_string("always"), NGX_HMUX_FLUSH_ALWAYS},
  { ngx_null_string, 0 }
};

static ngx_command_t ngx_http_hmux_commands[] = {

  { ngx_string("hmux_pass"),
    NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
    ngx_http_hmux_pass,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },

  { ngx_string("hmux_buffering"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, upstream.buffering),
    NULL },

  { ngx_string("hmux_ignore_client_abort"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, upstream.ignore_client_abort),
    NULL },

  { ngx_string("hmux_bind"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_http_upstream_bind_set_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, upstream.local),
    NULL },

  { ngx_string("hmux_connect_timeout"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, upstream.connect_timeout),
    NULL },

  { ngx_string("hmux_send_timeout"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, upstream.send_timeout),
    NULL },

  { ngx_string("hmux_intercept_errors"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, upstream.intercept_errors),
    NULL },

  { ngx_string("hmux_set_header"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
    ngx_conf_set_keyval_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, headers_source),
    NULL },

  { ngx_string("hmux_headers_hash_max_size"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, headers_hash_max_size),
    NULL },

  { ngx_string("hmux_headers_hash_bucket_size"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, headers_hash_bucket_size),
    NULL },

  { ngx_string("hmux_buffer_size"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_size_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, upstream.buffer_size),
    NULL },

  { ngx_string("hmux_read_timeout"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, upstream.read_timeout),
    NULL },

  { ngx_string("hmux_buffers"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
    ngx_conf_set_bufs_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, upstream.bufs),
    NULL },

  { ngx_string("hmux_busy_buffers_size"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_size_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, upstream.busy_buffers_size_conf),
    NULL },

  { ngx_string("hmux_temp_path"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
    ngx_conf_set_path_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, upstream.temp_path),
    NULL },

  { ngx_string("hmux_max_temp_file_size"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_size_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, upstream.max_temp_file_size_conf),
    NULL },

  { ngx_string("hmux_temp_file_write_size"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_size_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, upstream.temp_file_write_size_conf),
    NULL },

  { ngx_string("hmux_next_upstream"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
    ngx_conf_set_bitmask_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, upstream.next_upstream),
    &ngx_http_hmux_next_upstream_masks },

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

  { ngx_string("hmux_ack_size"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_size_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, ack_size),
    NULL },

  { ngx_string("hmux_flush"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_enum_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_hmux_loc_conf_t, flush),
    &ngx_http_hmux_flush},

  ngx_null_command
};

static ngx_http_module_t ngx_http_hmux_module_ctx = {
  ngx_http_hmux_add_vars,                   /* preconfiguration */
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

static ngx_keyval_t  ngx_http_hmux_headers[] = {
  { ngx_string("Content-Type"), ngx_string("") },
  { ngx_string("Content-Length"), ngx_string("") },
  { ngx_string("Expect"), ngx_string("") },

  { ngx_string("SCRIPT_URI"), ngx_string("$hmux_request_uri") },
  { ngx_string("SCRIPT_URL"),
    ngx_string("$scheme://$host$hmux_server_port$hmux_request_uri") },

  { ngx_null_string, ngx_null_string }
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

static ngx_http_variable_t  ngx_http_hmux_variables[] = {
  { ngx_string("hmux_request_uri"), NULL,
      ngx_http_variable_hmux_request_uri, 0, 0, 0 },

  { ngx_string("hmux_server_port"), NULL,
      ngx_http_variable_hmux_server_port, 0, 0, 0 },

  { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_path_init_t  ngx_http_hmux_temp_path = {
  ngx_string(NGX_HTTP_HMUX_TEMP_PATH), { 1, 2, 0 }
};

#if 0
static ngx_http_hmux_param_t ngx_http_hmux_params[] = {
  { HMUX_CHANNEL,       ngx_string("\x00\x01"),         0 },
  { HMUX_URL,           ngx_string("$hmux_uri"),        0 },
  { HMUX_METHOD,        ngx_string("$request_method"),  0 },
  { CSE_PROTOCOL,       ngx_string("$server_protocol"), 0 },
  { CSE_QUERY_STRING,   ngx_string("$args"),            1 },
  { HMUX_SERVER_NAME,   ngx_string("$host"),            0 },
  { CSE_SERVER_PORT,    ngx_string("$server_port"),     0 },
  { CSE_REMOTE_HOST,    ngx_string("$remote_addr"),     0 },
  { CSE_REMOTE_ADDR,    ngx_string("$remote_addr"),     0 },
  { CSE_REMOTE_PORT,    ngx_string("$remote_port"),     0 },
  { CSE_REMOTE_USER,    ngx_string("$remote_user"),     2 },
  { CSE_AUTH_TYPE,      ngx_string("Basic"),            0 },
  { CSE_CONTENT_LENGTH, ngx_string("$content_length"),  1 },
  { CSE_CONTENT_TYPE,   ngx_string("$content_type"),    1 },

  { 0, ngx_null_string, 0 }
};
#endif

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

static ngx_int_t
ngx_http_hmux_get_data_chain(ngx_http_request_t *r, ngx_chain_t *in,
    ngx_chain_t **out)
{
  u_char                        *p;
  size_t                        chunk_size, chain_size, buf_size, offset, eat;
  ngx_buf_t                     *b;
  ngx_chain_t                   *body, *cl, *top, *next, *last, **ll;
  ngx_http_hmux_ctx_t           *ctx;
  ngx_http_hmux_loc_conf_t      *hlcf;

  ctx = ngx_http_get_module_ctx(r, ngx_http_hmux_module);
  if (ctx == NULL) {
    return NGX_ERROR;
  }

  hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hmux_module);
  if (hlcf == NULL) {
    return NGX_ERROR;
  }

  if (in != NULL) {

    ctx->rest = r->headers_in.content_length_n;

  } else if (ctx->segments && ctx->segment_idx < ctx->segments->nelts) {
    ll = ctx->segments->elts;

    *out = ll[ctx->segment_idx ++];

    return NGX_OK;
  } else if (ctx->in == NULL && ctx->segment_idx >= ctx->segments->nelts) {
    return NGX_DONE;
  }

  body = in ? in : ctx->in;

  top = ngx_alloc_chain_link(r->pool);
  if (top == NULL) {
    return NGX_ERROR;
  }

  cl = top;

  offset = 0;

  chain_size = 0;

  while (body) {
    b = ngx_create_temp_buf(r->pool, 3);
    if (b == NULL) {
      return NGX_ERROR;
    }

    p = b->pos;

    b->last += 3;

    cl->buf = b;

    cl->next = ngx_alloc_chain_link(r->pool);
    if (cl->next == NULL) {
      return NGX_ERROR;
    }

    cl = cl->next;

    chunk_size = 0;

    while (body) {
      b = ngx_alloc_buf(r->pool);
      if (b == NULL) {
        return NGX_ERROR;
      }

      ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));

      cl->buf = b;

      cl->next = ngx_alloc_chain_link(r->pool);
      if (cl->next == NULL) {
        return NGX_ERROR;
      }

      cl = cl->next;

      if (offset) {
        if (ngx_buf_in_memory(b)) {
          b->start += offset;
          b->pos = b->start;
        } else {
          b->file_pos += offset;
        }
      }

      buf_size = ngx_buf_size(b);

      if (chunk_size + buf_size > NGX_HMUX_DATA_MAX_SIZE) {
        eat = NGX_HMUX_DATA_MAX_SIZE - chunk_size;

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http hmux split buf: o:%O s:%uz b:%uz", offset, eat, buf_size);

        offset += eat;

        if (ngx_buf_in_memory(b)) {
          b->last = b->pos + eat;
        } else {
          b->file_last = b->file_pos + eat;
          b->NGX_BUF_FLEN_FIELD = (u_char *)eat;
        }

        chunk_size = NGX_HMUX_DATA_MAX_SIZE;

        break;
      }

      offset = 0;

      chunk_size += buf_size;

      if (in == NULL) {
        next = body->next;

        ngx_free_chain(r->pool, body);

        body = next;
      } else {
        body = body->next;
      }

      if (chunk_size == NGX_HMUX_DATA_MAX_SIZE)
        break;
    }

    NGX_HMUX_WRITE_CMD(p, HMUX_DATA, chunk_size);

    chain_size += chunk_size;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "http hmux add chunk: t:%uz c:%uz", chunk_size, chain_size);

    if (chain_size >= hlcf->ack_size) {
      b = ngx_create_temp_buf(r->pool, 1);
      if (b == NULL) {
        return NGX_ERROR;
      }

      *b->last ++ = HMUX_YIELD;

      b->flush = 1;

      cl->buf = b;

      break;
    }

    if (body == NULL) {
      break;
    }
  }

  cl->next = NULL;

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
      "http hmux data chain: c:%uz", chain_size);

  if (ctx->segments == NULL) {
    if (in == NULL || (body == NULL && chain_size >= hlcf->ack_size)) {
      ctx->segments = ngx_array_create(r->pool, 4, sizeof(ngx_chain_t *));
      if (ctx->segments == NULL) {
        return NGX_ERROR;
      }
    }
  }

  if (in == NULL) {
    ll = ngx_array_push(ctx->segments);
    if (ll == NULL) {
      return NGX_ERROR;
    }

    *ll = top;

    ctx->segment_idx = ctx->segments->nelts;
  }

  last = NULL;

  if (body == NULL) {
    b = ngx_create_temp_buf(r->pool, 1);
    if (b == NULL) {
      return NGX_ERROR;
    }

    *b->last ++ = HMUX_QUIT;

    b->flush = 1;

    if (chain_size >= hlcf->ack_size) {
      last = ngx_alloc_chain_link(r->pool);
      if (last == NULL) {
        return NGX_ERROR;
      }

      last->buf = b;
      last->next = NULL;

      ll = ngx_array_push(ctx->segments);
      if (ll == NULL) {
        return NGX_ERROR;
      }

      *ll = last;
    } else {
      cl->buf = b;
    }

    ctx->in = NULL;
  } else {
    // save chains left
    if (in == NULL) {
      ctx->in = body;
    } else {
      ll = &ctx->in;

      while (body) {
        b = ngx_alloc_buf(r->pool);
        if (b == NULL) {
          return NGX_ERROR;
        }

        ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
          return NGX_ERROR;
        }

        cl->buf = b;

        *ll = cl;

        ll = &cl->next;

        body = body->next;
      }

      *ll = NULL;
    }

    if (offset) {
      b = ctx->in->buf;

      if (ngx_buf_in_memory(b)) {
        b->start += offset;
        b->pos = b->start;
      } else {
        b->file_pos += offset;
      }
    }
  }

  *out = top;

  ctx->rest -= chain_size;

  ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
      "http hmux send body %O, rest %O", chain_size, ctx->rest);

  return NGX_OK;
}

static ngx_int_t ngx_http_hmux_create_request(ngx_http_request_t *r) {
  ngx_http_hmux_loc_conf_t      *hlcf;
  size_t                        len, uri_len, port_len, value_len;
  uintptr_t                     escape;
  ngx_uint_t                    i, unparsed_uri, port;

  struct sockaddr_in            *sin;
#if (NGX_HAVE_INET6)
  struct sockaddr_in6           *sin6;
#endif

  ngx_list_part_t               *part;
  ngx_table_elt_t               *header;

  ngx_str_t                     method;

  ngx_buf_t                     *b;
  ngx_chain_t                   *cl, *body, *chunks;
  ngx_http_upstream_t           *u;

  u_char                        *p;

  ngx_http_script_engine_t      e, le;
  ngx_http_script_len_code_pt   lcode;
  ngx_http_script_code_pt       code;

  u = r->upstream;

  hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hmux_module);

  len = NGX_HMUX_CHANNEL_LEN + 1; // 1 for HMUX_QUIT

  // env
  escape = 0;
  unparsed_uri = 0;

  if (r->valid_unparsed_uri && r == r->main) {
    unparsed_uri = 1;

    p = ngx_strlchr(r->unparsed_uri.data,
                    r->unparsed_uri.data + r->unparsed_uri.len, '?');
    if (p == NULL) {
      uri_len = r->unparsed_uri.len;
    } else {
      uri_len = p - r->unparsed_uri.data;
    }
  } else {
    if (r->quoted_uri || r->space_in_uri || r->internal) {
      escape = 2 * ngx_escape_uri(NULL, r->uri.data, r->uri.len,
          NGX_ESCAPE_URI);
    }

    uri_len = r->uri.len + escape;
  }

  if (uri_len == 0) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        "zero length URI to hmux");
    return NGX_ERROR;
  }
  
  if (u->method.len) {
    /* HEAD was changed to GET to cache response */
    method = u->method;
  } else {
    method = r->method_name;
  }

  len += NGX_HMUX_STRING_LEN(uri_len) +
    NGX_HMUX_STRING_LEN(method.len) +
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

  if (r->headers_in.content_length != NULL) {
    len += NGX_HMUX_STRING_LEN(r->headers_in.content_length->value.len);
  }

  if (r->headers_in.content_type != NULL) {
    len += NGX_HMUX_STRING_LEN(r->headers_in.content_type->value.len);
  }

  // headers
  ngx_http_script_flush_no_cacheable_variables(r, hlcf->flushes);

  le.ip = hlcf->headers_set_len->elts;
  le.request = r;
  le.flushed = 1;

  while (*(uintptr_t *) le.ip) {
    while (*(uintptr_t *) le.ip) {
      lcode = *(ngx_http_script_len_code_pt *) le.ip;
      len += lcode(&le);
    }
    le.ip += sizeof(uintptr_t);
  }

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

    if (ngx_hash_find(&hlcf->headers_set_hash, header[i].hash,
          header[i].lowcase_key, header[i].key.len))
    {
      continue;
    }

    len += NGX_HMUX_STRING_LEN(header[i].key.len)
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
    b->last = ngx_copy(b->last, r->unparsed_uri.data, uri_len);
  } else {
    if (escape) {
      ngx_escape_uri(b->last, r->uri.data, r->uri.len, NGX_ESCAPE_URI);
      b->last += uri_len;
    } else {
      b->last = ngx_copy(b->last, r->uri.data, r->uri.len);
    }
  }

  u->uri.len = b->last - u->uri.data;

  NGX_HMUX_WRITE_STR(b->last, HMUX_METHOD, method);
  NGX_HMUX_WRITE_STR(b->last, CSE_PROTOCOL, r->http_protocol);

  if (r->args.len) {
    NGX_HMUX_WRITE_STR(b->last, CSE_QUERY_STRING, r->args);
  }

  NGX_HMUX_WRITE_STR(b->last, HMUX_SERVER_NAME, r->headers_in.server);

  // server port
  if (ngx_connection_local_sockaddr(r->connection, NULL, 0) != NGX_OK) {
    return NGX_ERROR;
  }

  switch (r->connection->local_sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
    case AF_INET6:
      sin6 = (struct sockaddr_in6 *) r->connection->local_sockaddr;
      port = ntohs(sin6->sin6_port);
      break;
#endif
    default: /* AF_INET */
      sin = (struct sockaddr_in *) r->connection->local_sockaddr;
      port = ntohs(sin->sin_port);
      break;
  }

  p = b->last;
  b->last = ngx_sprintf(p + NGX_HMUX_STRING_LEN(0), "%ui", port);
  port_len = b->last - p - NGX_HMUX_STRING_LEN(0);
  NGX_HMUX_WRITE_CMD(p, CSE_SERVER_PORT, port_len);

  NGX_HMUX_WRITE_STR(b->last, CSE_REMOTE_HOST, r->connection->addr_text);
  NGX_HMUX_WRITE_STR(b->last, CSE_REMOTE_ADDR, r->connection->addr_text);

  // remote port
  switch (r->connection->sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
    case AF_INET6:
      sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
      port = ntohs(sin6->sin6_port);
      break;
#endif
    default: /* AF_INET */
      sin = (struct sockaddr_in *) r->connection->sockaddr;
      port = ntohs(sin->sin_port);
      break;
  }

  p = b->last;
  b->last = ngx_sprintf(p + NGX_HMUX_STRING_LEN(0), "%ui", port);
  port_len = b->last - p - NGX_HMUX_STRING_LEN(0);
  NGX_HMUX_WRITE_CMD(p, CSE_REMOTE_PORT, port_len);

  if (r->headers_in.user.len){
    NGX_HMUX_WRITE_STR(b->last, CSE_REMOTE_USER, r->headers_in.user);
    NGX_HMUX_WRITE_CMD(b->last, CSE_AUTH_TYPE, sizeof("Basic") - 1);
    b->last = ngx_cpymem(b->last, "Basic", sizeof("Basic") - 1);
  }

  if (r->headers_in.content_length != NULL) {
    NGX_HMUX_WRITE_STR(b->last, CSE_CONTENT_LENGTH,
        r->headers_in.content_length->value);
  }

  if (r->headers_in.content_type != NULL) {
    NGX_HMUX_WRITE_STR(b->last, CSE_CONTENT_TYPE,
        r->headers_in.content_type->value);
  }

  // headers
  ngx_memzero(&e, sizeof(ngx_http_script_engine_t));
  e.ip = hlcf->headers_set->elts;
  e.pos = b->last;
  e.request = r;
  e.flushed = 1;

  le.ip = hlcf->headers_set_len->elts;

  while (*(uintptr_t *) le.ip) {
    lcode = *(ngx_http_script_len_code_pt *) le.ip;

    /* skip the header line name length */
    (void) lcode(&le);

    if (*(ngx_http_script_len_code_pt *) le.ip) {
      for (value_len = 0; *(uintptr_t *) le.ip; value_len += lcode(&le)) {
        lcode = *(ngx_http_script_len_code_pt *) le.ip;
      }

      e.skip = value_len == 0;

      e.status = value_len;
    } else {
      e.skip = 0;
    }

    le.ip += sizeof(uintptr_t);

    while (*(uintptr_t *)e.ip) {
      code = *(ngx_http_script_code_pt *) e.ip;
      code((ngx_http_script_engine_t *) &e);
    }

    e.ip += sizeof(uintptr_t);
  }

  b->last = e.pos;

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

    if (ngx_hash_find(&hlcf->headers_set_hash, header[i].hash,
          header[i].lowcase_key, header[i].key.len))
    {
      continue;
    }

    NGX_HMUX_WRITE_STR(b->last, HMUX_HEADER, header[i].key);
    NGX_HMUX_WRITE_STR(b->last, HMUX_STRING, header[i].value);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "http hmux header: \"%V: %V\"",
        &header[i].key, &header[i].value);
  }

  ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
      "http hmux headers write done. alloc:%uz used:%uz",
      len, b->last - b->start);

  body = u->request_bufs;
  u->request_bufs = cl;

  if (r->headers_in.content_length_n <= 0) {
    *b->last ++ = HMUX_QUIT;

    b->flush = 1;
    cl->next = NULL;
  } else {
    if (ngx_http_hmux_get_data_chain(r, body, &chunks) != NGX_OK){
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cl->next = chunks;
  }

  return NGX_OK;
}

static ngx_int_t ngx_http_hmux_reinit_request(ngx_http_request_t *r) {
  ngx_http_hmux_ctx_t     *ctx;
  ngx_chain_t             *cl, **ll;
  ngx_int_t               i;

  ctx = ngx_http_get_module_ctx(r, ngx_http_hmux_module);

  if (ctx == NULL) {
    return NGX_OK;
  }

  ctx->key_done = 0;
  ctx->cmd_state = 0;
  ctx->body_chunk_size = 0;

  if (ctx->segments) {
    ctx->segment_idx = 0;

    ll = ctx->segments->elts;

    for (i = 0; i < ctx->segments->nelts; i ++) {
      for (cl = ll[i]; cl; cl = cl->next) {
        cl->buf->pos = cl->buf->start;
        if (cl->buf->file_last) {
          cl->buf->file_pos = cl->buf->file_last -
            (off_t) cl->buf->NGX_BUF_FLEN_FIELD;
        }
      }
    }
  }

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

static void
ngx_http_hmux_upstream_dummy_handler(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
      "http hmux upstream dummy handler");
}

static ngx_int_t ngx_http_hmux_send_body_chunk(ngx_http_upstream_t *u,
    ngx_chain_t *in)
{
  ngx_int_t             rc;
  ngx_connection_t      *c;

  c = u->peer.connection;

  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
      "http hmux upstream send body");

  rc = ngx_output_chain(&u->output, in);

  if (rc == NGX_ERROR) {
    return NGX_ERROR;
  }

  if (c->write->timer_set) {
    ngx_del_timer(c->write);
  }

  if (rc == NGX_AGAIN) {
    ngx_add_timer(c->write, u->conf->send_timeout);

    u->write_event_handler = ngx_http_hmux_upstream_send_body_handler;

    if (ngx_handle_write_event(c->write, u->conf->send_lowat) != NGX_OK) {
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_AGAIN;
  }

  /* rc == NGX_OK */

  if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
    if (ngx_tcp_push(c->fd) == NGX_ERROR) {
      ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
          ngx_tcp_push_n " failed");
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
  }

  ngx_add_timer(c->read, u->conf->read_timeout);

  u->write_event_handler = ngx_http_hmux_upstream_dummy_handler;

  if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  return NGX_OK;
}

static void
ngx_http_hmux_upstream_send_body_handler(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
  ngx_int_t                   rc;
  ngx_connection_t            *c;

  c = u->peer.connection;

  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
     "http hmux upstream send body handler");

  if (c->write->timedout) {
    ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
    return;
  }

  rc = ngx_http_hmux_send_body_chunk(u, NULL);

  if (rc == NGX_ERROR) {
    ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
    return;
  }

  if (rc == NGX_HTTP_INTERNAL_SERVER_ERROR) {
    ngx_http_upstream_finalize_request(r, u,
        NGX_HTTP_INTERNAL_SERVER_ERROR);
    return;
  }
}

static ngx_int_t ngx_http_hmux_process_header(ngx_http_request_t *r) {
  ngx_int_t                       rc, code;
  ngx_buf_t                       *b;
  ngx_chain_t                     *cl;
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

  b = &u->buffer;

  for ( ;; ){
    rc = ngx_http_hmux_process_cmd(r, ctx, b, 1);

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

          u->headers_in.status_line.data = ngx_pstrdup(r->pool, &ctx->key);
          if (u->headers_in.status_line.data == NULL) {
            return NGX_ERROR;
          }

          u->headers_in.status_line.len = ctx->key.len;

          ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
              "http hmux status %ui \"%V\"",
              u->headers_in.status_n, &u->headers_in.status_line);

          break;

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

        case CSE_SEND_HEADER:
          ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
              "http hmux header done");

          return NGX_OK;

        case HMUX_ACK:
          ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
              "http hmux ack received");

          /* for large post body, there will be too many acks */

          if (b->pos == b->last) {
            b->last -= NGX_HMUX_ACK_CMD_LEN;
            b->pos = b->last;
          }

          rc = ngx_http_hmux_get_data_chain(r, NULL, &cl);

          if (rc == NGX_OK) {
            rc = ngx_http_hmux_send_body_chunk(u, cl);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "http hmux send next chain return %i", rc);

            if (rc == NGX_HTTP_INTERNAL_SERVER_ERROR) {
              return NGX_ERROR;
            }

            if (rc == NGX_ERROR) {
              return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

          } else if (rc == NGX_DONE) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "http hmux body sent done");
          } else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "http hmux body get data error");

            return NGX_ERROR;
          }

          break;

        case HMUX_META_HEADER: //IGNORE
        case HMUX_CHANNEL:
        case HMUX_FLUSH:
        default:
          ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
              "http hmux ignore cmd: '%c' %02d %i",
              ctx->cmd, ctx->cmd, ctx->cmd_len);
          break;
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
  ngx_http_request_t          *r;
  ngx_int_t                   rc;
  ngx_buf_t                   *b, **prev;
  ngx_chain_t                 *cl;
  ngx_http_hmux_ctx_t         *ctx;
  ngx_http_hmux_loc_conf_t    *hlcf;

  if (buf->pos == buf->last) {
    return NGX_OK;
  }

  r = p->input_ctx;

  ctx = ngx_http_get_module_ctx(r, ngx_http_hmux_module);

  hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hmux_module);

  b = NULL;
  prev = &buf->shadow;

  do {
    if (ctx->body_chunk_size) {
      ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
          "http hmux fill data chunk: %ui @%ui",
          buf->last - buf->pos, ctx->body_chunk_size);

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
          "http hmux input buf #%d %p", b->num, b->pos);

      if (buf->last - buf->pos > ctx->body_chunk_size) {
        buf->pos += ctx->body_chunk_size;
        b->last = buf->pos;
        ctx->body_chunk_size = 0;
      } else {
        ctx->body_chunk_size -= buf->last - buf->pos;
        buf->pos = buf->last;
        b->last = buf->last;

        break;
      }
    }

    rc = ngx_http_hmux_process_cmd(r, ctx, buf, 1);

    if (rc == NGX_OK){
      switch (ctx->cmd) {
        case HMUX_QUIT:
        case HMUX_EXIT:
          p->length = 0;
          p->upstream_done = 1;
          r->upstream->keepalive = ctx->cmd == HMUX_QUIT;

          ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
              "http hmux send quit. k:%d", r->upstream->keepalive);

          break;

        case HMUX_FLUSH:
          ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
              "http hmux flush received");

          if (hlcf->flush == NGX_HMUX_FLUSH_ON) {
            if (b) {
              b->flush = 1;
            } else if (ngx_http_send_special(r, NGX_HTTP_FLUSH) == NGX_ERROR) {
              return NGX_ERROR;
            }
          }

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

  if (hlcf->flush != NGX_HMUX_FLUSH_ALWAYS && ctx->body_chunk_size) {
    p->length = ctx->body_chunk_size + 1; /* + HMUX_QUIT */
  } else if (!p->upstream_done) {
    p->length = 1;
  }

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
      "http hmux pipe set next expect length %d", p->length);

  if (b) {
    b->shadow = buf;
    b->last_shadow = 1;

    if (hlcf->flush == NGX_HMUX_FLUSH_ALWAYS) {
      b->flush = 1;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
        "http hmux input buf %p %z", b->pos, b->last - b->pos);

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

//  cl->buf->flush = 1;
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

  nb = NULL;

  for ( ;; ){
    if (ctx->body_chunk_size) {
      ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
          "http hmux fill data chunk: %ui @%ui", bytes, ctx->body_chunk_size);

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
        break;
      }
    }

    last = b->pos;

    rc = ngx_http_hmux_process_cmd(r, ctx, b, 1);

    bytes -= b->pos - last;

    if (rc == NGX_OK){
      switch (ctx->cmd){
        case HMUX_QUIT:
        case HMUX_EXIT:
          u->length = 0;
          u->keepalive = ctx->cmd == HMUX_QUIT;

          ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
              "http hmux get hmux quit, k:%d", u->keepalive);

          goto quit;

        case HMUX_FLUSH:
          ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
              "http hmux flush received, ignore in non-buffered mode");

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

quit:

  if (nb) {
    nb->flush = 1;
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

static ngx_int_t ngx_http_variable_hmux_request_uri(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {
  u_char                      *p;

  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;

  p = ngx_strlchr(r->unparsed_uri.data,
      r->unparsed_uri.data + r->unparsed_uri.len, '?');

  v->data = r->unparsed_uri.data;
  v->len = (p == NULL) ? r->unparsed_uri.len : (p - r->unparsed_uri.data);

  return NGX_OK;
}

static ngx_int_t ngx_http_variable_hmux_server_port(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {
  ngx_uint_t            port;
  struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
  struct sockaddr_in6  *sin6;
#endif

  v->len = 0;
  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;

  if (ngx_connection_local_sockaddr(r->connection, NULL, 0) != NGX_OK) {
    return NGX_ERROR;
  }

  switch (r->connection->local_sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
    case AF_INET6:
      sin6 = (struct sockaddr_in6 *) r->connection->local_sockaddr;
      port = ntohs(sin6->sin6_port);
      break;
#endif
    default: /* AF_INET */
      sin = (struct sockaddr_in *) r->connection->local_sockaddr;
      port = ntohs(sin->sin_port);
      break;
  }

  if (port > 0 && port < 65536) {
#if (NGX_HTTP_SSL)
    if (r->connection->ssl) {
      if (port == 443) {
        return NGX_OK;
      }
    } else 
#endif
    if (port == 80) {
      return NGX_OK;
    }

    v->data = ngx_pnalloc(r->pool, sizeof(":65535") - 1);
    if (v->data == NULL) {
      return NGX_ERROR;
    }
    v->len = ngx_sprintf(v->data, ":%ui", port) - v->data;
  }

  return NGX_OK;
}

static ngx_int_t ngx_http_hmux_add_vars(ngx_conf_t *cf) {
  ngx_http_variable_t   *var, *v;

  for (v = ngx_http_hmux_variables; v->name.len; v++) {
    var = ngx_http_add_variable(cf, &v->name, v->flags);
    if (var == NULL) {
      return NGX_ERROR;
    }

    var->get_handler = v->get_handler;
    var->data = v->data;
  }

  return NGX_OK;
}

static void *ngx_http_hmux_create_loc_conf(ngx_conf_t *cf){
  ngx_http_hmux_loc_conf_t    *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hmux_loc_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  /*
   * set by calloc
   *    conf->upstream.temp_path = NULL;
   *
   *    conf->headers_source = NULL;
   *    conf->headers_set_len = NULL;
   *    conf->headers_set = NULL;
   *    conf->headers_set_hash = NULL;
   */

  conf->upstream.buffering = NGX_CONF_UNSET;
  conf->upstream.ignore_client_abort = NGX_CONF_UNSET;

  conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
  conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
  conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

  conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

  conf->upstream.busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
  conf->upstream.max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
  conf->upstream.temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;

  conf->ack_size = NGX_CONF_UNSET_SIZE;
  conf->flush = NGX_CONF_UNSET_UINT;

  conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
  conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;

  conf->upstream.intercept_errors = NGX_CONF_UNSET;

  /* the hardcoded values */
  conf->upstream.cyclic_temp_file = 0;
  conf->upstream.send_lowat = 0;
  conf->upstream.bufs.num = 0;
  conf->upstream.busy_buffers_size = 0;
  conf->upstream.max_temp_file_size = 0;
  conf->upstream.temp_file_write_size = 0;
  conf->upstream.intercept_404 = 0; // if set 1, connection will be closed
  conf->upstream.pass_request_headers = 0;

  conf->headers_hash_max_size = NGX_CONF_UNSET_UINT;
  conf->headers_hash_bucket_size = NGX_CONF_UNSET_UINT;

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

  ngx_conf_merge_value(conf->upstream.ignore_client_abort,
      prev->upstream.ignore_client_abort, 0);

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

  ngx_conf_merge_size_value(conf->ack_size,
      prev->ack_size,
      16 * 1024);

  ngx_conf_merge_uint_value(conf->flush, prev->flush, NGX_HMUX_FLUSH_ON);

  ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
      prev->upstream.next_upstream,
      (NGX_CONF_BITMASK_SET
       |NGX_HTTP_UPSTREAM_FT_ERROR
       |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

  if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
    conf->upstream.next_upstream = NGX_CONF_BITMASK_SET |
      NGX_HTTP_UPSTREAM_FT_OFF;
  }

  if (ngx_conf_merge_path_value(cf, &conf->upstream.temp_path,
        prev->upstream.temp_path,
        &ngx_http_hmux_temp_path)
      != NGX_OK)
  {
    return NGX_CONF_ERROR;
  }

  ngx_conf_merge_value(conf->upstream.intercept_errors,
      prev->upstream.intercept_errors, 0);

  ngx_conf_merge_uint_value(conf->headers_hash_max_size,
      prev->headers_hash_max_size, 512);

  ngx_conf_merge_uint_value(conf->headers_hash_bucket_size,
      prev->headers_hash_bucket_size, 64);

  conf->headers_hash_bucket_size = ngx_align(conf->headers_hash_bucket_size,
      ngx_cacheline_size);

  hash.max_size = conf->headers_hash_max_size;
  hash.bucket_size = conf->headers_hash_bucket_size;
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

  if (ngx_http_hmux_merge_headers(cf, conf, prev) != NGX_OK) {
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

void ngx_hmux_value_cmd_code(ngx_http_script_engine_t *e) {
  ngx_http_script_code_pt       *code;

  code = (ngx_http_script_code_pt *) e->ip;

  if (!e->skip) {
    NGX_HMUX_WRITE_CMD(e->pos, HMUX_STRING, e->status);
  }

  e->ip += sizeof(ngx_http_script_code_pt);

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, e->request->connection->log, 0,
      "http hmux set value len: %ui", e->status);
}

static ngx_int_t
ngx_http_hmux_merge_headers(ngx_conf_t *cf, ngx_http_hmux_loc_conf_t *conf,
        ngx_http_hmux_loc_conf_t *prev)
{
  u_char                        *p;
  size_t                        size;
  uintptr_t                     *code;
  ngx_uint_t                    i;
  ngx_array_t                   headers_names, headers_merged;
  ngx_keyval_t                  *src, *s, *h;
  ngx_hash_key_t                *hk;
  ngx_hash_init_t               hash;
  ngx_http_script_compile_t     sc;
  ngx_http_script_copy_code_t   *copy;

  if (conf->headers_source == NULL) {
    conf->flushes = prev->flushes;
    conf->headers_set_len = prev->headers_set_len;
    conf->headers_set = prev->headers_set;
    conf->headers_set_hash = prev->headers_set_hash;
    conf->headers_source = prev->headers_source;
  }

  if (conf->headers_set_hash.buckets) {
    return NGX_OK;
  }

  if (ngx_array_init(&headers_names, cf->temp_pool, 4, sizeof(ngx_hash_key_t))
      != NGX_OK)
  {
    return NGX_ERROR;
  }

  if (ngx_array_init(&headers_merged, cf->temp_pool, 4, sizeof(ngx_keyval_t))
      != NGX_OK)
  {
    return NGX_ERROR;
  }

  if (conf->headers_source == NULL) {
    conf->headers_source = ngx_array_create(cf->pool, 4,
        sizeof(ngx_keyval_t));
    if (conf->headers_source == NULL) {
      return NGX_ERROR;
    }
  }

  conf->headers_set_len = ngx_array_create(cf->pool, 64, 1);
  if (conf->headers_set_len == NULL) {
    return NGX_ERROR;
  }

  conf->headers_set = ngx_array_create(cf->pool, 512, 1);
  if (conf->headers_set == NULL) {
    return NGX_ERROR;
  }

  h = ngx_http_hmux_headers;

  src = conf->headers_source->elts;
  for (i = 0; i < conf->headers_source->nelts; i++) {

    s = ngx_array_push(&headers_merged);
    if (s == NULL) {
      return NGX_ERROR;
    }

    *s = src[i];
  }

  while (h->key.len) {

    src = headers_merged.elts;
    for (i = 0; i < headers_merged.nelts; i++) {
      if (ngx_strcasecmp(h->key.data, src[i].key.data) == 0) {
        goto next;
      }
    }

    s = ngx_array_push(&headers_merged);
    if (s == NULL) {
      return NGX_ERROR;
    }

    *s = *h;

next:

    h++;
  }

  src = headers_merged.elts;
  for (i = 0; i < headers_merged.nelts; i++) {

    hk = ngx_array_push(&headers_names);
    if (hk == NULL) {
      return NGX_ERROR;
    }

    hk->key = src[i].key;
    hk->key_hash = ngx_hash_key_lc(src[i].key.data, src[i].key.len);
    hk->value = (void *) 1;

    if (src[i].value.len == 0) {
      continue;
    }

    if (ngx_http_script_variables_count(&src[i].value) == 0) {
      copy = ngx_array_push_n(conf->headers_set_len,
          sizeof(ngx_http_script_copy_code_t));
      if (copy == NULL) {
        return NGX_ERROR;
      }

      copy->code = (ngx_http_script_code_pt)
        ngx_http_script_copy_len_code;
      copy->len = NGX_HMUX_STRING_LEN(src[i].key.len)
        + NGX_HMUX_STRING_LEN(src[i].value.len);

      size = (sizeof(ngx_http_script_copy_code_t)
          + NGX_HMUX_STRING_LEN(src[i].key.len)
          + NGX_HMUX_STRING_LEN(src[i].value.len)
          + sizeof(uintptr_t) - 1)
        & ~(sizeof(uintptr_t) - 1);

      copy = ngx_array_push_n(conf->headers_set, size);
      if (copy == NULL) {
        return NGX_ERROR;
      }

      copy->code = ngx_http_script_copy_code;
      copy->len = NGX_HMUX_STRING_LEN(src[i].key.len)
        + NGX_HMUX_STRING_LEN(src[i].value.len);

      p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);

      NGX_HMUX_WRITE_STR(p, HMUX_HEADER, src[i].key);
      NGX_HMUX_WRITE_STR(p, HMUX_STRING, src[i].value);

    } else {
      copy = ngx_array_push_n(conf->headers_set_len,
          sizeof(ngx_http_script_copy_code_t));
      if (copy == NULL) {
        return NGX_ERROR;
      }

      copy->code = (ngx_http_script_code_pt)
        ngx_http_script_copy_len_code;
      copy->len = NGX_HMUX_STRING_LEN(src[i].key.len)
        + NGX_HMUX_STRING_LEN(0);   // value cmd and len

      size = (sizeof(ngx_http_script_copy_code_t)
          + NGX_HMUX_STRING_LEN(src[i].key.len) + sizeof(uintptr_t) - 1)
        & ~(sizeof(uintptr_t) - 1);

      copy = ngx_array_push_n(conf->headers_set, size);
      if (copy == NULL) {
        return NGX_ERROR;
      }

      copy->code = ngx_http_script_copy_code;
      copy->len = NGX_HMUX_STRING_LEN(src[i].key.len);

      p = (u_char *) copy + sizeof(ngx_http_script_copy_code_t);
      NGX_HMUX_WRITE_STR(p, HMUX_HEADER, src[i].key);

      copy = ngx_array_push_n(conf->headers_set,
          sizeof(ngx_http_script_code_pt));
      if (copy == NULL) {
        return NGX_ERROR;
      }

      copy->code = ngx_hmux_value_cmd_code;

      ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

      sc.cf = cf;
      sc.source = &src[i].value;
      sc.flushes = &conf->flushes;
      sc.lengths = &conf->headers_set_len;
      sc.values = &conf->headers_set;

      if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_ERROR;
      }
    }

    code = ngx_array_push_n(conf->headers_set_len, sizeof(uintptr_t));
    if (code == NULL) {
      return NGX_ERROR;
    }

    *code = (uintptr_t) NULL;

    code = ngx_array_push_n(conf->headers_set, sizeof(uintptr_t));
    if (code == NULL) {
      return NGX_ERROR;
    }

    *code = (uintptr_t) NULL;
  }

  code = ngx_array_push_n(conf->headers_set_len, sizeof(uintptr_t));
  if (code == NULL) {
    return NGX_ERROR;
  }

  *code = (uintptr_t) NULL;


  hash.hash = &conf->headers_set_hash;
  hash.key = ngx_hash_key_lc;
  hash.max_size = conf->headers_hash_max_size;
  hash.bucket_size = conf->headers_hash_bucket_size;
  hash.name = "hmux_headers_hash";
  hash.pool = cf->pool;
  hash.temp_pool = NULL;

  return ngx_hash_init(&hash, headers_names.elts, headers_names.nelts);
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
