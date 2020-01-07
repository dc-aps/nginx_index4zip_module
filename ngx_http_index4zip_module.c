/*
 * Copyright (C) datacanvas.com
 * Author lixf@zetyun.com
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t       name;
    time_t          mtime;
    off_t           size;
    uint32_t        crc32;
} ngx_http_index4zip_entry_t;


typedef struct {
    ngx_flag_t     enable;
    ngx_flag_t     extract_crc32;
} ngx_http_index4zip_loc_conf_t;

#define NGX_HTTP_INDEX4ZIP_PREALLOCATE  64

#define NGX_HTTP_INDEX4ZIP_PATH_MAX_LEN  1024
#define NGX_HTTP_INDEX4ZIP_READ_BUF_LEN  4096

static ngx_int_t
ngx_http_index4zip_extract_crc32(ngx_http_request_t *r, ngx_str_t *file_path, 
    uint32_t *crc32);

static ngx_int_t
ngx_http_index4zip_get_entries(ngx_http_request_t *r, ngx_str_t *root, ngx_str_t *path, 
    ngx_pool_t *pool, ngx_array_t *entries, ngx_flag_t  extract_crc32);

static ngx_buf_t *ngx_http_index4zip_output(ngx_http_request_t *r,
    ngx_array_t *entries, ngx_flag_t  extract_crc32);

static int ngx_libc_cdecl ngx_http_index4zip_cmp_entries(const void *one,
    const void *two);
static ngx_int_t ngx_http_index4zip_error(ngx_http_request_t *r,
    ngx_dir_t *dir, ngx_str_t *name);

static ngx_int_t ngx_http_index4zip_init(ngx_conf_t *cf);
static void *ngx_http_index4zip_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_index4zip_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_command_t  ngx_http_index4zip_commands[] = {
    { ngx_string("index4zip"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_index4zip_loc_conf_t, enable),
      NULL },

    { ngx_string("index4zip_extract_crc32"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_index4zip_loc_conf_t, extract_crc32),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_index4zip_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_index4zip_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_index4zip_create_loc_conf,    /* create location configuration */
    ngx_http_index4zip_merge_loc_conf      /* merge location configuration */
};


ngx_module_t  ngx_http_index4zip_module = {
    NGX_MODULE_V1,
    &ngx_http_index4zip_module_ctx,        /* module context */
    ngx_http_index4zip_commands,           /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_index4zip_extract_crc32(ngx_http_request_t *r, ngx_str_t *file_path, uint32_t *crc32)
{
    ngx_file_t  file;
    u_char      buf[NGX_HTTP_INDEX4ZIP_READ_BUF_LEN];
    ssize_t     n;
    ngx_err_t   err;
    ngx_int_t   rc = NGX_OK;

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = *file_path;
    file.log = r->connection->log;

    file.fd = ngx_open_file(file_path->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE) {
        err = ngx_errno;
        if (err != NGX_ENOENT) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, err,
                          ngx_open_file_n " \"%V\" failed", file_path);
        }
        return NGX_ERROR;
    }
    
    ngx_crc32_init(*crc32);
    do{
        n = ngx_read_file(&file, buf, NGX_HTTP_INDEX4ZIP_READ_BUF_LEN, file.offset);
        if (n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                               ngx_read_file_n " \"%V\" failed", file_path);
            rc = NGX_ERROR;
            break;
        }
        if(n > 0){
            ngx_crc32_update(crc32, buf, n);
        }
    } while (n > 0);
    ngx_crc32_final(*crc32);

    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_close_file_n " \"%V\" failed", file_path);
    }

    return rc;
}


static ngx_int_t
ngx_http_index4zip_get_entries(ngx_http_request_t *r, ngx_str_t *root, ngx_str_t *path, 
    ngx_pool_t *pool, ngx_array_t *entries, ngx_flag_t  extract_crc32)
{
    ngx_http_index4zip_entry_t  *entry;
    u_char      tmp_path_buf[NGX_HTTP_INDEX4ZIP_PATH_MAX_LEN];
    ngx_dir_t   dir;
    ngx_str_t   tmp_path;
    size_t      name_len;
    ngx_err_t   err;

    ngx_str_null(&tmp_path);
    tmp_path.data = tmp_path_buf;

#define put_dir_to_tmp_path \
            ngx_cpystrn(tmp_path.data, path->data, path->len + 1); \
            tmp_path.data[path->len] = '/'; \
            ngx_cpystrn(tmp_path.data + path->len + 1, ngx_de_name(&dir), name_len + 1); \
            tmp_path.len = path->len + name_len + 1

    if (path->len < root->len) {
        return NGX_ERROR;
    }

    if (ngx_open_dir(path, &dir) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "http index4zip open dir failed: \"%V\".", path);
        return NGX_ERROR;
    }

    for ( ;; ) {
        ngx_set_errno(0);

        if (ngx_read_dir(&dir) != NGX_OK) {
            err = ngx_errno;

            if (err != NGX_ENOMOREFILES) {
                ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
                    ngx_read_dir_n " \"%V\" failed", path);
                return ngx_http_index4zip_error(r, &dir, path);
            }

            break;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
            "http index4zip file: \"%s\"", ngx_de_name(&dir));

        if (ngx_de_name(&dir)[0] == '.') {
            continue;
        }

        name_len = ngx_de_namelen(&dir);

        if (!dir.valid_info){
            put_dir_to_tmp_path;

            if (ngx_de_info(tmp_path.data, &dir) == NGX_FILE_ERROR) {
                err = ngx_errno;

                if (err != NGX_ENOENT && err != NGX_ELOOP) {
                    ngx_log_error(NGX_LOG_CRIT, r->connection->log, err,
                        ngx_de_info_n " \"%s\" failed", tmp_path.data);
                    if (err == NGX_EACCES) {
                        continue;
                    }
                    return ngx_http_index4zip_error(r, &dir, path);
                }

                if (ngx_de_link_info(tmp_path.data, &dir) == NGX_FILE_ERROR) {
                    ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                        ngx_de_link_info_n " \"%s\" failed", tmp_path.data);
                    return ngx_http_index4zip_error(r, &dir, path);
                }
            }
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "http index4zip dir fixed: \"%V\"", &tmp_path);
        }

        if (ngx_de_is_dir(&dir)) {
            put_dir_to_tmp_path;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "http index4zip enter sub-path: \"%V\"", &tmp_path);
            if ( ngx_http_index4zip_get_entries(r, root, &tmp_path, pool, entries, extract_crc32)
                    != NGX_OK ){
                return ngx_http_index4zip_error(r, &dir, path);
            }
        } else if (ngx_de_is_file(&dir)) {
            entry = ngx_array_push(entries);
            if (entry == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                    "http index4zip alloc entry failed: \"%V\"", path);
                return ngx_http_index4zip_error(r, &dir, path);
            }

            entry->name.data = ngx_pnalloc(pool, path->len - root->len + name_len + 1 + 1);
            if (entry->name.data == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                    "http index4zip alloc failed: \"%V\" [entry name]", path);
                return ngx_http_index4zip_error(r, &dir, path);
            }
            
            if (path->len > root->len) {
                ngx_cpystrn(entry->name.data, path->data + root->len + 1, path->len - root->len);
                entry->name.data[path->len - root->len - 1] = '/';
//            } else {
//                ngx_cpystrn(entry->name.data , ngx_de_name(&dir), name_len + 1);
//                entry->name.len = name_len;
            }
            ngx_cpystrn(entry->name.data + path->len - root->len , ngx_de_name(&dir), name_len + 1);
            entry->name.len = path->len - root->len + name_len;

            entry->mtime = ngx_de_mtime(&dir);
            entry->size = ngx_de_size(&dir);
            if (extract_crc32) {
                put_dir_to_tmp_path;

                if (ngx_http_index4zip_extract_crc32(r, &tmp_path, &entry->crc32) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                        "http index4zip extract crc32 failed: \"%V\" [entry name]", path);
                    return ngx_http_index4zip_error(r, &dir, path);
                }
            }
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
                "http index4zip find entry: \"%V\"", &entry->name);
        } else {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                ngx_read_dir_n " \"%V\" failed, nor dir and neither file", path);
        }
    }

    if (ngx_close_dir(&dir) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno, 
            ngx_close_dir_n " \"%V\" failed", path);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_index4zip_handler(ngx_http_request_t *r)
{
    u_char                         *last;
    size_t                          root_len;
    ngx_err_t                       err;
    ngx_buf_t                      *b;
    ngx_int_t                       rc;
    ngx_str_t                       path;
    ngx_dir_t                       dir;
    ngx_uint_t                      level;
    ngx_pool_t                     *pool;
    ngx_chain_t                     out;
    ngx_array_t                     entries;
    ngx_http_index4zip_loc_conf_t  *cf;

    if (r->uri.data[r->uri.len - 1] != '/') {
        return NGX_DECLINED;
    }

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }

    cf = ngx_http_get_module_loc_conf(r, ngx_http_index4zip_module);

    if (!cf->enable) {
        return NGX_DECLINED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    last = ngx_http_map_uri_to_path(r, &path, &root_len, NGX_HTTP_INDEX4ZIP_PREALLOCATE);
    if (last == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                       "map_uri_to_path \"%V\" failed", &r->uri);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    path.len = last - path.data;
    if (path.len > 1) {
        path.len--;
    }
    path.data[path.len] = '\0';

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
        "http index4zip: \"%s\"", path.data);

    if (ngx_open_dir(&path, &dir) == NGX_ERROR) {
        err = ngx_errno;

        if (err == NGX_ENOENT
            || err == NGX_ENOTDIR
            || err == NGX_ENAMETOOLONG)
        {
            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;
        } else if (err == NGX_EACCES) {
            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
        } else {
            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_error(level, r->connection->log, err,
                      ngx_open_dir_n " \"%s\" failed", path.data);
        return rc;
    }

    if (ngx_close_dir(&dir) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_close_dir_n " \"%V\" failed", &path);
    }
    
    // send headers
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type_len = r->headers_out.content_type.len;
    r->headers_out.content_type_lowcase = NULL;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        if (ngx_close_dir(&dir) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                          ngx_close_dir_n " \"%V\" failed", &path);
        }
        return rc;
    }

    // initlize entries

#if (NGX_SUPPRESS_WARN)
    /* MSVC thinks 'entries' may be used without having been initialized */
    ngx_memzero(&entries, sizeof(ngx_array_t));
#endif

    pool = r->pool;

    if (ngx_array_init(&entries, pool, 40, sizeof(ngx_http_index4zip_entry_t)) != NGX_OK){
        return ngx_http_index4zip_error(r, &dir, &path);
    }

    // get entries
    if ( ngx_http_index4zip_get_entries(r, &path, &path, pool, &entries, cf->extract_crc32) != NGX_OK ){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
            "http index4zip get entries failed: \"%V\"", &path);
        return NGX_ERROR;
    }

    if (entries.nelts > 1) {
        ngx_qsort(entries.elts, (size_t) entries.nelts,
                  sizeof(ngx_http_index4zip_entry_t), ngx_http_index4zip_cmp_entries);
    }

    // output entries
    b = ngx_http_index4zip_output(r, &entries, cf->extract_crc32);
    if (b == NULL) {
        return NGX_ERROR;
    }

    if (r == r->main) {
        b->last_buf = 1;
    }

    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, 
        "http index4zip success for: \"%V\", %d", &path, entries.nelts);

    return ngx_http_output_filter(r, &out);
}


static ngx_buf_t *
ngx_http_index4zip_output(ngx_http_request_t *r, ngx_array_t *entries, ngx_flag_t  extract_crc32)
{
    size_t                          len, entry_len, name_len, uri_len, crc32_len;
    size_t                          uri_escape, name_escape;
    ngx_buf_t                      *b;
    ngx_uint_t                      i, utf8;
    ngx_http_index4zip_entry_t     *entry;

    if (r->headers_out.charset.len == 5
        && ngx_strncasecmp(r->headers_out.charset.data, (u_char *) "utf-8", 5)== 0) {
        utf8 = 1;
    } else {
        utf8 = 0;
    }

    crc32_len = extract_crc32 ? 8 : 1;
    uri_escape = ngx_escape_uri(NULL, r->uri.data, r->uri.len, NGX_ESCAPE_URI);
    
    len = 0;
    entry = entries->elts;
    for (i = 0; i < entries->nelts; i++) {
        if (utf8) {
            name_len = ngx_utf8_length(entry[i].name.data, entry[i].name.len);
            uri_len = ngx_utf8_length(r->uri.data, r->uri.len);
        } else {
            name_len = entry[i].name.len;
            uri_len = r->uri.len;
        }
        name_escape = ngx_escape_uri(NULL, entry[i].name.data, entry[i].name.len, NGX_ESCAPE_URI);

        entry_len = 2 * name_len + uri_len + (uri_escape + name_escape) * 2 
                  + crc32_len /* crc size */
                  + 20 /* the file size */
                  + 4;  /* 3 spaces + '\n' */
        len += entry_len;

        if (len > NGX_MAX_SIZE_T_VALUE) {
            return NULL;
        }
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NULL;
    }

    for (i = 0; i < entries->nelts; i++) {
        /*
        if (extract_crc32) {
            b->last = ngx_sprintf(b->last, "%08xd %l %V%V %V\n",
                entry[i].crc32, entry[i].size, &r->uri, &entry[i].name, &entry[i].name);
        } else {
            b->last = ngx_sprintf(b->last, "- %l %V%V %V\n", 
                entry[i].size, &r->uri, &entry[i].name, &entry[i].name);
        }
        */
        //output: crc32 & size
        if (extract_crc32) {
            b->last = ngx_sprintf(b->last, "%08xd %l ", entry[i].crc32, entry[i].size);
        } else {
            b->last = ngx_sprintf(b->last, "- %l ", entry[i].size);
        }
        //output: location
        //name_escape = utf8 ? 0: ngx_escape_uri(NULL, entry[i].name.data, entry[i].name.len, NGX_ESCAPE_URI_COMPONENT);
        name_escape = ngx_escape_uri(NULL, entry[i].name.data, entry[i].name.len, NGX_ESCAPE_URI);
        if( name_escape || uri_escape ){
            b->last = (u_char *)ngx_escape_uri(b->last, r->uri.data, r->uri.len, NGX_ESCAPE_URI);
            b->last = (u_char *)ngx_escape_uri(b->last, entry[i].name.data, entry[i].name.len, NGX_ESCAPE_URI);
        } else {
            b->last = ngx_sprintf(b->last, "%V%V", &r->uri, &entry[i].name);
        }
        //output: entry name
        b->last = ngx_sprintf(b->last, " %V\n", &entry[i].name);        
    }

    return b;
}


static int ngx_libc_cdecl
ngx_http_index4zip_cmp_entries(const void *one, const void *two)
{
    ngx_http_index4zip_entry_t *first = (ngx_http_index4zip_entry_t *) one;
    ngx_http_index4zip_entry_t *second = (ngx_http_index4zip_entry_t *) two;

    return (int) ngx_strcmp(first->name.data, second->name.data);
}


static ngx_int_t
ngx_http_index4zip_error(ngx_http_request_t *r, ngx_dir_t *dir, ngx_str_t *name)
{
    if (ngx_close_dir(dir) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                      ngx_close_dir_n " \"%V\" failed", name);
    }

    return r->header_sent ? NGX_ERROR : NGX_HTTP_INTERNAL_SERVER_ERROR;
}


static void *
ngx_http_index4zip_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_index4zip_loc_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_index4zip_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->extract_crc32 = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_index4zip_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_index4zip_loc_conf_t *prev = parent;
    ngx_http_index4zip_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->extract_crc32, prev->extract_crc32, 1);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_index4zip_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_index4zip_handler;

    return NGX_OK;
}
