
#include "ngx_http_cds_url_signing_module.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <ngx_md5.h>

// ---------------------------------------------------------------------------------------------------------------------
ngx_str_t g_algo_sha1 = ngx_string("sha1");


#define MAX_INT_LEN (sizeof("18446744073709551616")-1)
#define MAX_IP_LEN (sizeof("[0000:0000:0000:0000:0000:0000:0000:0000]")-1)
#define SIG_PARAMS_MAX_LEN (sizeof("?SIGV=2&IS=0&ET=&CIP=&KO=&KN=&US=")-1 + MAX_IP_LEN + 3*MAX_INT_LEN)


// ---------------------------------------------------------------------------------------------------------------------
static void *
ngx_http_cds_create_loc_conf(ngx_conf_t *cf);

static char *
ngx_http_cds_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char *
ngx_conf_cds_set_keys_array_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_http_cds_ctx_t *
ngx_cds_create_ctx(ngx_http_request_t *r);

static ngx_int_t
ngx_http_cds_add_variables(ngx_conf_t *cf);

static ngx_int_t
ngx_http_cds_validate_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t
ngx_http_cds_signed_url_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t
ngx_http_cds_validate_is_exp_ok_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t
ngx_http_cds_validate_is_ip_ok_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t
ngx_http_cds_signed_path_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t
ngx_http_cds_signed_token_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t
ngx_cds_find_key(ngx_array_t *keys,
    ngx_int_t ko, ngx_int_t kn, ngx_str_t *key);

static ngx_int_t
ngx_http_cds_sign_msg_hmac(ngx_http_request_t *r,
    ngx_str_t *algorithm, ngx_str_t *key,
    ngx_str_t *msg_to_sign, ngx_str_t * sig_result);

static ngx_int_t
ngx_http_cds_sign_msg_md5(ngx_http_request_t *r,
    ngx_str_t *key, ngx_str_t *msg_to_sign, ngx_str_t * sig_result);

static ngx_int_t
ngx_cds_parse_url_for_signer(ngx_str_t *url, ngx_str_t *scheme,
    ngx_str_t *host, ngx_str_t *path, ngx_str_t *args);

static ngx_int_t
ngx_cds_strip_port(ngx_str_t* host);

static u_char *
ngx_http_cds_parse_arg(u_char *start, u_char *end,
    u_char *name, size_t len, ngx_str_t *value);

static u_char *
ngx_http_cds_parse_arg_as_int(u_char *start, u_char *end,
    u_char *name, size_t len, ngx_int_t *value);

static ngx_inline ngx_int_t
ngx_cds_is_lstr_equal(ngx_str_t *s1, ngx_str_t *s2);


// ---------------------------------------------------------------------------------------------------------------------
static ngx_conf_enum_t  ngx_http_cds_sig_vers[] = {
    { ngx_string("0"), NGX_CDS_SIG_VER_0 },
    { ngx_string("1"), NGX_CDS_SIG_VER_1 },
    { ngx_string("2"), NGX_CDS_SIG_VER_2 },
    { ngx_null_string, 0 }
};

// ---------------------------------------------------------------------------------------------------------------------
static ngx_command_t  ngx_http_cds_commands[] = {

    // Common
    // -----------------

   { ngx_string("cds_exclude_domain"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_cds_loc_conf_t, is_exclude_domain),
     NULL },

   { ngx_string("cds_key"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
     ngx_conf_cds_set_keys_array_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_cds_loc_conf_t, keys),
     NULL },

    // Validation config
    // -----------------

   { ngx_string("cds_validate_expiration"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_cds_loc_conf_t, validate_conf.is_validate_expiration),
     NULL },

   { ngx_string("cds_validate_client_ip"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_cds_loc_conf_t, validate_conf.is_validate_ip),
     NULL },

   { ngx_string("cds_validate_client_ip_to_ignore"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_cds_loc_conf_t, validate_conf.client_ip_to_ignore),
     NULL },

   { ngx_string("cds_validate_host_override"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_http_set_complex_value_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_cds_loc_conf_t, validate_conf.host_override),
     NULL },

    // Signing config
    // -----------------
   { ngx_string("cds_sign_url"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_http_set_complex_value_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_cds_loc_conf_t, sign_conf.url_to_sign),
     NULL },

   { ngx_string("cds_sign_client_ip"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_http_set_complex_value_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_cds_loc_conf_t, sign_conf.client_ip),
     NULL },

   { ngx_string("cds_sign_mimic_request"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_cds_loc_conf_t, sign_conf.is_copy_original),
     NULL },

   { ngx_string("cds_sign_version"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_enum_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_cds_loc_conf_t, sign_conf.sig_ver),
     &ngx_http_cds_sig_vers },

   { ngx_string("cds_sign_key_owner"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_cds_loc_conf_t, sign_conf.signing_ko),
     NULL },

   { ngx_string("cds_sign_key_number"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_cds_loc_conf_t, sign_conf.signing_kn),
     NULL },

   { ngx_string("cds_sign_expiration_sec"),
     NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_sec_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_cds_loc_conf_t, sign_conf.expiration_delta_sec),
     NULL },

     ngx_null_command
};

// ---------------------------------------------------------------------------------------------------------------------
static ngx_http_module_t  ngx_http_cds_module_ctx = {
    ngx_http_cds_add_variables,            /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_cds_create_loc_conf,          /* create location configuration */
    ngx_http_cds_merge_loc_conf            /* merge location configuration */
};

// ---------------------------------------------------------------------------------------------------------------------
ngx_module_t  ngx_http_cds_url_signing_module = {
    NGX_MODULE_V1,
    &ngx_http_cds_module_ctx,              /* module context */
    ngx_http_cds_commands,                 /* module directives */
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

// ---------------------------------------------------------------------------------------------------------------------
static ngx_http_variable_t ngx_http_cds_vars[] = {

    { ngx_string("cds_validate"), NULL,
      ngx_http_cds_validate_variable, 0, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("cds_signed_url"), NULL,
      ngx_http_cds_signed_url_variable, 0, NGX_HTTP_VAR_CHANGEABLE, 0 },

    // Note: Below variables are available only after calling cds_signed_url or cds_validate

    { ngx_string("cds_validate_is_exp_ok"), NULL,
      ngx_http_cds_validate_is_exp_ok_variable, 0, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("cds_validate_is_ip_ok"), NULL,
      ngx_http_cds_validate_is_ip_ok_variable, 0, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("cds_signed_path"), NULL,
      ngx_http_cds_signed_path_variable, 0, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("cds_signed_token"), NULL,
      ngx_http_cds_signed_token_variable, 0, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0}
};

// ---------------------------------------------------------------------------------------------------------------------
static void *
ngx_http_cds_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_cds_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cds_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->keys = NGX_CONF_UNSET_PTR;
    conf->is_exclude_domain = NGX_CONF_UNSET;

    conf->validate_conf.is_validate_expiration = NGX_CONF_UNSET;
    conf->validate_conf.is_validate_ip = NGX_CONF_UNSET;
    ngx_str_null(&conf->validate_conf.client_ip_to_ignore);
    conf->validate_conf.host_override = NULL;

    conf->sign_conf.url_to_sign = NULL;
    conf->sign_conf.client_ip = NULL;
    conf->sign_conf.sig_ver = NGX_CONF_UNSET;
    conf->sign_conf.expiration_delta_sec = NGX_CONF_UNSET;
    conf->sign_conf.signing_ko = NGX_CONF_UNSET;
    conf->sign_conf.signing_kn = NGX_CONF_UNSET;
    conf->sign_conf.is_copy_original = NGX_CONF_UNSET;

    return conf;
}

// ---------------------------------------------------------------------------------------------------------------------
static char *
ngx_http_cds_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_cds_loc_conf_t *prev = parent;
    ngx_http_cds_loc_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->keys, prev->keys, NULL);

    ngx_conf_merge_value(conf->is_exclude_domain,
                         prev->is_exclude_domain, 0);

    ngx_conf_merge_value(conf->validate_conf.is_validate_expiration,
                         prev->validate_conf.is_validate_expiration, 1);

    ngx_conf_merge_value(conf->validate_conf.is_validate_ip,
                         prev->validate_conf.is_validate_ip, 1);

    ngx_conf_merge_str_value(conf->validate_conf.client_ip_to_ignore,
                             prev->validate_conf.client_ip_to_ignore, "");

    if (conf->validate_conf.host_override == NULL) {
        conf->validate_conf.host_override = prev->validate_conf.host_override;
        if (conf->validate_conf.host_override == NULL) {
            conf->validate_conf.host_override = ngx_pcalloc(cf->pool, sizeof(ngx_http_complex_value_t));
            ngx_str_set(&conf->validate_conf.host_override->value, "");
        }
    }

    ngx_conf_merge_value(conf->sign_conf.sig_ver,
                         prev->sign_conf.sig_ver, 2);

    ngx_conf_merge_value(conf->sign_conf.expiration_delta_sec,
                         prev->sign_conf.expiration_delta_sec, 120);

    ngx_conf_merge_value(conf->sign_conf.signing_ko,
                         prev->sign_conf.signing_ko, 0);

    ngx_conf_merge_value(conf->sign_conf.signing_kn,
                         prev->sign_conf.signing_kn, 0);

    ngx_conf_merge_value(conf->sign_conf.is_copy_original,
                         prev->sign_conf.is_copy_original, 1);

    if (conf->sign_conf.url_to_sign == NULL) {
        conf->sign_conf.url_to_sign = prev->sign_conf.url_to_sign;
    }

    if (conf->sign_conf.client_ip == NULL) {
        conf->sign_conf.client_ip = prev->sign_conf.client_ip;
    }

    return NGX_CONF_OK;
}

// ---------------------------------------------------------------------------------------------------------------------
static char *
ngx_conf_cds_set_keys_array_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cds_loc_conf_t        *lcf = conf;
    ngx_http_cds_conf_key_t        *key_info;
    ngx_str_t                      *value;

    if (lcf->keys == NGX_CONF_UNSET_PTR) {
        lcf->keys = ngx_array_create(cf->pool, 4, sizeof(ngx_http_cds_conf_key_t));
        if (lcf->keys == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    key_info = ngx_array_push(lcf->keys);
    if (key_info == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    key_info->ko = ngx_atoi(value[1].data, value[1].len);
    key_info->kn = ngx_atoi(value[2].data, value[2].len);
    key_info->key = value[3];

    if (key_info->ko < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "cds_key first param must be a number (key owner)");
        return NGX_CONF_ERROR;
    }

    if (key_info->kn < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "cds_key second param must be a number (key number)");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

// ---------------------------------------------------------------------------------------------------------------------
static ngx_http_cds_ctx_t *
ngx_cds_create_ctx(ngx_http_request_t *r)
{
    ngx_http_cds_ctx_t         *ctx;
    ngx_http_cds_loc_conf_t    *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_cds_url_signing_module);
    if (conf == NULL) {
        return NULL;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_cds_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_cds_url_signing_module);

    ctx->conf = conf;
    return ctx;
}

// ---------------------------------------------------------------------------------------------------------------------
static ngx_int_t
ngx_http_cds_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_cds_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

// ---------------------------------------------------------------------------------------------------------------------
static ngx_int_t
ngx_http_cds_validate_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_int_t                           rc, len;
    u_char                             *p, *last;
    ngx_buf_t                          *b;
    ngx_str_t                           value, url_to_sign, client_sig, sig_result, key;
    ngx_http_cds_ctx_t                 *ctx;
    ngx_http_cds_validate_conf_t       *v_conf;
    ngx_http_cds_validate_results_t    *v_results;

    // No args - missing directives
    if (r->args.len == 0) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "cds validate: failed - no uri args");
       goto not_found;
    }

    // We take config from context, to allow external modules to set different configuration than location
    ctx = ngx_http_get_module_ctx(r, ngx_http_cds_url_signing_module);
    if (ctx == NULL) {
        ctx = ngx_cds_create_ctx(r);
        if (ctx == NULL) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                          "cds validate: create ctx failed");
            goto not_found;
        }
    }

    v_conf = &ctx->conf->validate_conf;
    v_results = &ctx->validate_results;

    if ((ctx->conf->keys == NULL) || (v_conf->host_override == NULL)) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "cds validate: failed - missing configuration");
        goto not_found;
    }

    p = r->args.data;
    last = p + r->args.len;

    // Expected format: ["SIGV=" + getVer + "&"] + "IS=0" + "&ET=" + expires + "&CIP=" + clientIp + "&KO=" + keyOwner + "&KN=" + keyNum + "&US=";

    // Find Anchor to work with. It's "IS=0" which should always exist.
    p = ngx_http_cds_parse_arg(p, last, (u_char *)"IS", sizeof("IS")-1, &value);
    if (p == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "cds validate: failed - no arg IS");
        goto not_found;
    }

    // Get sig_ver if exists
    if ((p - (sizeof("SIGV=1&")-1) >= r->args.data) &&
        (ngx_strncmp(p-(sizeof("SIGV=1&")-1), "SIGV=", sizeof("SIGV=")-1) == 0)) {

        v_results->sig_ver = ngx_atoi(p-(sizeof("1&")-1), 1);

        if ((v_results->sig_ver < 0) || (v_results->sig_ver > 2)) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                          "cds validate: invalid value for SIG %d", v_results->sig_ver);
            goto not_found;
        }
    }

    // Expiration
    p = ngx_http_cds_parse_arg_as_int(p, last, (u_char *)"ET", sizeof("ET")-1, &v_results->expiration_epoc_sec);
    if (v_results->expiration_epoc_sec == NGX_ERROR) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "cds validate: failed - no arg ET");
        goto not_found;
    }

    // Client IP
    p = ngx_http_cds_parse_arg(p, last, (u_char *)"CIP", sizeof("CIP")-1, &v_results->client_ip);
    if (p == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "cds validate: failed - no arg CIP");
        goto not_found;
    }

    // Key Owner
    p = ngx_http_cds_parse_arg_as_int(p, last, (u_char *)"KO", sizeof("KO")-1, &v_results->signing_ko);
    if (v_results->signing_ko == NGX_ERROR) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                              "cds validate: failed - no arg KO");
        goto not_found;
    }

    // Key Number
    p = ngx_http_cds_parse_arg_as_int(p, last, (u_char *)"KN", sizeof("KN")-1, &v_results->signing_kn);
    if (v_results->signing_kn == NGX_ERROR) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "cds validate: failed - no arg KN");
        goto not_found;
    }

    // Client Sig
    p = ngx_http_cds_parse_arg(p, last, (u_char *)"US", sizeof("US")-1, &client_sig);
    if (p == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "cds validate: failed - no arg US");
        goto not_found;
    }

    // Set p to end of string to sign
    p += sizeof("US=")-1;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "cds validate: extracted info: sig_ver=%d, exp=%d, cip=%V, ko=%d, kn=%d, sig=%V",
                  v_results->sig_ver, v_results->expiration_epoc_sec, &v_results->client_ip,
                  v_results->signing_ko, v_results->signing_kn, &client_sig);

    if (ctx->conf->is_exclude_domain == 1) {

        // Sign only on path - no need to copy anything
        url_to_sign.data = r->unparsed_uri.data;
        url_to_sign.len = p - r->unparsed_uri.data;

    } else {

        // Need to build string to sign on

        // Which host?
        if (v_conf->host_override->value.len) {
            value = v_conf->host_override->value;
        } else if (r->headers_in.host != NULL) {
            value = r->headers_in.host->value;
        } else {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                          "cds validate: failed - no Host in request");
            goto not_found;
        }

        len = sizeof("https://")-1 + value.len + r->unparsed_uri.len;
        b = ngx_create_temp_buf(r->pool, len);
        if (b == NULL) {
            return NGX_ERROR;
        }

        // Scheme
        if (v_results->sig_ver != 2) {
            b->last = ngx_copy(b->last, "http", sizeof("http")-1);
            if (r->connection->ssl) {
                *b->last++ = 's';
            }
        }

        *b->last++ = ':'; *b->last++ = '/'; *b->last++ = '/';

        // Domain
        ngx_cds_strip_port(&value);
        b->last = ngx_copy(b->last, value.data, value.len);

        // Url up to "US="
        b->last = ngx_copy(b->last, r->unparsed_uri.data, p - r->unparsed_uri.data);

        url_to_sign.data = b->start;
        url_to_sign.len = b->last - b->start;
    }

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "cds validate: string for signing: %V", &url_to_sign);

    // Get key
    rc = ngx_cds_find_key(ctx->conf->keys, v_results->signing_ko, v_results->signing_kn, &key);
    if (rc != NGX_OK) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "cds validate: failed - no matching key for ko=%d, kn=%d",
                      v_results->signing_ko, v_results->signing_kn);
        goto not_found;
    }

    // Sign - md5 vs. sha1
    if (v_results->sig_ver == 0) {
        rc = ngx_http_cds_sign_msg_md5(r, &key, &url_to_sign, &sig_result);
    } else {
        rc = ngx_http_cds_sign_msg_hmac(r, &g_algo_sha1, &key, &url_to_sign, &sig_result);
    }

    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    // Validate signature
    v_results->is_equal = ngx_cds_is_lstr_equal(&client_sig, &sig_result);

    // Validate expiration
    v_results->is_expiration_ok = v_conf->is_validate_expiration ?
            ((ngx_current_msec/1000) <= (ngx_uint_t)v_results->expiration_epoc_sec) : 1;

    // Validate client ip (if enabled and ip doesn't match ip to ignore)
    if (v_conf->is_validate_ip &&
        ((v_conf->client_ip_to_ignore.len == 0) ||
         (ngx_cds_is_lstr_equal(&v_results->client_ip, &v_conf->client_ip_to_ignore) == 0))) {
        v_results->is_client_ip_ok = ngx_cds_is_lstr_equal(&v_results->client_ip, &r->connection->addr_text);
    } else {
        v_results->is_client_ip_ok = 1;
    }

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "cds validate: sign results: [sig_ok=%d, ip_ok=%d, exp_ok=%d], client's=%V, ours=%V",
                  v_results->is_equal, v_results->is_client_ip_ok,
                  v_results->is_expiration_ok, &client_sig, &sig_result);

    if (v_results->is_equal == 0) {
        goto not_found;
    }

    v->data = (u_char *) ((v_results->is_client_ip_ok && v_results->is_expiration_ok) ? "1" : "0");
    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}

// ---------------------------------------------------------------------------------------------------------------------
static ngx_int_t
ngx_http_cds_signed_url_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_int_t                           rc, len;
    ngx_int_t                           sig_ver, ko, kn, exp_sec;
    ngx_buf_t                          *b;
    ngx_str_t                           value, url_part_sig_info, key;
    ngx_str_t                           scheme, host, path, uri_params;
    ngx_http_cds_ctx_t                 *ctx;
    ngx_http_cds_sign_conf_t           *s_conf;
    ngx_http_cds_sign_results_t        *s_results;

    // We take config from context, to allow external modules to set different configuration than location
    ctx = ngx_http_get_module_ctx(r, ngx_http_cds_url_signing_module);
    if (ctx == NULL) {
        ctx = ngx_cds_create_ctx(r);
        if (ctx == NULL) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                          "cds sign: create ctx failed ");
            goto not_found;
        }
    }

    s_conf = &ctx->conf->sign_conf;
    s_results = &ctx->sign_results;

    if ((ctx->conf->keys == NULL) || (s_conf->url_to_sign == NULL) || (s_conf->client_ip == NULL)) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "cds sign: failed - no keys / url /client ip");
        goto not_found;
    }

    if (s_conf->is_copy_original && ctx->validate_results.is_equal) {
        sig_ver = ctx->validate_results.sig_ver;
        ko = ctx->validate_results.signing_ko;
        kn = ctx->validate_results.signing_kn;
        exp_sec = ctx->validate_results.expiration_epoc_sec - (ngx_current_msec/1000);
    } else {
        sig_ver = s_conf->sig_ver;
        ko = s_conf->signing_ko;
        kn = s_conf->signing_kn;
        exp_sec = s_conf->expiration_delta_sec;
    }

    // Start with parsing the url, see it matches out expectations
    if (ngx_http_complex_value(r, s_conf->url_to_sign, &value) != NGX_OK) {
        return NGX_ERROR;
    }

    rc = ngx_cds_parse_url_for_signer(&value, &scheme, &host, &path, &uri_params);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "cds sign: failed to parse url for signing \"%V\" - expected to be full url with scheme and host.",
                      &value);
        goto not_found;
    }

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "cds sign: parsed url to sign: scheme='%V', host='%V', path='%V', args='%V', full_url='%V'",
                  &scheme, &host, &path, &uri_params, &value);

    // Get key
    rc = ngx_cds_find_key(ctx->conf->keys, ko, kn, &key);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "cds sign: failed to get key for signing with ko=%d, kn=%d", &ko, kn);
        goto not_found;
    }

    // Build the url for signing
    len = scheme.len + (sizeof("://")-1) + host.len + path.len + 1/* ? */ + uri_params.len + SIG_PARAMS_MAX_LEN;
    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    // Scheme + domain
    if (ctx->conf->is_exclude_domain == 0) {

        // Scheme
        if (sig_ver != 2) {
            b->last = ngx_copy(b->last, scheme.data, scheme.len);
        }

        *b->last++ = ':'; *b->last++ = '/'; *b->last++ = '/';

        // Domain (no port)
        value = host;
        ngx_cds_strip_port(&value);
        b->last = ngx_copy(b->last, value.data, value.len);
    }

    // Remember for final url
    url_part_sig_info.data = b->last;

    // Rest of the url
    b->last = ngx_copy(b->last, path.data, path.len);
    *b->last++ = '?';
    if (uri_params.len) {
        b->last = ngx_copy(b->last, uri_params.data, uri_params.len);
        *b->last++ = '&';
    }

    // url signing uri params
    if (sig_ver > 0) {
        b->last = ngx_sprintf(b->last, "SIGV=%d&", sig_ver);
    }

    if (ngx_http_complex_value(r, s_conf->client_ip, &value) != NGX_OK) {
        return NGX_ERROR;
    }

    b->last = ngx_sprintf(b->last, "IS=0&ET=%d&CIP=%V&KO=%d&KN=%d&US=",
                          (exp_sec + ngx_current_msec/1000),
                          &value, ko, kn);

    // url to sign on
    s_results->url_for_signing.data = b->start;
    s_results->url_for_signing.len = b->last - b->start;

    // Remember for final url
    url_part_sig_info.len = b->last - url_part_sig_info.data;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "cds sign: string for signing: %V", &s_results->url_for_signing);

    // Sign - md5 vs. sha1
    if (sig_ver == 0) {
        rc = ngx_http_cds_sign_msg_md5(r, &key, &s_results->url_for_signing, &s_results->signature);
    } else {
        rc = ngx_http_cds_sign_msg_hmac(r, &g_algo_sha1, &key, &s_results->url_for_signing, &s_results->signature);
    }

    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    // Build signed url
    len = scheme.len + (sizeof("://")-1) + host.len + url_part_sig_info.len + s_results->signature.len;
    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    // Scheme
    b->last = ngx_copy(b->last, scheme.data, scheme.len);
    *b->last++ = ':'; *b->last++ = '/'; *b->last++ = '/';

    // Domain
    b->last = ngx_copy(b->last, host.data, host.len);

    s_results->signed_path.data = b->last; // Only path part

    // Path with sig info
    b->last = ngx_copy(b->last, url_part_sig_info.data, url_part_sig_info.len);

    // signature
    b->last = ngx_copy(b->last, s_results->signature.data, s_results->signature.len);

    // Full signed url
    s_results->signed_url.data = b->start;
    s_results->signed_url.len = b->last - b->start;

    // Only the path part
    s_results->signed_path.len = b->last - s_results->signed_path.data;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "cds sign: signed url: %V", &s_results->signed_url);

    v->data = b->start;
    v->len = b->last - b->start;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}

// ---------------------------------------------------------------------------------------------------------------------
static ngx_int_t
ngx_http_cds_validate_is_exp_ok_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_cds_ctx_t                 *ctx;

    //Note: This variable is only available after getting "cds_validate".

    ctx = ngx_http_get_module_ctx(r, ngx_http_cds_url_signing_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = (u_char *) (ctx->validate_results.is_expiration_ok ? "1" : "0");
    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

// ---------------------------------------------------------------------------------------------------------------------
static ngx_int_t
ngx_http_cds_validate_is_ip_ok_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_cds_ctx_t                 *ctx;

    //Note: This variable is only available after getting "cds_validate".

    ctx = ngx_http_get_module_ctx(r, ngx_http_cds_url_signing_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = (u_char *) (ctx->validate_results.is_client_ip_ok ? "1" : "0");
    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;

}

// ---------------------------------------------------------------------------------------------------------------------
static ngx_int_t
ngx_http_cds_signed_path_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_cds_ctx_t                 *ctx;

    //Note: This variable is only available after getting "cds_signed_url".

    ctx = ngx_http_get_module_ctx(r, ngx_http_cds_url_signing_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->sign_results.signed_path.data;
    v->len = ctx->sign_results.signed_path.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

// ---------------------------------------------------------------------------------------------------------------------
static ngx_int_t
ngx_http_cds_signed_token_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_cds_ctx_t                 *ctx;

    //Note: This variable is only available after getting "cds_signed_url".

    ctx = ngx_http_get_module_ctx(r, ngx_http_cds_url_signing_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->sign_results.signature.data;
    v->len = ctx->sign_results.signature.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

// ---------------------------------------------------------------------------------------------------------------------
static ngx_int_t
ngx_cds_find_key(ngx_array_t *keys, ngx_int_t ko, ngx_int_t kn, ngx_str_t *key)
{
    ngx_uint_t                          i;
    ngx_http_cds_conf_key_t            *keys_set;

    if (keys == NULL) {
        return NGX_DECLINED;
    }

    // Get key
    keys_set = keys->elts;
    for (i = 0; i < keys->nelts; ++i) {
        if ((keys_set[i].ko == ko) && (keys_set[i].kn == kn)) {
            *key = keys_set[i].key;
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}

// ---------------------------------------------------------------------------------------------------------------------
static ngx_int_t
ngx_http_cds_sign_msg_hmac(ngx_http_request_t *r,
    ngx_str_t *algorithm, ngx_str_t *key, ngx_str_t *msg_to_sign, ngx_str_t * sig_result)
{
    ngx_str_t                   hmac;
    const EVP_MD               *evp_md;
    u_char                      hmac_buf[EVP_MAX_MD_SIZE];
    u_int                       hmac_size;

    evp_md = EVP_get_digestbyname((const char*)algorithm->data);
    if (evp_md == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cds: unknown cryptographic hash function \"%V\"", &algorithm);

        return NGX_ERROR;
    }

    hmac.data = hmac_buf;

    HMAC(evp_md, key->data, key->len, msg_to_sign->data, msg_to_sign->len, hmac.data, &hmac_size);
    hmac.len = hmac_size;

    sig_result->len = 2 * hmac.len;
    sig_result->data = ngx_pnalloc(r->pool, sig_result->len);
    if (sig_result->data == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(sig_result->data, hmac.data, hmac.len);

    return NGX_OK;
}

// ---------------------------------------------------------------------------------------------------------------------
static ngx_int_t
ngx_http_cds_sign_msg_md5(ngx_http_request_t *r,
    ngx_str_t *key, ngx_str_t *msg_to_sign, ngx_str_t * sig_result)
{
    ngx_str_t                     val;
    ngx_md5_t                     md5;
    u_char                        md5_buf[16];

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, key->data, key->len);
    ngx_md5_update(&md5, msg_to_sign->data, msg_to_sign->len);
    ngx_md5_final(md5_buf, &md5);

    val.len = 16;
    val.data = md5_buf;

    sig_result->len = 2 * val.len;
    sig_result->data = ngx_pnalloc(r->pool, sig_result->len);
    if (sig_result->data == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(sig_result->data, val.data, val.len);

    return NGX_OK;
}

// ---------------------------------------------------------------------------------------------------------------------
static ngx_int_t
ngx_cds_parse_url_for_signer(ngx_str_t *url, ngx_str_t *scheme,
    ngx_str_t *host, ngx_str_t *path, ngx_str_t *args)
{
    ngx_str_t       value;
    u_char         *p = url->data;
    u_char         *last = url->data + url->len;

    // Scheme
    p = ngx_strlchr(p, last, ':');
    if (p == NULL) {
        return NGX_ERROR;
    }

    scheme->data = url->data;
    scheme->len = p - url->data;

    if ((last - p < 2) || (*(++p) != '/') || (*(++p) != '/')) {
        return NGX_ERROR;
    }

    // Host
    host->data = ++p;
    p = ngx_strlchr(p, last, '/');
    if (p == NULL) {
        return NGX_ERROR;
    }

    host->len = p - host->data;

    // Path
    path->data = p;
    p = ngx_strlchr(p, last, '?');
    if (p == NULL) {
        // No args
        path->len = last - path->data;
        args->len = 0;
        return NGX_OK;
    }

    path->len = p - path->data;

    // Args
    args->data = ++p; // Skip the "?"
    args->len = last - args->data;

    // Args may contain signature params. If so trim it before them
    p = ngx_http_cds_parse_arg(p, last, (u_char *)"IS", sizeof("IS")-1, &value);

    if (p != NULL) {
        if ((p - (sizeof("SIGV=1&")-1) >= args->data) &&
            (ngx_strncmp(p-(sizeof("SIGV=1&")-1), "SIGV=", sizeof("SIGV=")-1) == 0)) {
            p -= (sizeof("SIGV=1&")-1);
        }

        if ((p > args->data) && (*(p-1) == '&'))
        {
            --p;
        }

        args->len = p - args->data;
    }

    return NGX_OK;
}

// ---------------------------------------------------------------------------------------------------------------------
static ngx_int_t
ngx_cds_strip_port(ngx_str_t* host)
{
    u_char* p = host->data;
    u_char* last = host->data + host->len;

    if (host->len <= 0) {
        return NGX_OK;
    }

    // Is it ipv6 address?
    if (p[0] == '[') {
        p = ngx_strlchr(p, last, ']');
        if (p == NULL) {
            return NGX_ERROR;
        }
    }

    // Find port delimiter (':')
    p = ngx_strlchr(p, last, ':');

    // No port found
    if (p == NULL) {
        return NGX_OK;
    }

    // Trim before port
    host->len = p - host->data;
    return NGX_OK;
}

// ---------------------------------------------------------------------------------------------------------------------
// Find "name=X" in string between end-start, sets value to point to the value (X), and returns the pointer of the
// beginning of the match (i.e. beginning of "name").
// Returns NULL if no match found
static u_char *
ngx_http_cds_parse_arg(u_char *start, u_char *end, u_char *name, size_t len, ngx_str_t *value)
{
    u_char  *p, *last;

    if (start >= end) {
        return NULL;
    }

    p = start;
    last = end;

    for ( /* void */ ; p < last; p++) {

        /* we need '=' after name, so drop one char from last */

        p = ngx_strlcasestrn(p, last - 1, name, len - 1);

        if (p == NULL) {
            return NULL;
        }

        if ((p == start || *(p - 1) == '&') && *(p + len) == '=') {

            value->data = p + len + 1;

            p = ngx_strlchr(p, last, '&');

            if (p == NULL) {
                p = end;
            }

            value->len = p - value->data;

            // begging of match key
            return (value->data - len - 1);
        }
    }

    return NULL;
}

// ---------------------------------------------------------------------------------------------------------------------
// Call ngx_http_cds_parse_arg and convert to integer
// Returns NULL if no match found, and sets value to NGX_ERROR
static u_char *
ngx_http_cds_parse_arg_as_int(u_char *start, u_char *end, u_char *name, size_t len, ngx_int_t *value)
{
    ngx_str_t str_value;
    start = ngx_http_cds_parse_arg(start, end, name, len, &str_value);

    if (start == NULL) {
        *value = NGX_ERROR;
        return NULL;
    }

    *value = ngx_atoi(str_value.data, str_value.len);
    return start;
}

// ---------------------------------------------------------------------------------------------------------------------
static ngx_inline ngx_int_t
ngx_cds_is_lstr_equal(ngx_str_t *s1, ngx_str_t *s2)
{
    return ((s1->len == s2->len) && (ngx_memcmp(s1->data, s2->data, s1->len) == 0));
}

