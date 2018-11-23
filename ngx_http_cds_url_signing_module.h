
#ifndef NGX_HTTP_CDS_URL_SIGNING_MODULE_H_
#define NGX_HTTP_CDS_URL_SIGNING_MODULE_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>

// ---------------------------------------------------------------------------------------------------------------------
extern ngx_module_t  ngx_http_cds_url_signing_module;

// ---------------------------------------------------------------------------------------------------------------------
#define NGX_CDS_SIG_VER_0 0
#define NGX_CDS_SIG_VER_1 1
#define NGX_CDS_SIG_VER_2 2

// ---------------------------------------------------------------------------------------------------------------------
typedef struct {
    ngx_int_t                           ko;
    ngx_int_t                           kn;
    ngx_str_t                           key;
} ngx_http_cds_conf_key_t;

// ---------------------------------------------------------------------------------------------------------------------
typedef struct {
    ngx_int_t                           is_validate_ip;
    ngx_int_t                           is_validate_expiration;
    ngx_str_t                           client_ip_to_ignore;
    ngx_http_complex_value_t           *host_override;
} ngx_http_cds_validate_conf_t;

// ---------------------------------------------------------------------------------------------------------------------
typedef struct {
    ngx_int_t                           sig_ver;
    ngx_int_t                           expiration_epoc_sec;
    ngx_int_t                           signing_ko;
    ngx_int_t                           signing_kn;
    ngx_str_t                           client_ip;
    unsigned                            is_equal:1;
    unsigned                            is_client_ip_ok:1;
    unsigned                            is_expiration_ok:1;
} ngx_http_cds_validate_results_t;

// ---------------------------------------------------------------------------------------------------------------------
typedef struct {
    ngx_http_complex_value_t           *url_to_sign; // Always including scheme and host
    ngx_http_complex_value_t           *client_ip;
    ngx_int_t                           sig_ver;
    ngx_int_t                           expiration_delta_sec;
    ngx_int_t                           signing_ko;
    ngx_int_t                           signing_kn;
    ngx_int_t                           is_copy_original;
} ngx_http_cds_sign_conf_t;

// ---------------------------------------------------------------------------------------------------------------------
typedef struct {
    ngx_str_t                           url_for_signing;
    ngx_str_t                           signature;
    ngx_str_t                           signed_url;
    ngx_str_t                           signed_path;

} ngx_http_cds_sign_results_t;

// ---------------------------------------------------------------------------------------------------------------------
typedef struct {
    ngx_array_t                        *keys;
    ngx_int_t                           is_exclude_domain;
    ngx_http_cds_validate_conf_t        validate_conf;
    ngx_http_cds_sign_conf_t            sign_conf;
} ngx_http_cds_loc_conf_t;

// ---------------------------------------------------------------------------------------------------------------------
typedef struct {
    ngx_http_cds_loc_conf_t            *conf;
    ngx_http_cds_validate_results_t     validate_results;
    ngx_http_cds_sign_results_t         sign_results;
} ngx_http_cds_ctx_t;


#endif /* NGX_HTTP_CDS_URL_SIGNING_MODULE_H_ */
