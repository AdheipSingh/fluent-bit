#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_event.h>
#include <fluent-bit/flb_record_accessor.h>

#include <msgpack.h>
#include "parseable.h"

static int http_post(struct flb_out_parseable *ctx,
                     const void *body, size_t body_len,
                     const char *tag, int tag_len,
                     char **headers)
{
    int ret;
    int out_ret = FLB_OK;
    int compressed = FLB_FALSE;
    size_t b_sent;
    void *payload_buf = NULL;
    size_t payload_size = 0;
    struct flb_upstream *u;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    flb_sds_t signature = NULL;

    /* Get upstream context and connection */
    u = ctx->upstream;
    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "no upstream connections available to %s:%i",
                      u->tcp_host, u->tcp_port);
        return FLB_RETRY;
    }

    /* Map payload */
    payload_buf = (void *) body;
    payload_size = body_len;

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_POST, "/api/v1/ingest",
                        payload_buf, payload_size,
                        ctx->server_host, ctx->server_port,
                        NULL, 0);

    if (!c) {
        flb_plg_error(ctx->ins, "Failed to create HTTP client");
        flb_upstream_conn_release(u_conn);
        return FLB_ERROR;
    }

    /* Set headers */
    flb_http_add_header(c, "Content-Type", 12, "application/json", 16);
    
    /* Add stream header if available */
    if (ctx->stream) {
        flb_http_add_header(c, "X-P-Stream", 10, ctx->stream, strlen(ctx->stream));
    }

    /* Basic Auth */
    if (ctx->username && ctx->password) {
        flb_http_basic_auth(c, ctx->username, ctx->password);
    }

    /* Perform HTTP request */
    ret = flb_http_do(c, &b_sent);
    if (ret == 0) {
        if (c->resp.status < 200 || c->resp.status > 205) {
            flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i",
                          ctx->server_host, ctx->server_port,
                          c->resp.status);
            
            if (c->resp.status >= 400 && c->resp.status < 500 &&
                c->resp.status != 429 && c->resp.status != 408) {
                out_ret = FLB_ERROR;
            }
            else {
                out_ret = FLB_RETRY;
            }
        }
        else {
            flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i",
                         ctx->server_host, ctx->server_port,
                         c->resp.status);
        }
    }
    else {
        flb_plg_error(ctx->ins, "could not flush records to %s:%i (http_do=%i)",
                      ctx->server_host, ctx->server_port, ret);
        out_ret = FLB_RETRY;
    }

    /* Cleanup */
    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    return out_ret;
}

static int cb_parseable_init(struct flb_output_instance *ins,
                           struct flb_config *config, void *data)
{
    int ret;
    struct flb_out_parseable *ctx = NULL;
    (void) ins;
    (void) config;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_out_parseable));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;

    /* Read in config values */
    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Create upstream context */
    ctx->upstream = flb_upstream_create(config,
                                        ctx->server_host,
                                        ctx->server_port,
                                        FLB_IO_TCP | FLB_IO_ASYNC,
                                        NULL);
    if (!ctx->upstream) {
        flb_free(ctx);
        return -1;
    }

    ctx->upstream->base.net.connect_timeout = 600;
    ctx->upstream->base.net.accept_timeout = 600;
    ctx->upstream->base.net.keepalive_idle_timeout = 600;
    
    /* Add plugin-specific configuration */
    flb_output_set_property(ins, "flush", "2");             // Flush interval
    flb_output_set_property(ins, "Buffer_Chunk_Size", "512K"); // Chunk size
    flb_output_set_property(ins, "Buffer_Max_Size", "2M");     // Max buffer size
    flb_output_set_property(ins, "Mem_Buf_Limit", "20MB");     // Memory buffer limit
    /* Export context */
    flb_output_set_context(ins, ctx);

    return 0;
}

static int send_log_entry(struct flb_out_parseable *ctx, 
                           const char *body, 
                           size_t body_len)
{
    char *headers[3] = {
        "Content-Type", "application/json",
        NULL  // Sentinel to mark end of headers
    };

    /* Add stream header if configured */
    char stream_header[256];
    if (ctx->stream) {
        snprintf(stream_header, sizeof(stream_header), "X-P-Stream");
        headers[2] = stream_header;
        headers[3] = ctx->stream;
        headers[4] = NULL;
    }

    return http_post(ctx, body, body_len, "parseable_tag", 13, headers);
}

static void cb_parseable_flush(struct flb_event_chunk *event_chunk,
                               struct flb_output_flush *out_flush,
                               struct flb_input_instance *i_ins,
                               void *out_context,
                               struct flb_config *config)
{
    msgpack_unpacked result;
    size_t off = 0;
    struct flb_out_parseable *ctx = out_context;
    (void) config;
    struct flb_time tmp;
    msgpack_object *p;
    msgpack_sbuffer sbuf;
    msgpack_packer pk;
    flb_sds_t body;
    int ret;

    /* Skip processing if no upstream or invalid context */
    if (!ctx || !ctx->upstream) {
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result,
                                event_chunk->data,
                                event_chunk->size, &off) == MSGPACK_UNPACK_SUCCESS) {
        flb_time_pop_from_msgpack(&tmp, &result, &p);

        /* Only process map type logs */
        if (p->type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        /* Initialize msgpack buffer for packing */
        msgpack_sbuffer_init(&sbuf);
        msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

        /* Pack a map with original size + 1 for source field */
        msgpack_pack_map(&pk, p->via.map.size + 1);

        /* Pack original key-value pairs */
        for (int i = 0; i < p->via.map.size; i++) {
            msgpack_pack_object(&pk, p->via.map.ptr[i].key);
            msgpack_pack_object(&pk, p->via.map.ptr[i].val);
        }

        /* Append source field */
        msgpack_pack_str_with_body(&pk, "source", 6);
        msgpack_pack_str_with_body(&pk, "fluent bit parseable plugin", 25);

        /* Convert msgpack to JSON */
        body = flb_msgpack_raw_to_json_sds(sbuf.data, sbuf.size);
        msgpack_sbuffer_destroy(&sbuf);

        if (!body) {
            flb_plg_error(ctx->ins, "Failed to convert msgpack to JSON");
            continue;
        }

        /* Send log entry */
        ret = send_log_entry(ctx, body, flb_sds_len(body));
        flb_sds_destroy(body);

        if (ret != FLB_OK) {
            flb_plg_error(ctx->ins, "Failed to send log entry");
            msgpack_unpacked_destroy(&result);
            FLB_OUTPUT_RETURN(ret);
        }
    }
    msgpack_unpacked_destroy(&result);

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_parseable_exit(void *data, struct flb_config *config)
{
    struct flb_out_parseable *ctx = data;

    if (!ctx) {
        return 0;
    }

    /* Free up resources */
    if (ctx->upstream) {
        flb_upstream_destroy(ctx->upstream);
    }
    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "server_host", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, server_host),
    "The host of the server to send logs to."
    },
    {
     FLB_CONFIG_MAP_STR, "username", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, username),
    "The parseable server username."
    },
    {
     FLB_CONFIG_MAP_STR, "password", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, password),
    "The parseable server password."
    },
    {
     FLB_CONFIG_MAP_STR, "stream", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, stream),
    "The stream name to send logs to."
    },
    {
     FLB_CONFIG_MAP_INT, "server_port", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, server_port),
    "The port on the host to send logs to."
    },
    /* EOF */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_parseable_plugin = {
    .name         = "parseable",
    .description  = "Sends events to a Parseable HTTP server",
    .cb_init      = cb_parseable_init,
    .cb_flush     = cb_parseable_flush,
    .cb_exit      = cb_parseable_exit,
    .flags        = 0,
    .event_type   = FLB_OUTPUT_LOGS,
    .config_map   = config_map
};