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


#include "parseable.h"

// Function prototypes - add these before cb_parseable_init
static int should_skip_namespace(struct flb_out_parseable *ctx, const char *namespace);
static int pack_event_data(msgpack_packer *pk, struct flb_log_event *log_event);
static flb_sds_t get_stream_value(struct flb_out_parseable *ctx, 
                                 struct flb_record_accessor *ra,
                                 msgpack_object *body);
static int send_http_request(struct flb_out_parseable *ctx,
                           struct flb_connection *u_conn,
                           flb_sds_t body,
                           flb_sds_t stream_value,
                           size_t *b_sent);
static void cleanup_resources(msgpack_sbuffer *sbuf,
                            struct flb_record_accessor *ra,
                            struct flb_record_accessor *ns_ra,
                            struct flb_connection *u_conn,
                            struct flb_log_event_decoder *decoder);

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

    flb_plg_info(ctx->ins, "Configured port: %d", ctx->server_port);

    ctx->upstream = flb_upstream_create(config,
                                        ctx->server_host,
                                        ctx->server_port,
                                        FLB_IO_TCP,
                                        NULL);

    if (!ctx->upstream) {
        flb_free(ctx);
        return -1;
    }

    /* Export context */
    flb_output_set_context(ins, ctx);

    return 0;
}

/* Main flush callback */
static void cb_parseable_flush(struct flb_event_chunk *event_chunk,
                             struct flb_output_flush *out_flush,
                             struct flb_input_instance *i_ins,
                             void *out_context,
                             struct flb_config *config)
{
    struct flb_out_parseable *ctx = out_context;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    struct flb_record_accessor *ra = NULL;
    struct flb_record_accessor *ns_ra = NULL;
    struct flb_http_client *client;
    struct flb_connection *u_conn;
    struct flb_upstream *u;
    flb_sds_t body;
    flb_sds_t x_p_stream_value = NULL;
    int ret;
    int i;
    size_t b_sent;
    msgpack_sbuffer sbuf;
    msgpack_packer pk;

    /* Initialize event decoder */
    flb_plg_debug(ctx->ins, "[INIT] Starting flush operation with chunk size: %zu", event_chunk->size);
    ret = flb_log_event_decoder_init(&log_decoder, (char *) event_chunk->data, event_chunk->size);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins, "[INIT] Event decoder initialization failed with code: %d", ret);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Get upstream context */
    u = ctx->upstream;
    if (!u) {
        flb_plg_error(ctx->ins, "[CONN] Upstream context is NULL");
        flb_log_event_decoder_destroy(&log_decoder);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /* Debug upstream configuration */
    flb_plg_debug(ctx->ins, "[CONN] Attempting connection to %s:%i", u->tcp_host, u->tcp_port);


    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "[CONN] Failed to get upstream connection to %s:%i", 
                     u->tcp_host, u->tcp_port);
        flb_log_event_decoder_destroy(&log_decoder);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Create record accessors only if needed */
    if (ctx->stream && strcmp(ctx->stream, "$NAMESPACE") == 0) {
        ra = flb_ra_create("$kubernetes['namespace_name']", FLB_TRUE);
        if (!ra) {
            flb_plg_error(ctx->ins, "[RA] Failed to create namespace record accessor");
            flb_upstream_conn_release(u_conn);
            flb_log_event_decoder_destroy(&log_decoder);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
    }

    if (ctx->exclude_namespaces) {
        ns_ra = flb_ra_create("$kubernetes['namespace_name']", FLB_TRUE);
        if (!ns_ra) {
            flb_plg_error(ctx->ins, "[RA] Failed to create exclusion namespace record accessor");
            if (ra) flb_ra_destroy(ra);
            flb_upstream_conn_release(u_conn);
            flb_log_event_decoder_destroy(&log_decoder);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
    }

    /* Process events */
    flb_plg_debug(ctx->ins, "[PROC] Starting event processing");
    while (flb_log_event_decoder_next(&log_decoder, &log_event) == FLB_EVENT_DECODER_SUCCESS) {
        /* Check namespace exclusions */
        if (ns_ra && ctx->exclude_namespaces) {
            flb_sds_t current_ns = flb_ra_translate(ns_ra, NULL, -1, *log_event.body, NULL);
            if (current_ns) {
                if (should_skip_namespace(ctx, current_ns)) {
                    flb_sds_destroy(current_ns);
                    continue;
                }
                flb_sds_destroy(current_ns);
            }
        }

        /* Prepare message pack buffer */
        msgpack_sbuffer_init(&sbuf);
        msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

        /* Pack data */
        ret = pack_event_data(&pk, &log_event);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "[PACK] Failed to pack event data");
            cleanup_resources(&sbuf, ra, ns_ra, u_conn, &log_decoder);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        /* Convert to JSON */
        body = flb_msgpack_raw_to_json_sds(sbuf.data, sbuf.size);
        if (!body) {
            flb_plg_error(ctx->ins, "[JSON] Failed to convert msgpack to JSON");
            cleanup_resources(&sbuf, ra, ns_ra, u_conn, &log_decoder);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        /* Get stream value */
        x_p_stream_value = get_stream_value(ctx, ra, log_event.body);
        if (!x_p_stream_value) {
            flb_plg_error(ctx->ins, "[STREAM] Failed to get stream value");
            flb_sds_destroy(body);
            cleanup_resources(&sbuf, ra, ns_ra, u_conn, &log_decoder);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        /* Create and send HTTP request */
        ret = send_http_request(ctx, u_conn, body, x_p_stream_value, &b_sent);
        
        /* Cleanup iteration resources */
        flb_sds_destroy(body);
        flb_sds_destroy(x_p_stream_value);
        msgpack_sbuffer_destroy(&sbuf);

        if (ret != FLB_OK) {
            cleanup_resources(NULL, ra, ns_ra, u_conn, &log_decoder);
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }

    /* Final cleanup */
    cleanup_resources(NULL, ra, ns_ra, u_conn, &log_decoder);
    FLB_OUTPUT_RETURN(FLB_OK);
}

/* Helper functions */
static inline int should_skip_namespace(struct flb_out_parseable *ctx, const char *namespace) {
    struct cfl_list *head;
    struct flb_slist_entry *entry;

    cfl_list_foreach(head, ctx->exclude_namespaces) {
        entry = cfl_list_entry(head, struct flb_slist_entry, _head);
        if (strcmp(namespace, entry->str) == 0) {
            flb_plg_debug(ctx->ins, "[NS] Skipping excluded namespace: %s", namespace);
            return 1;
        }
    }
    return 0;
}

static int pack_event_data(msgpack_packer *pk, struct flb_log_event *log_event) {
    int i;
    
    /* Pack the map with one additional field for source */
    msgpack_pack_map(pk, log_event->body->via.map.size + 1);

    /* Pack original map content */
    for (i = 0; i < log_event->body->via.map.size; i++) {
        msgpack_pack_object(pk, log_event->body->via.map.ptr[i].key);
        msgpack_pack_object(pk, log_event->body->via.map.ptr[i].val);
    }

    /* Add source field */
    msgpack_pack_str_with_body(pk, "source", 6);
    msgpack_pack_str_with_body(pk, "fluent bit parseable plugin", 25);

    return 0;
}

static flb_sds_t get_stream_value(struct flb_out_parseable *ctx, 
                                struct flb_record_accessor *ra,
                                msgpack_object *body) {
    if (ra) {
        return flb_ra_translate(ra, NULL, -1, *body, NULL);
    }
    else if (ctx->stream) {
        return flb_sds_create(ctx->stream);
    }
    return NULL;
}

static int send_http_request(struct flb_out_parseable *ctx,
                           struct flb_connection *u_conn,
                           flb_sds_t body,
                           flb_sds_t stream_value,
                           size_t *b_sent) {
    struct flb_http_client *client;
    int ret;

    flb_plg_debug(ctx->ins, "[HTTP] Creating client for request, body size: %zu", flb_sds_len(body));
    
    client = flb_http_client(u_conn,
                           FLB_HTTP_POST, "/api/v1/ingest",
                           body, flb_sds_len(body),
                           ctx->server_host, ctx->server_port,
                           NULL, 0);
    if (!client) {
        flb_plg_error(ctx->ins, "[HTTP] Failed to create HTTP client");
        return FLB_ERROR;
    }

    /* Set headers */
    flb_http_add_header(client, "Content-Type", 12, "application/json", 16);
    flb_http_add_header(client, "X-P-Stream", 10, stream_value, flb_sds_len(stream_value));
    flb_http_basic_auth(client, ctx->username, ctx->password);

    /* Perform request */
    ret = flb_http_do(client, b_sent);
    flb_plg_debug(ctx->ins, "[HTTP] Request sent - Status: %i, Bytes sent: %zu", 
                 client->resp.status, *b_sent);

    /* Check response */
    if (ret != 0 || client->resp.status != 200) {
        flb_plg_error(ctx->ins, "[HTTP] Request failed - Status: %i, Error: %s",
                     client->resp.status, client->resp.payload);
        flb_http_client_destroy(client);
        return FLB_ERROR;
    }

    flb_http_client_destroy(client);
    return FLB_OK;
}

static void cleanup_resources(msgpack_sbuffer *sbuf,
                            struct flb_record_accessor *ra,
                            struct flb_record_accessor *ns_ra,
                            struct flb_connection *u_conn,
                            struct flb_log_event_decoder *decoder) {
    if (sbuf) {
        msgpack_sbuffer_destroy(sbuf);
    }
    if (ra) {
        flb_ra_destroy(ra);
    }
    if (ns_ra) {
        flb_ra_destroy(ns_ra);
    }
    if (u_conn) {
        flb_upstream_conn_release(u_conn);
    }
    if (decoder) {
        flb_log_event_decoder_destroy(decoder);
    }
}

static int cb_parseable_exit(void *data, struct flb_config *config)
{
    struct flb_out_parseable *ctx = data;

    if (!ctx) {
        return 0;
    }

    if (ctx->exclude_namespaces) {
        flb_slist_destroy((struct mk_list *)ctx->exclude_namespaces);
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
    "The stream name to send logs to. Using $NAMESPACE will dynamically create a namespace."
    },
    {
     FLB_CONFIG_MAP_INT, "server_port", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, server_port),
    "The port on the host to send logs to."
    },
    {
     FLB_CONFIG_MAP_CLIST, "Exclude_Namespaces", NULL,
     0, FLB_TRUE, offsetof(struct flb_out_parseable, exclude_namespaces),
    "A space-separated list of Kubernetes namespaces to exclude from log forwarding."
    },
    /* EOF */
    {0}
};

/* Plugin registration */
struct flb_output_plugin out_parseable_plugin = {
    .name         = "parseable",
    .description  = "Sends events to a HTTP server",
    .cb_init      = cb_parseable_init,
    .cb_flush     = cb_parseable_flush,
    .cb_exit      = cb_parseable_exit,
    .flags        = 0,
    .event_type   = FLB_OUTPUT_LOGS,
    .config_map   = config_map
};
