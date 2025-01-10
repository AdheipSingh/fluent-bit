#ifndef FLB_OUT_PARSEABLE_H
#define FLB_OUT_PARSEABLE_H

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_sds.h>

struct flb_out_parseable {
    flb_sds_t server_host;
    int server_port;
    flb_sds_t username;
    flb_sds_t password;
    flb_sds_t stream;
    struct cfl_list *exclude_namespaces;  // Use mk_list for namespace exclusion
    struct flb_upstream *upstream;
    struct flb_output_instance *ins;
};

#endif