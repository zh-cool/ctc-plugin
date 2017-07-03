#include "config.h"

#include <stdio.h>
#include <epan/packet.h>

#define FOO_PORT 1234

static int proto_foo = -1;


static int
dissect_foo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FOOT");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    fprintf(stderr, "Entry func:%s\n", __func__);
    return tvb_captured_length(tvb);
}

void
proto_register_foo(void)
{
        proto_foo = proto_register_protocol (
                        "FOO Protocol", /* name       */
                        "FOO",      /* short name */
                        "foo"       /* abbrev     */
                        );
    fprintf(stderr, "Entry func:%s\n", __func__);
}

void
proto_reg_handoff_foo(void)
{
    static dissector_handle_t foo_handle;

    foo_handle = create_dissector_handle(dissect_foo, proto_foo);
    dissector_add_uint("udp.port", FOO_PORT, foo_handle);
}


