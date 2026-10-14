#pragma once

// qdecode - router.hpp
// ---------------------------------------------------------------------------
// Template-ID dispatch with branch-prediction hints. This is the hot routing
// path: after the 8-byte header is decoded, `dispatch()` examines `templateId`
// and routes to the matching schema decoder. [[likely]]/[[unlikely]] hint the
// CPU so the pipeline does not stall on the dominant message types.

#include <cstdint>

#include "qdecode/message_header.hpp"
#include "qdecode/schema.hpp"
#include "qdecode/byte_order.hpp"

namespace qdecode {

/// Result of routing one SBE message. Carries the decoded header plus a view
/// positioned at the root block. Zero allocation; the caller reads fields from
/// the appropriate template decoder on demand.
struct RouteResult {
    MessageHeaderWire header{};
    BufferView root{};       ///< bytes immediately after the header
    bool valid = false;      ///< header fit within the message buffer
    bool schema_match = false;  ///< templateId/schemaId recognized
};

/// Route `msg` (the bytes of exactly one SBE message) to a recognized template.
/// This performs no copying; it merely validates the header and positions the
/// root view. Template-specific decoding is a separate call.
[[nodiscard]] inline RouteResult route(BufferView msg) noexcept {
    RouteResult out;
    MessageHeaderDecoder h(msg);
    if (!h.decode(out.header)) [[unlikely]] {
        out.valid = false;
        return out;
    }
    out.valid = true;
    out.root = h.root();

    const std::uint16_t tmpl = out.header.templateId;
    // CME MDP 3.0 dominant message: MDIncrementalRefreshBook32 / Book46
    if (tmpl == schema::kTmplIncrementalRefreshBook32) [[likely]] {
        out.schema_match = true;
    } else if (tmpl == schema::kTmplIncrementalRefreshBook46) [[likely]] {
        out.schema_match = true;
    } else if (tmpl == schema::kTmplIncrementalRefreshTrade32) [[unlikely]] {
        out.schema_match = true;
    } else if (tmpl == schema::kTmplSecurityDefinition) [[unlikely]] {
        out.schema_match = true;
    } else if (tmpl == schema::kTmplIncrementalRefreshOrderBook32) [[unlikely]] {
        out.schema_match = true;
    } else if (tmpl == schema::kTmplInstrumentDefinitionFuture55) [[unlikely]] {
        out.schema_match = true;
    } else if (tmpl == schema::kTmplInstrumentDefinitionFuture54 ||
               tmpl == schema::kTmplInstrumentDefinitionSpread56) [[unlikely]] {
        out.schema_match = true;
    } else if (tmpl == schema::kTmplAdminHeartbeat) [[unlikely]] {
        out.schema_match = true;
    } else {
        out.schema_match = false;  // unknown template, still decodable header
    }
    return out;
}

}  // namespace qdecode