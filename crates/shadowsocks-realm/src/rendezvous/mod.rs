//! Rendezvous client (Phase 1): the HTTP + SSE protocol spoken with the stock
//! Go `hysteria-realm-server`.
//!
//! Submodules:
//! * [`types`]   — request/response bodies and SSE event types.
//! * [`client`]  — the `reqwest`-based HTTP client (register / heartbeat /
//!   connect / connects / delete).
//! * [`events`]  — the Server-Sent Events stream parser for `GET /events`.
//!
//! This is a scaffold; the wire types and client land in Phase 1 and are tested
//! against `testing/nat-sim/rendezvous.py`.

pub mod client;
pub mod events;
pub mod types;
