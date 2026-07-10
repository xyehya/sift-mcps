-- P1 first-party RAG: allow a tightly-scoped in-process gateway transport.
-- The registry remains DB-authoritative, but this transport has no child
-- process, network URL, command, or credential reference.  The gateway code
-- separately allow-lists the sole supported backend name (forensic-rag-mcp).

alter table app.mcp_backends
  drop constraint if exists mcp_backends_transport_check;

alter table app.mcp_backends
  add constraint mcp_backends_transport_check
  check (transport in ('stdio', 'http', 'gateway'));

alter table app.mcp_backends
  drop constraint if exists mcp_backends_connection_transport_shape_check;

alter table app.mcp_backends
  add constraint mcp_backends_connection_transport_shape_check
  check (
    (
      transport = 'stdio'
      and connection ? 'command'
      and not (connection ? 'url')
    )
    or (
      transport = 'http'
      and connection ? 'url'
      and not (connection ? 'command')
    )
    or (
      transport = 'gateway'
      and connection->>'type' = 'gateway'
      and connection ? 'manifest_path'
      and not (connection ? 'command')
      and not (connection ? 'url')
      and not (connection ? 'env_refs')
      and not (connection ? 'bearer_token_env')
      and not (connection ? 'tls_cert_env')
    )
  );
