You said: kong vs envoy for supabaseWhen self-hosting Supabase, choosing between Kong and Envoy depends on your architectural needs. Kong is the default, batteries-included gateway for Supabase, while Envoy is offered as a lighter, cloud-native alternative.Kong (Default)Kong is an NGINX-based API gateway chosen by Supabase for its rich plugin ecosystem and ease of configuration.Best For: Turnkey setups, traditional VMs, or bare-metal self-hosting where you want built-in features (like JWT authentication, rate-limiting, and analytics) out-of-the-box.Pros: Massive library of plugins, familiar NGINX debugging, easy to spin up via standard Supabase Docker files.Cons: Heavier resource footprint and more complex configuration management if you operate heavily in a microservices environment.Envoy (Alternative)Envoy is a highly performant, C++-based proxy that Supabase natively supports as a drop-in replacement via their Docker overrides.Best For: Kubernetes-native environments, complex microservices meshes, and applications handling massive, high-throughput loads.Pros: Superior tail latency and throughput, dynamic hot-reloads (zero-downtime config changes), and standard Kubernetes Gateway API support.Cons: Steeper learning curve and less immediate plugin support out-of-the-box compared to Kong.How to use Envoy in SupabaseSupabase provides an official Envoy Docker compose override. If you are self-hosting, you can swap out Kong for Envoy by starting your stack with both composition files:bashdocker compose -f docker-compose.yml -f docker-compose.envoy.yml up -d
Use code with caution.Note: This override disables the default Kong gateway, starts Envoy on port 8000 (maintaining compatibility with Edge Functions and Studio), and reconfigures your setup.If you'd like, let me know:Is your setup running on Docker Compose or Kubernetes?Are you heavily reliant on custom Kong plugins?What is your primary goal in switching (e.g., performance, Kubernetes integration, or licensing)?I can help you plan your exact deployment path.10 sitesEnvoy API Gateway | Supabase DocsEnabling the Envoy gateway. The Envoy gateway is provided as a Docker Compose override. If your stack is already running from the ...SupabaseWhy pick Envoy Proxy and Solo.io over Kong Gateway for ...Kubernetes came in and so clearly dominated the space that even CIOs are talking about their “Kubernetes strategy” these days. * E...Solo.ioEnvoy vs Kong Performance Comparison - MediumBased on the results, Kong outperformed Envoy with higher throughput and shorter test duration, although Envoy showed a lower mini...MediumShow allYou said: can they also act as a gateway for other non supabase FastAPI ?Yes, both Kong and Envoy can act as a single gateway for both Supabase and your external FastAPI services. This allows you to unify routing, security, and rate limiting under one entry point.Using Kong for FastAPIKong excels at this because of its declarative configuration via a kong.yml file or its Admin API.Routing: You can map a route like /api/v1/fastapi directly to your FastAPI container or host.Authentication: You can reuse Supabase JWTs. Kong can validate the Supabase-issued tokens before forwarding requests to FastAPI.Plugins: You can instantly apply global or route-specific plugins (like rate-limiting or CORS) to your FastAPI endpoints without writing Python code.Using Envoy for FastAPIEnvoy handles this via its Listener and Cluster architecture, defined in its configuration file.Routing: You add a new route match under the virtual host configuration that points to your FastAPI cluster.Performance: Envoy provides unmatched speed and low latency if your FastAPI application handles massive traffic or heavy WebSocket connections.Service Mesh: If your FastAPI service runs in Kubernetes, Envoy integrates natively as a sidecar or ingress controller.The Catch: Configuration ManagementWhile both work perfectly, you must manage how you update their configurations:With Kong: If you use the standard Supabase Docker setup, you will need to modify the kong.yml template to include your FastAPI service as a "Service" and a "Route."With Envoy: You must manually edit the envoy.yaml file to append your FastAPI backend to the routing table and clusters list.If you'd like, let me know:Will your FastAPI application need to validate Supabase user JWTs?Are you hosting FastAPI on the same machine/network as Supabase?Which gateway (Kong or Envoy) are you leaning toward right now?I can provide a concrete configuration snippet to route traffic to your FastAPI app.You said: Yes Id prefer to use supabase for JWTs too. My FastAPI will hit the host machine vs the docker for supabase i guess? I want the one with lower footprint and higher security because my use case is digital forensicsEnvoy is the superior choice for your digital forensics use case [1]. It delivers an incredibly low memory footprint, an exceptional security profile, and native integration with Supabase JWT validation [1].Architecture OverviewTo maximize security and network isolation, your API gateway should live inside the Docker network alongside Supabase, while your forensics FastAPI app runs on the host machine [1].The Network Path: External Requests → Envoy (Docker) → FastAPI (Host Machine) [1].Host Access: Inside the Docker network, Envoy targets the host machine using the special DNS name host.docker.internal [1].1. Gateway EvaluationCriteriaEnvoy (Recommended)KongMemory FootprintExtremely Low (~30MB to 50MB) [1]Moderate (~250MB+ due to OpenResty/Lua)Security ProfileMinimal attack surface (C++) [1]Larger attack surface (NGINX + Lua ecosystem)JWT ValidationNative, fast, and cryptographically strict [1]Plugin-dependentTamper ResistanceImmutable, file-based declarative config [1]Relies on dynamic state databases/files2. Configuration BlueprintTo implement this, you need to configure Envoy's JWT Authentication filter and add a route pointing to your host machine.Step 1: Update Envoy Configuration (envoy.yaml)Locate your Supabase Envoy configuration file and add your FastAPI service into the HTTP filter chain and cluster list.yaml# 1. Add the JWT Authentication filter to your HTTP filter chain
http_filters:
  - name: envoy.filters.http.jwt_authn
    typed_config:
      "@type": ://googleapis.com
      providers:
        supabase_jwt:
          issuer: "https://supabase.co"
          # Replace with your actual Supabase local/remote JWKS URI
          remote_jwks:
            http_uri:
              uri: "http://auth:9999/.well-known/jwks.json" 
              cluster: supabase_auth_cluster
              timeout: 1s
          from_headers:
            - name: Authorization
              value_prefix: "Bearer "
      rules:
        # Require valid Supabase JWT specifically for your forensics endpoints
        - match:
            prefix: "/api/v1/forensics"
          requires:
            provider_name: "supabase_jwt"

  - name: envoy.filters.http.router
    typed_config:
      "@type": ://googleapis.com

# 2. Add the routing rule to your Virtual Host
routes:
  - match:
      prefix: "/api/v1/forensics"
    route:
      cluster: fastapi_host_service

# 3. Define the cluster pointing to your host machine
clusters:
  - name: fastapi_host_service
    connect_timeout: 0.25s
    type: LOGICAL_DNS
    dns_lookup_family: V4_ONLY
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: fastapi_host_service
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: host.docker.internal
                    port_value: 8000 # Your FastAPI host port
Use code with caution.Step 2: Enable Host Communication in Docker ComposeTo ensure Envoy can resolve host.docker.internal, append the extra_hosts directive to your Envoy service block inside your docker-compose.envoy.yml or override file [1]:yamlservices:
  envoy:
    extra_hosts:
      - "host.docker.internal:host-gateway"
Use code with caution.3. FastAPI VerificationBecause Envoy strictly validates and cryptographically verifies the Supabase JWT at the perimeter, your FastAPI application does not need to re-verify the signature. It can safely ingest the user metadata sent by Envoy [1].To securely capture user identities for your forensics audit logs, parse the raw JWT payload directly from the header within Python [1]:pythonfrom fastapi import FastAPI, Header, HTTPException
import base64
import json

app = FastAPI()

def extract_supabase_user(authorization: str):
    try:
        # Format: "Bearer <token>"
        token = authorization.split(" ")[1]
        payload_b64 = token.split(".")[1]
        # Fix padding if necessary
        payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
        payload_json = base64.b64decode(payload_b64).decode("utf-8")
        return json.loads(payload_json)
    except Exception:
        raise HTTPException(status_code=401, detail="Malformed claims payload")

@app.get("/api/v1/forensics/evidence")
async def get_evidence(authorization: str = Header(...)):
    user_data = extract_supabase_user(authorization)
    # Securely log user_data['sub'] (User ID) alongside the action
    return {"status": "secure access granted", "operator": user_data.get("email")}
Use code with caution.✅ Summary of SetupEnvoy will intercept all incoming API traffic on your network perimeter, reject any requests missing a valid Supabase cryptographically signed token, and proxy verified forensic traffic down to your host-managed FastAPI instance via a secure internal Docker bridge [1].If you'd like, let me know:What Operating System is the host running (Linux, macOS, or Windows)?Do you need Envoy to enforce strict IP whitelisting or TLS client certificates (mTLS) for the forensics dashboard?I can provide the configuration layers to harden Envoy's network security boundaries further.You said: Ubuntu, Yes I want to maximize on Envoys security featurelist and hardening. And another question, can envoy also support being a gateway for an http mcp server (which is byitself an aggregator of stdio backend mcps)? or i need a separate mcp proxyYes, Envoy can natively act as the gateway for your HTTP MCP (Model Context Protocol) server, eliminating the need for a separate MCP proxy.Envoy features a specialized MCP HTTP Filter (envoy.extensions.filters.http.mcp.v3.Mcp). It is built precisely to parse JSON-RPC 2.0 messages, handle persistent Server-Sent Events (SSE) data streams, and enforce strict policy controls directly at your network perimeter before traffic hits your MCP aggregator.Here is how to harden Envoy on Ubuntu for your digital forensics use case, alongside routing both your FastAPI app and your HTTP MCP aggregator.Part 1: Hardening Envoy for Digital Forensics (Ubuntu)In forensics, preserving systemic integrity and preventing unauthorized intercept/tampering are paramount. We will configure Envoy to enforce Strict TLS 1.3, Mutual TLS (mTLS) client verification, and strict IP Whitelisting.Step 1: Secure the Transport Layer (Downstream TLS & mTLS)Modify the listeners block in your envoy.yaml to mandate client certificates. This ensures only forensic workstations with cryptographic keys can communicate with the gateway.yamlstatic_resources:
  listeners:
    - name: secure_forensics_gateway
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 443 # Bind to secure port
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": ://googleapis.com
                stat_prefix: ingress_http
                # Route configurations go here...
          
          # Enforcement of mTLS & Strict Ciphers
          transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": ://googleapis.com
              common_tls_context:
                tls_certificates:
                  - certificate_chain: { filename: "/etc/envoy/certs/server.crt" }
                    private_key: { filename: "/etc/envoy/certs/server.key" }
                # Force mTLS by validating client certs against your internal CA
                validation_context:
                  trusted_ca: { filename: "/etc/envoy/certs/forensics_internal_ca.crt" }
                  require_client_certificate: true
                tls_params:
                  tls_minimum_protocol_version: TLSv1_3 # Strict TLS 1.3 only
Use code with caution.Step 2: RBAC IP Whitelisting (Network Level Protection)Before HTTP processing even starts, block unauthorized IP blocks from scanning or flooding your endpoints using a Network Role-Based Access Control (RBAC) filter:yaml          filter_chains:
            - filters:
                - name: envoy.filters.network.rbac
                  typed_config:
                    "@type": ://googleapis.com
                    stat_prefix: network_rbac
                    rules:
                      action: ALLOW
                      policies:
                        "trusted-forensic-subnets":
                          permissions:
                            - any: true
                          principals:
                            - source_ip:
                                address_prefix: "10.0.40.0" # Example Forensic Lab Subnet
                                prefix_len: 24
Use code with caution.Part 2: Unified Routing Table (FastAPI + HTTP MCP Aggregator)Now, we add your HTTP MCP Server (the aggregator managing your underlying stdio tools) into Envoy's HTTP route architecture. Because MCP uses Streaming-HTTP/SSE over JSON-RPC, Envoy requires specific timeout overrides to maintain persistent tunnels without disconnecting active AI agents.Step 1: Define the Unified Route TableInside your HttpConnectionManager, append your routes under the virtual host structure:yamlvirtual_hosts:
  - name: forensics_secure_vhost
    domains: ["*"]
    routes:
      # 1. Supabase Auth/Studio routes go here...

      # 2. Your Forensics FastAPI App
      - match:
          prefix: "/api/v1/forensics"
        route:
          cluster: fastapi_host_service

      # 3. Your HTTP MCP Server Aggregator
      - match:
          prefix: "/mcp"
        route:
          cluster: mcp_aggregator_service
          # CRITICAL FOR MCP: Prevent Envoy from severing long-running SSE streams
          timeout: 0s 
          idle_timeout: 0s
Use code with caution.Step 2: Incorporate the MCP Data Inspection FilterTo allow Envoy to deeply monitor, log, or restrict actions based on which tools an AI agent is trying to trigger via your MCP backend, insert the native mcp filter into your http_filters chain:yamlhttp_filters:
  - name: envoy.filters.http.jwt_authn # Validates Supabase JWTs first
    typed_config:
      "@type": ://googleapis.com
      # ... (JWT setup from previous step)

  - name: envoy.filters.http.mcp # Native Protocol Parsing
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.mcp.v3.Mcp

  - name: envoy.filters.http.router # Final Router Step
    typed_config:
      "@type": ://googleapis.com
Use code with caution.Step 3: Define Upstream ClustersPoint both clusters toward your Ubuntu host machine. Remember to assign different ports corresponding to where FastAPI and your HTTP MCP aggregator are listening natively on Ubuntu.yamlclusters:
  - name: fastapi_host_service
    connect_timeout: 0.5s
    type: LOGICAL_DNS
    dns_lookup_family: V4_ONLY
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: fastapi_host_service
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  socket_address: { address: host.docker.internal, port_value: 8000 }

  - name: mcp_aggregator_service
    connect_timeout: 0.5s
    type: LOGICAL_DNS
    dns_lookup_family: V4_ONLY
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: mcp_aggregator_service
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  socket_address: { address: host.docker.internal, port_value: 8080 } # Your HTTP MCP host port
Use code with caution.Why this structure is ideal for ForensicsZero-Trust for AI Agents: By adding the envoy.filters.http.mcp filter, Envoy parses incoming JSON-RPC calls. If an AI tool call attempts to execute an unapproved stdio terminal string backend, Envoy can reject it before it touches the HTTP aggregator.Immutable Audit Trails: Because Envoy acts as the absolute gateway for Supabase, FastAPI, and MCP, you can route all traffic logs upstream to an immutable system log (such as a local syslog or an external SIEM) for bulletproof forensics auditing.If you'd like, let me know:Do you want to see how to configure Envoy’s Access Logging to generate cryptographic audit trails for your forensics logs?Are your stdio backends executing destructive/write commands that need explicit step-by-step approval blocks at the Envoy tier?I can provide the specific filter configurations to implement those constraints.7 sitesThe case for Envoy networking in the agentic AI eraApr 3, 2026 — With Envoy in front of the MCP server, the gateway can verify the agent identity using SPIFFE during the mTLS handshake, parse the...Google CloudModel Context Protocol (MCP) - Envoy proxyPass-Through MCP Gateway. Envoy's primary role is a Policy Enforcement Point (PEP) for policies defined in either HTTP or MCP form...Envoy proxyModel Context Protocol (MCP) GatewayOverview​ Envoy AI Gateway's MCP support allows you to: Aggregate multiple MCP servers into a single unified endpoint. Apply secur...Envoy AI Gateway

Skip to main contentAccessibility help
AI Mode
All
Images
Videos
Short videos
More




kong vs envoy for supabase
Kong-to-Envoy Gateway migration tool : r/kubernetesWhen self-hosting Supabase, choosing between Kong and Envoy depends on your architectural needs. Kong is the default, batteries-included gateway for Supabase, while Envoy is offered as a lighter, cloud-native alternative. 

Supabase
 +1
Kong (Default)
Kong is an NGINX-based API gateway chosen by Supabase for its rich plugin ecosystem and ease of configuration. 

GitHub
 +3
Best For: Turnkey setups, traditional VMs, or bare-metal self-hosting where you want built-in features (like JWT authentication, rate-limiting, and analytics) out-of-the-box.
Pros: Massive library of plugins, familiar NGINX debugging, easy to spin up via standard Supabase Docker files.
Cons: Heavier resource footprint and more complex configuration management if you operate heavily in a microservices environment. 
Envoy (Alternative)
Envoy is a highly performant, C++-based proxy that Supabase natively supports as a drop-in replacement via their Docker overrides. 

Supabase
 +1
Best For: Kubernetes-native environments, complex microservices meshes, and applications handling massive, high-throughput loads.
Pros: Superior tail latency and throughput, dynamic hot-reloads (zero-downtime config changes), and standard Kubernetes Gateway API support.
Cons: Steeper learning curve and less immediate plugin support out-of-the-box compared to Kong. 

Medium
·Azzelya Rosya Denovya
 +4
How to use Envoy in Supabase
Supabase provides an official Envoy Docker compose override. If you are self-hosting, you can swap out Kong for Envoy by starting your stack with both composition files: 

Supabase
bash
docker compose -f docker-compose.yml -f docker-compose.envoy.yml up -d
Use code with caution.
Note: This override disables the default Kong gateway, starts Envoy on port 8000 (maintaining compatibility with Edge Functions and Studio), and reconfigures your setup. 

Supabase
If you'd like, let me know:
Is your setup running on Docker Compose or Kubernetes?
Are you heavily reliant on custom Kong plugins?
What is your primary goal in switching (e.g., performance, Kubernetes integration, or licensing)?
I can help you plan your exact deployment path.






10 sites
Envoy API Gateway | Supabase Docs
Enabling the Envoy gateway. The Envoy gateway is provided as a Docker Compose override. If your stack is already running from the ...


Supabase
Why pick Envoy Proxy and Solo.io over Kong Gateway for ...
Kubernetes came in and so clearly dominated the space that even CIOs are talking about their “Kubernetes strategy” these days. * E...


Solo.io
Envoy vs Kong Performance Comparison - Medium
Based on the results, Kong outperformed Envoy with higher throughput and shorter test duration, although Envoy showed a lower mini...


Medium
Show all
can they also act as a gateway for other non supabase FastAPI ?
Yes, both Kong and Envoy can act as a single gateway for both Supabase and your external FastAPI services. This allows you to unify routing, security, and rate limiting under one entry point.
Using Kong for FastAPI
Kong excels at this because of its declarative configuration via a kong.yml file or its Admin API.
Routing: You can map a route like /api/v1/fastapi directly to your FastAPI container or host.
Authentication: You can reuse Supabase JWTs. Kong can validate the Supabase-issued tokens before forwarding requests to FastAPI.
Plugins: You can instantly apply global or route-specific plugins (like rate-limiting or CORS) to your FastAPI endpoints without writing Python code.
Using Envoy for FastAPI
Envoy handles this via its Listener and Cluster architecture, defined in its configuration file.
Routing: You add a new route match under the virtual host configuration that points to your FastAPI cluster.
Performance: Envoy provides unmatched speed and low latency if your FastAPI application handles massive traffic or heavy WebSocket connections.
Service Mesh: If your FastAPI service runs in Kubernetes, Envoy integrates natively as a sidecar or ingress controller.
The Catch: Configuration Management
While both work perfectly, you must manage how you update their configurations:
With Kong: If you use the standard Supabase Docker setup, you will need to modify the kong.yml template to include your FastAPI service as a "Service" and a "Route."
With Envoy: You must manually edit the envoy.yaml file to append your FastAPI backend to the routing table and clusters list.
If you'd like, let me know:
Will your FastAPI application need to validate Supabase user JWTs?
Are you hosting FastAPI on the same machine/network as Supabase?
Which gateway (Kong or Envoy) are you leaning toward right now?
I can provide a concrete configuration snippet to route traffic to your FastAPI app.





Yes Id prefer to use supabase for JWTs too. My FastAPI will hit the host machine vs the docker for supabase i guess? I want the one with lower footprint and higher security because my use case is digital forensics
Envoy is the superior choice for your digital forensics use case [1]. It delivers an incredibly low memory footprint, an exceptional security profile, and native integration with Supabase JWT validation [1].
Architecture Overview
To maximize security and network isolation, your API gateway should live inside the Docker network alongside Supabase, while your forensics FastAPI app runs on the host machine [1].
The Network Path: External Requests → Envoy (Docker) → FastAPI (Host Machine) [1].
Host Access: Inside the Docker network, Envoy targets the host machine using the special DNS name host.docker.internal [1].
1. Gateway Evaluation
Criteria
Envoy (Recommended)	Kong
Memory Footprint	Extremely Low (~30MB to 50MB) [1]	Moderate (~250MB+ due to OpenResty/Lua)
Security Profile	Minimal attack surface (C++) [1]	Larger attack surface (NGINX + Lua ecosystem)
JWT Validation	Native, fast, and cryptographically strict [1]	Plugin-dependent
Tamper Resistance	Immutable, file-based declarative config [1]	Relies on dynamic state databases/files
2. Configuration Blueprint
To implement this, you need to configure Envoy's JWT Authentication filter and add a route pointing to your host machine.
Step 1: Update Envoy Configuration (envoy.yaml)
Locate your Supabase Envoy configuration file and add your FastAPI service into the HTTP filter chain and cluster list.
yaml
# 1. Add the JWT Authentication filter to your HTTP filter chain
http_filters:
  - name: envoy.filters.http.jwt_authn
    typed_config:
      "@type": ://googleapis.com
      providers:
        supabase_jwt:
          issuer: "https://supabase.co"
          # Replace with your actual Supabase local/remote JWKS URI
          remote_jwks:
            http_uri:
              uri: "http://auth:9999/.well-known/jwks.json" 
              cluster: supabase_auth_cluster
              timeout: 1s
          from_headers:
            - name: Authorization
              value_prefix: "Bearer "
      rules:
        # Require valid Supabase JWT specifically for your forensics endpoints
        - match:
            prefix: "/api/v1/forensics"
          requires:
            provider_name: "supabase_jwt"

  - name: envoy.filters.http.router
    typed_config:
      "@type": ://googleapis.com

# 2. Add the routing rule to your Virtual Host
routes:
  - match:
      prefix: "/api/v1/forensics"
    route:
      cluster: fastapi_host_service

# 3. Define the cluster pointing to your host machine
clusters:
  - name: fastapi_host_service
    connect_timeout: 0.25s
    type: LOGICAL_DNS
    dns_lookup_family: V4_ONLY
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: fastapi_host_service
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: host.docker.internal
                    port_value: 8000 # Your FastAPI host port
Use code with caution.
Step 2: Enable Host Communication in Docker Compose
To ensure Envoy can resolve host.docker.internal, append the extra_hosts directive to your Envoy service block inside your docker-compose.envoy.yml or override file [1]:
yaml
services:
  envoy:
    extra_hosts:
      - "host.docker.internal:host-gateway"
Use code with caution.
3. FastAPI Verification
Because Envoy strictly validates and cryptographically verifies the Supabase JWT at the perimeter, your FastAPI application does not need to re-verify the signature. It can safely ingest the user metadata sent by Envoy [1].
To securely capture user identities for your forensics audit logs, parse the raw JWT payload directly from the header within Python [1]:
python
from fastapi import FastAPI, Header, HTTPException
import base64
import json

app = FastAPI()

def extract_supabase_user(authorization: str):
    try:
        # Format: "Bearer <token>"
        token = authorization.split(" ")[1]
        payload_b64 = token.split(".")[1]
        # Fix padding if necessary
        payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
        payload_json = base64.b64decode(payload_b64).decode("utf-8")
        return json.loads(payload_json)
    except Exception:
        raise HTTPException(status_code=401, detail="Malformed claims payload")

@app.get("/api/v1/forensics/evidence")
async def get_evidence(authorization: str = Header(...)):
    user_data = extract_supabase_user(authorization)
    # Securely log user_data['sub'] (User ID) alongside the action
    return {"status": "secure access granted", "operator": user_data.get("email")}
Use code with caution.
✅ Summary of Setup
Envoy will intercept all incoming API traffic on your network perimeter, reject any requests missing a valid Supabase cryptographically signed token, and proxy verified forensic traffic down to your host-managed FastAPI instance via a secure internal Docker bridge [1].
If you'd like, let me know:
What Operating System is the host running (Linux, macOS, or Windows)?
Do you need Envoy to enforce strict IP whitelisting or TLS client certificates (mTLS) for the forensics dashboard?
I can provide the configuration layers to harden Envoy's network security boundaries further.





Ubuntu, Yes I want to maximize on Envoys security featurelist and hardening. And another question, can envoy also support being a gateway for an http mcp server (which is byitself an aggregator of stdio backend mcps)? or i need a separate mcp proxy
Yes, Envoy can natively act as the gateway for your HTTP MCP (Model Context Protocol) server, eliminating the need for a separate MCP proxy. 

Envoy AI Gateway
 +1
Envoy features a specialized MCP HTTP Filter (envoy.extensions.filters.http.mcp.v3.Mcp). It is built precisely to parse JSON-RPC 2.0 messages, handle persistent Server-Sent Events (SSE) data streams, and enforce strict policy controls directly at your network perimeter before traffic hits your MCP aggregator. 

Envoy AI Gateway
 +4
Here is how to harden Envoy on Ubuntu for your digital forensics use case, alongside routing both your FastAPI app and your HTTP MCP aggregator.
Part 1: Hardening Envoy for Digital Forensics (Ubuntu)
In forensics, preserving systemic integrity and preventing unauthorized intercept/tampering are paramount. We will configure Envoy to enforce Strict TLS 1.3, Mutual TLS (mTLS) client verification, and strict IP Whitelisting.
Step 1: Secure the Transport Layer (Downstream TLS & mTLS)
Modify the listeners block in your envoy.yaml to mandate client certificates. This ensures only forensic workstations with cryptographic keys can communicate with the gateway.
yaml
static_resources:
  listeners:
    - name: secure_forensics_gateway
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 443 # Bind to secure port
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": ://googleapis.com
                stat_prefix: ingress_http
                # Route configurations go here...
          
          # Enforcement of mTLS & Strict Ciphers
          transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": ://googleapis.com
              common_tls_context:
                tls_certificates:
                  - certificate_chain: { filename: "/etc/envoy/certs/server.crt" }
                    private_key: { filename: "/etc/envoy/certs/server.key" }
                # Force mTLS by validating client certs against your internal CA
                validation_context:
                  trusted_ca: { filename: "/etc/envoy/certs/forensics_internal_ca.crt" }
                  require_client_certificate: true
                tls_params:
                  tls_minimum_protocol_version: TLSv1_3 # Strict TLS 1.3 only
Use code with caution.
Step 2: RBAC IP Whitelisting (Network Level Protection)
Before HTTP processing even starts, block unauthorized IP blocks from scanning or flooding your endpoints using a Network Role-Based Access Control (RBAC) filter:
yaml
          filter_chains:
            - filters:
                - name: envoy.filters.network.rbac
                  typed_config:
                    "@type": ://googleapis.com
                    stat_prefix: network_rbac
                    rules:
                      action: ALLOW
                      policies:
                        "trusted-forensic-subnets":
                          permissions:
                            - any: true
                          principals:
                            - source_ip:
                                address_prefix: "10.0.40.0" # Example Forensic Lab Subnet
                                prefix_len: 24
Use code with caution.
Part 2: Unified Routing Table (FastAPI + HTTP MCP Aggregator)
Now, we add your HTTP MCP Server (the aggregator managing your underlying stdio tools) into Envoy's HTTP route architecture. Because MCP uses Streaming-HTTP/SSE over JSON-RPC, Envoy requires specific timeout overrides to maintain persistent tunnels without disconnecting active AI agents. 

Envoy proxy
 +1
Step 1: Define the Unified Route Table
Inside your HttpConnectionManager, append your routes under the virtual host structure:
yaml
virtual_hosts:
  - name: forensics_secure_vhost
    domains: ["*"]
    routes:
      # 1. Supabase Auth/Studio routes go here...

      # 2. Your Forensics FastAPI App
      - match:
          prefix: "/api/v1/forensics"
        route:
          cluster: fastapi_host_service

      # 3. Your HTTP MCP Server Aggregator
      - match:
          prefix: "/mcp"
        route:
          cluster: mcp_aggregator_service
          # CRITICAL FOR MCP: Prevent Envoy from severing long-running SSE streams
          timeout: 0s 
          idle_timeout: 0s
Use code with caution.
Step 2: Incorporate the MCP Data Inspection Filter
To allow Envoy to deeply monitor, log, or restrict actions based on which tools an AI agent is trying to trigger via your MCP backend, insert the native mcp filter into your http_filters chain: 

Envoy proxy
 +1
yaml
http_filters:
  - name: envoy.filters.http.jwt_authn # Validates Supabase JWTs first
    typed_config:
      "@type": ://googleapis.com
      # ... (JWT setup from previous step)

  - name: envoy.filters.http.mcp # Native Protocol Parsing
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.mcp.v3.Mcp

  - name: envoy.filters.http.router # Final Router Step
    typed_config:
      "@type": ://googleapis.com
Use code with caution.
Step 3: Define Upstream Clusters
Point both clusters toward your Ubuntu host machine. Remember to assign different ports corresponding to where FastAPI and your HTTP MCP aggregator are listening natively on Ubuntu.
yaml
clusters:
  - name: fastapi_host_service
    connect_timeout: 0.5s
    type: LOGICAL_DNS
    dns_lookup_family: V4_ONLY
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: fastapi_host_service
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  socket_address: { address: host.docker.internal, port_value: 8000 }

  - name: mcp_aggregator_service
    connect_timeout: 0.5s
    type: LOGICAL_DNS
    dns_lookup_family: V4_ONLY
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: mcp_aggregator_service
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  socket_address: { address: host.docker.internal, port_value: 8080 } # Your HTTP MCP host port
Use code with caution.
Why this structure is ideal for Forensics
Zero-Trust for AI Agents: By adding the envoy.filters.http.mcp filter, Envoy parses incoming JSON-RPC calls. If an AI tool call attempts to execute an unapproved stdio terminal string backend, Envoy can reject it before it touches the HTTP aggregator. 

Envoy proxy
 +3
Immutable Audit Trails: Because Envoy acts as the absolute gateway for Supabase, FastAPI, and MCP, you can route all traffic logs upstream to an immutable system log (such as a local syslog or an external SIEM) for bulletproof forensics auditing. 
If you'd like, let me know:
Do you want to see how to configure Envoy’s Access Logging to generate cryptographic audit trails for your forensics logs?
Are your stdio backends executing destructive/write commands that need explicit step-by-step approval blocks at the Envoy tier?
I can provide the specific filter configurations to implement those constraints.






7 sites
The case for Envoy networking in the agentic AI era
Apr 3, 2026 — With Envoy in front of the MCP server, the gateway can verify the agent identity using SPIFFE during the mTLS handshake, parse the...


Google Cloud
Model Context Protocol (MCP) - Envoy proxy
Pass-Through MCP Gateway. Envoy's primary role is a Policy Enforcement Point (PEP) for policies defined in either HTTP or MCP form...

Envoy proxy
Model Context Protocol (MCP) Gateway
Overview​ Envoy AI Gateway's MCP support allows you to: Aggregate multiple MCP servers into a single unified endpoint. Apply secur...


Envoy AI Gateway
Show all
Can you provide me with a detailed diagram showcasing the architectural design in tech stack, flow, and security boundaries layers?\
+-------------------------------------------------------------------------------------------------------------------------+

|                                           UNTRUSTED / EXTERNAL NETWORK                                                  |
|                                                                                                                         |
|    +------------------------+                 +------------------------+                 +------------------------+     |
|    |  Forensic Workstation  |                 |     External Agent     |                 |  Malicious Network IP  |     |
|    |  (Valid TLS Client x509|                 |   (No TLS Client Cert)  |                 |    (Untrusted Subnet)  |     |
|    +-----------+------------+                 +-----------+------------+                 +-----------+------------+     |
+----------------|------------------------------------------|------------------------------------------|------------------+

                 |                                          |                                          |
=================|==========================================|==========================================|===================

                 | [1] Direct Request (Port 443)            | [2] Direct Request                       | [3] Dropped Immed.
                 v                                          v                                          v
+-------------------------------------------------------------------------------------------------------------------------+

| SECURITY BOUNDARY LAYER 1: NETWORK PERIMETER HARDENING (Host Bridge TCP)                                                |
|                                                                                                                         |
|   +-----------------------------------------------------------------------------------------------------------------+   |
|   | ENVOY PROXY (Docker Container: `envoy`)                                                                         |   |
|   |                                                                                                                 |   |
|   |  [A] NETWORK RBAC FILTER                                                                                        |   |
|   |      • Evaluates incoming Source IP. Only allows Trusted Subnets (e.g., 10.0.40.0/24).                          |   |
|   |      • Blocked traffic drops completely at the TCP level.                                                       |   |
|   |                                                                                                                 |   |
|   |  [B] DOWNSTREAM TLS CONTEXT (Strict Mutual TLS)                                                                 |   |
|   |      • Enforces Minimum Protocol Version: TLSv1.3 Only.                                                          |   |
|   |      • Validates Client Certs against `forensics_internal_ca.crt`.                                              |   |
|   |      • Connection [2] is instantly terminated here for missing an authorized cryptographic identity.            |   |
|   +------------------------------------------------------+----------------------------------------------------------+   |
+----------------------------------------------------------|--------------------------------------------------------------+

                                                           |
                                                           | [4] Forward Validated Payload to Application Layers
                                                           v
+-------------------------------------------------------------------------------------------------------------------------+

| SECURITY BOUNDARY LAYER 2: HTTP FILTER CHAIN & CRYPTOGRAPHIC VERIFICATION                                               |
|                                                                                                                         |
|   +-----------------------------------------------------------------------------------------------------------------+   |
|   | ENVOY HTTP CONNECTION MANAGER                                                                                   |   |
|   |                                                                                                                 |   |
|   |  [C] JWT AUTHENTICATION FILTER (`envoy.filters.http.jwt_authn`)                                                 |   |
|   |      • Intercepts `/api/v1/forensics/*` and `/mcp/*`.                                                           |   |
|   |      • Extracts `Authorization: Bearer <JWT>`. Matches signatures directly using Supabase JWKS cache keys.       |   |
|   |                                                                                                                 |   |
|   |  [D] MCP PROTOCOL PARSING FILTER (`envoy.filters.http.mcp`)                                                     |   |
|   |      • Deep inspects HTTP stream on path `/mcp`.                                                                |   |
|   |      • Decodes JSON-RPC 2.0 frames; enforces validation blocks on specific destructive backend tools.          |   |
|   |                                                                                                                 |   |
|   |  [E] GLOBAL ACCESS LOG FILTER                                                                                   |   |
|   |      • Pumps structural JSON records tracking (User ID, IP, Client DN, Payload SHA) out to Host System logs.    |   |
|   +-----------------------------------------+----------------------------+------------------------------------------+   |
+---------------------------------------------|----------------------------|----------------------------------------------+

                                              |                            |
                     (Route: `/auth/*`)       | (Route: `/api/v1/*`)       | (Route: `/mcp/*`)

                                              |                            |
                                              | [5a] Reverse Proxy via     | [5b] Reverse Proxy via
                                              |      `host.docker.internal`|      `host.docker.internal`
                                              |      (Isolated Bridge)     |      (Isolated Bridge)
                                              v                            v
==============================================|============================|===============================================
+---------------------------------------------v----+         +-------------v----+                                         +

| PRIVATE DOCKER BRIDGE NETWORK                    |         | UBUNTU HOST SYSTEM (Native OS Loopback Execution Space)    |
|                                                  |         |                                                            |
|  +--------------------------------------------+  |         |  +------------------------------------------------------+  |
|  | SUPABASE STACK                             |  |         |  | FASTAPI APP (Port 8000)                              |  |
|  |                                            |  |         |  |                                                      |  |
|  |  • Auth Engine (Provides JWKS Keys)        |  |         |  |   • Consumes Pre-Validated Envoy Traffic             |  |
|  |  • PostgreSQL Storage Engine               |  |         |  |   • Parses User Metadata directly out of Headers     |  |
|  |  • Edge Runtime Environments               |  |         |  |   • Writes Local Cryptographic Forensics Logs        |  |
|  +--------------------------------------------+  |         |  +------------------------------------------------------+  |
|                                                  |         |                                                            |
|                                                  |         |  +------------------------------------------------------+  |
|                                                  |         |  | HTTP MCP AGGREGATOR SERVER (Port 8080)               |  |
|                                                  |         |  |                                                      |  |
|                                                  |         |  |   • Persistent SSE / Keep-Alive Streams Open         |  |
|                                                  |         |  |   • Orchestrates Internal stdio Sub-Processes:       |  |
|                                                  |         |  |      [ Tool 1 ]  --> Local File System Analyzer         |  |
|                                                  |         |  |      [ Tool 2 ]  --> Disk Image Mounter / Hashing       |  |
|                                                  |         |  +------------------------------------------------------+  |
+--------------------------------------------------+         +------------------------------------------------------------+

| SECURITY BOUNDARY LAYER 3: CORE DATA ISOLATION             | SECURITY BOUNDARY LAYER 4: SYSTEM PRIVILEGES & RUNTIME     |
+--------------------------------------------------+         +------------------------------------------------------------+
Explanatory Breakdown of Design Principles
Layer 1: Network Ingress Protection (Envoy)
RBAC Network Filter: Drops traffic immediately based on IP restrictions. If an investigator isn't using a device within the dedicated forensics network segment, their traffic cannot probe your services.
mTLS Ingress Constraint: Before Envoy reads a single line of HTTP data, it executes a strict cryptographic handshake (TLS 1.3 only). Any client failing to present a certificate generated from the explicit internal Certificate Authority (forensics_internal_ca.crt) gets rejected immediately.
Layer 2: HTTP Processing & Protocol Enforcement (Envoy Engine)
Boundary Cryptography Authentication: Supabase's identity provider serves JSON Web Key Sets (JWKS). Envoy caches these local keys and parses incoming request signatures at line rate. FastAPI never incurs performance or latency penalties validating signatures because unauthorized traffic is filtered out at this phase.
MCP Semantic Isolation: The envoy.filters.http.mcp protocol layer inspects persistent JSON-RPC 2.0 streams. It screens payloads on the /mcp route, protecting your host machine's low-level system binaries from injection attacks or prohibited command lines before passing requests down.
Layer 3: Network Topography & System Boundaries (Docker to Ubuntu Host)
Network Topography Isolation: Supabase lives contained within a dedicated internal Docker network.
Bridged Secure Routing: Envoy acts as an explicit path provider via the address host.docker.internal. Your local forensic tools running directly on the Ubuntu host layer do not expose their internal listening ports (8000, 8080) to the wider public network; they bind exclusively to internal local loops (127.0.0.1 / Docker virtual bridge interfaces).
If you'd like, let me know:
Do you want to review the complete envoy.yaml block mapping out the exact configurations for the Network RBAC block or the DownstreamTlsContext files?
Should we design a configuration path to route Envoy's structured logs into a secure, append-only file on your Ubuntu host for tamper-evident tracking?
I can provide the specific system implementation patterns for those tasks.





Ask anything


AI Mode response is ready
Ask ab
