use better_auth_core::utils::username::UsernameConfig;
use better_auth_core::{
    AuthConfig, AuthContext, AuthError, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse,
    AuthResult, AuthRoute, AuthSchema, AuthStore, BeforeRequestAction, EmailProvider,
    ErrorCodeMessageResponse, HttpMethod, OkResponse, OpenApiBuilder, OpenApiRegistry, OpenApiSpec,
    SessionManager, UpdateUser, UpdateUserRequest, core_paths,
    entity::AuthUser,
    hooks::{RequestHookContext, with_request_hook_context_value},
    middleware::{
        self, BodyLimitConfig, BodyLimitMiddleware, CorsConfig, CorsMiddleware, CsrfConfig,
        CsrfMiddleware, Middleware, RateLimitConfig, RateLimitMiddleware,
    },
};
use std::sync::Arc;

pub struct BetterAuth<S: AuthSchema> {
    config: Arc<AuthConfig>,
    telemetry: crate::telemetry::TelemetryConfig,
    pub(super) plugins: Vec<Box<dyn AuthPlugin<S>>>,
    transport_middlewares: Vec<Box<dyn Middleware>>,
    middlewares: Vec<Box<dyn Middleware>>,
    request_protection: CsrfMiddleware,
    body_limit: BodyLimitConfig,
    store: Arc<dyn AuthStore<S>>,
    session_manager: SessionManager<S>,
    pub(super) context: AuthContext<S>,
    openapi: Arc<OpenApiRegistry>,
    pub(super) endpoint_hooks: Vec<Arc<dyn better_auth_core::endpoint::EndpointHook<S>>>,
}

impl<S: AuthSchema> std::fmt::Debug for BetterAuth<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BetterAuth").finish_non_exhaustive()
    }
}

/// Initial builder for configuring `BetterAuth`.
pub struct AuthBuilder<S: AuthSchema> {
    config: AuthConfig,
    telemetry: crate::telemetry::TelemetryConfig,
    store: Option<Arc<dyn AuthStore<S>>>,
    plugins: Vec<Box<dyn AuthPlugin<S>>>,
    csrf_config: Option<CsrfConfig>,
    rate_limit_config: Option<RateLimitConfig>,
    cors_config: Option<CorsConfig>,
    body_limit_config: Option<BodyLimitConfig>,
    custom_middlewares: Vec<Box<dyn Middleware>>,
    endpoint_hooks: Vec<Arc<dyn better_auth_core::endpoint::EndpointHook<S>>>,
}

impl<S: AuthSchema> std::fmt::Debug for AuthBuilder<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthBuilder").finish_non_exhaustive()
    }
}

impl<S: AuthSchema> AuthBuilder<S> {
    /// Create an instance builder with the core API installed at build time.
    /// Email/password and username authentication remain disabled until an
    /// explicit email/password plugin enables them. Explicit core plugins keep
    /// their configuration; custom plugins keep their dispatch priority.
    #[must_use]
    pub fn new(config: AuthConfig) -> Self {
        Self {
            config,
            telemetry: crate::telemetry::TelemetryConfig::default(),
            store: None,
            plugins: Vec::new(),
            csrf_config: None,
            rate_limit_config: None,
            cors_config: None,
            body_limit_config: None,
            custom_middlewares: Vec::new(),
            endpoint_hooks: Vec::new(),
        }
    }

    /// Configure opt-in application-owned telemetry.
    #[must_use]
    pub fn telemetry(mut self, telemetry: crate::telemetry::TelemetryConfig) -> Self {
        self.telemetry = telemetry;
        self
    }

    /// Set the shared auth store implementation.
    #[must_use]
    pub fn store<T>(mut self, store: T) -> Self
    where
        T: AuthStore<S> + 'static,
    {
        self.store = Some(Arc::new(store));
        self
    }

    /// Set the shared auth store implementation using an existing [`Arc`].
    #[must_use]
    pub fn store_arc(mut self, store: Arc<dyn AuthStore<S>>) -> Self {
        self.store = Some(store);
        self
    }

    /// Add a plugin to the authentication system.
    #[must_use]
    pub fn plugin<P: AuthPlugin<S> + 'static>(mut self, plugin: P) -> Self {
        self.plugins.push(Box::new(plugin));
        self
    }

    /// Register configured application hooks before installed plugin endpoint hooks.
    #[must_use]
    pub fn endpoint_hook<H: better_auth_core::endpoint::EndpointHook<S> + 'static>(
        mut self,
        hook: H,
    ) -> Self {
        self.endpoint_hooks.push(Arc::new(hook));
        self
    }

    /// Configure CSRF protection.
    #[must_use]
    pub const fn csrf(mut self, config: CsrfConfig) -> Self {
        self.csrf_config = Some(config);
        self
    }

    /// Configure rate limiting.
    #[must_use]
    pub fn rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limit_config = Some(config);
        self
    }

    /// Configure CORS.
    #[must_use]
    pub fn cors(mut self, config: CorsConfig) -> Self {
        self.cors_config = Some(config);
        self
    }

    /// Configure body size limit.
    #[must_use]
    pub const fn body_limit(mut self, config: BodyLimitConfig) -> Self {
        self.body_limit_config = Some(config);
        self
    }

    /// Set the email provider.
    #[must_use]
    pub fn email_provider<E: EmailProvider + 'static>(mut self, provider: E) -> Self {
        self.config.email_provider = Some(Arc::new(provider));
        self
    }

    /// Add a custom middleware.
    #[must_use]
    pub fn middleware<M: Middleware + 'static>(mut self, mw: M) -> Self {
        self.custom_middlewares.push(Box::new(mw));
        self
    }

    /// Build the `BetterAuth` instance.
    ///
    /// # Errors
    ///
    /// Returns an error if configuration validation or plugin initialization fails.
    pub async fn build(mut self) -> AuthResult<BetterAuth<S>> {
        // Validate configuration
        self.config.validate()?;

        // Authentication and every producer use the same initialized token
        // name; related-cookie overrides remain independently configured.
        // Retain the unprefixed legacy name before storing the resolved name.
        // This keeps name resolution stable across producers and request clones.
        if !self
            .config
            .advanced
            .cookie_prefix
            .as_ref()
            .is_some_and(|p| !p.is_empty())
        {
            let entry = self
                .config
                .advanced
                .cookies
                .entry("session_token".into())
                .or_default();
            if entry.name.as_ref().is_none_or(|name| name.is_empty()) {
                entry.name = Some(self.config.session.cookie_name.clone());
            }
        }
        self.config.session.cookie_name =
            better_auth_core::utils::cookie_utils::related_cookie_name(
                &self.config,
                "session_token",
            );

        // Core modules exist on every instance. Explicit modules keep their own
        // configuration and priority; defaults never enable credential login.
        let defaults: Vec<Box<dyn AuthPlugin<S>>> = vec![
            Box::new(crate::plugins::SessionManagementPlugin::new()),
            Box::new(
                crate::plugins::EmailPasswordPlugin::new()
                    .enabled(false)
                    .enable_username(false),
            ),
            Box::new(crate::plugins::PasswordManagementPlugin::new()),
            Box::new(crate::plugins::EmailVerificationPlugin::new()),
            Box::new(crate::plugins::AccountManagementPlugin::new()),
            Box::new(crate::plugins::OAuthPlugin::new()),
            Box::new(crate::plugins::UserManagementPlugin::new()),
        ];
        for plugin in defaults {
            if !self
                .plugins
                .iter()
                .any(|installed| installed.name() == plugin.name())
            {
                self.plugins.push(plugin);
            }
        }

        let config = Arc::new(self.config);
        let store = self
            .store
            .ok_or_else(|| AuthError::config("Auth store not configured"))?;

        let mut init_context = AuthInitContext::new(Arc::clone(&config), Arc::clone(&store));

        // Initialize all plugins.
        for plugin in &self.plugins {
            plugin.on_init(&mut init_context).await?;
        }

        let mut session_fields =
            better_auth_core::field_policy::SessionFields(config.session.additional_fields.clone());
        let mut adapter_fields = better_auth_core::field_policy::FieldConfigs::new();
        for plugin in &self.plugins {
            let fields = plugin.session_fields();
            adapter_fields.extend(fields.clone());
            session_fields.0.extend(fields);
        }
        adapter_fields.extend(config.session.additional_fields.clone());
        init_context
            .extensions
            .insert(better_auth_core::field_policy::SessionAdapterFields(
                Arc::new(adapter_fields),
            ));
        init_context.extensions.insert(session_fields);
        let mut user_fields =
            better_auth_core::field_policy::SessionFields(config.user.additional_fields.clone());
        let mut account_fields =
            better_auth_core::field_policy::SessionFields(config.account.additional_fields.clone());
        let mut user_adapter = better_auth_core::field_policy::FieldConfigs::new();
        let mut account_adapter = better_auth_core::field_policy::FieldConfigs::new();
        for plugin in &self.plugins {
            let fields = plugin.user_fields();
            user_adapter.extend(fields.clone());
            user_fields.0.extend(fields);
            let fields = plugin.account_fields();
            account_adapter.extend(fields.clone());
            account_fields.0.extend(fields);
        }
        user_adapter.extend(config.user.additional_fields.clone());
        account_adapter.extend(config.account.additional_fields.clone());
        init_context
            .extensions
            .insert(better_auth_core::field_policy::UserFields(user_fields));
        init_context
            .extensions
            .insert(better_auth_core::field_policy::AccountFields(
                account_fields,
            ));
        init_context
            .extensions
            .insert(better_auth_core::field_policy::AdapterFieldPolicies {
                user: better_auth_core::field_policy::SessionAdapterFields(Arc::new(user_adapter)),
                account: better_auth_core::field_policy::SessionAdapterFields(Arc::new(
                    account_adapter,
                )),
            });
        let mut openapi = OpenApiRegistry::configured(S::openapi_models(), &config);
        let core_routes = better_auth_core::openapi::annotations::core_routes();
        let core_metadata =
            better_auth_core::openapi::annotations::plugin_metadata("core", &core_routes);
        openapi.register("core", core_routes, core_metadata);
        for plugin in &self.plugins {
            openapi.register(
                plugin.name(),
                plugin.routes(),
                plugin.openapi_metadata(&init_context),
            );
            openapi.register_fields("User", &plugin.user_fields());
            openapi.register_fields("Session", &plugin.session_fields());
            openapi.register_fields("Account", &plugin.account_fields());
        }
        init_context.extensions.insert(openapi);
        let openapi_2 = init_context
            .extensions
            .get::<OpenApiRegistry>()
            .ok_or_else(|| AuthError::internal("OpenAPI registry initialization failed"))?;

        let store_2 = init_context.database_with_registered_transforms();
        let init_parts = init_context.into_parts();

        // Create session manager
        let session_manager = SessionManager::new(Arc::clone(&config), Arc::clone(&store_2));

        // Create context
        let mut context = AuthContext::with_metadata(
            Arc::clone(&config),
            Arc::clone(&store_2),
            init_parts.metadata,
        )
        .with_extensions(init_parts.extensions);
        context.email_provider = init_parts.email_provider;

        let body_limit = self.body_limit_config.unwrap_or_default();

        let request_protection =
            CsrfMiddleware::new(self.csrf_config.unwrap_or_default(), Arc::clone(&config));
        // Transport and application request middleware precede router resolution.
        let transport_middlewares: Vec<Box<dyn Middleware>> = vec![
            Box::new(BodyLimitMiddleware::new(body_limit.clone())),
            Box::new(
                RateLimitMiddleware::new(self.rate_limit_config.unwrap_or_default())
                    .with_base_path(config.base_path.clone())
                    .with_plugin_rules(
                        self.plugins
                            .iter()
                            .flat_map(|plugin| plugin.rate_limits())
                            .collect(),
                    ),
            ),
        ];
        let mut middlewares: Vec<Box<dyn Middleware>> = vec![Box::new(CorsMiddleware::new(
            self.cors_config.unwrap_or_default(),
        ))];

        middlewares.extend(self.custom_middlewares);

        if self.telemetry.is_enabled() {
            self.telemetry
            .publish(crate::telemetry::TelemetryEvent::new(
                "init",
                serde_json::json!({
                    "libraryVersion": env!("CARGO_PKG_VERSION"),
                    "runtime": "rust",
                    "platform": std::env::consts::OS,
                    "architecture": std::env::consts::ARCH,
                    "plugins": self.plugins.iter().map(|plugin| plugin.name()).collect::<Vec<_>>(),
                }),
            ))
            .await;
        }

        Ok(BetterAuth {
            telemetry: self.telemetry,
            config,
            plugins: self.plugins,
            transport_middlewares,
            middlewares,
            request_protection,
            body_limit,
            store: store_2,
            session_manager,
            context,
            openapi: openapi_2,
            endpoint_hooks: self.endpoint_hooks,
        })
    }
}

impl<S: AuthSchema> BetterAuth<S> {
    /// Create a new `BetterAuth` builder.
    #[expect(
        clippy::new_ret_no_self,
        reason = "returns AuthBuilder by design — builder pattern entry point"
    )]
    #[must_use]
    pub fn new(config: AuthConfig) -> AuthBuilder<S> {
        AuthBuilder::new(config)
    }
}

impl<S: AuthSchema> BetterAuth<S> {
    /// Publish an application-owned event to the configured telemetry sink.
    /// Delivery is awaited; a sink failure is logged and does not fail authentication.
    /// The host is responsible for excluding secrets and personal data from its payload.
    pub async fn publish_telemetry(&self, event: crate::telemetry::TelemetryEvent) {
        self.telemetry.publish(event).await;
    }

    /// Handle an authentication request.
    ///
    /// Errors from plugins and core handlers are automatically converted
    /// into standardized JSON responses via [`AuthError::to_auth_response`],
    /// producing `{ "message": "..." }` with the appropriate HTTP status code.
    ///
    /// This future is owned by the caller: dropping or aborting it cancels
    /// unfinished dispatch without rolling back already committed writes.
    /// Independently owned background callbacks already launched can continue.
    /// Hosts that require continuation after disconnect must retain the future
    /// in an owned task. Dropping a Tokio task's `JoinHandle` does not cancel it.
    /// The Axum integration already supervises fully buffered requests this way.
    ///
    /// # Errors
    ///
    /// Propagates errors from after-response middleware. Route and plugin errors become error responses.
    pub async fn handle_request(&self, req: AuthRequest) -> AuthResult<AuthResponse> {
        // Reset caller-supplied session context, typed extensions and queued headers.
        // Only trusted handlers and hooks may establish them during dispatch.
        let query_pairs = req
            .query
            .keys()
            .flat_map(|name| {
                req.query_values(name)
                    .into_iter()
                    .flatten()
                    .map(|value| (name.clone(), value.clone()))
            })
            .collect::<Vec<_>>();
        let request_url = req.url().cloned();
        let mut req =
            AuthRequest::from_parts(req.method, req.path, req.headers, req.body, req.query);
        if let Some(url) = request_url {
            req = req.with_url(url);
        }
        req.set_query_pairs(query_pairs);
        req.extensions()
            .insert(self.config.advanced.ip_address.clone());

        let context = match self.config.resolve_request(&req).await {
            Ok(config) => AuthContext {
                config: Arc::new(config),
                database: Arc::clone(&self.context.database),
                email_provider: self.context.email_provider.clone(),
                metadata: self.context.metadata.clone(),
                extensions: self.context.extensions.clone(),
            },
            Err(error) => return Ok(error.to_auth_response()),
        };
        let request_context = RequestHookContext::from_request(&req);
        better_auth_core::endpoint::without_endpoint_call_context(with_request_hook_context_value(
            request_context,
            async {
                let mut run_after_hooks = false;
                // Keep the public request future bounded while scoped context
                // and route-specific authentication retain their actual state.
                let mut response = match Box::pin(self.handle_request_inner(
                    &mut req,
                    &mut run_after_hooks,
                    &context,
                ))
                .await
                {
                    Ok(response) => response,
                    Err(err) => {
                        if matches!(err, AuthError::CallbackFailure(_)) {
                            run_after_hooks = false;
                        }
                        err.to_auth_response()
                    }
                };
                let (cache_headers, ordinary_cache_error) =
                    better_auth_core::cache::runtime::take_issuance(req.extensions());
                if ordinary_cache_error {
                    run_after_hooks = false;
                    response = AuthResponse::new(500);
                    drop(req.take_response_headers());
                }
                if better_auth_api::plugins::oauth_proxy::take_unhandled_error(&req) {
                    run_after_hooks = false;
                }
                let mut nested_headers = req.take_response_headers();
                for (name, value) in response.headers {
                    if name.eq_ignore_ascii_case("set-cookie") {
                        nested_headers.append(name, value);
                    } else {
                        drop(nested_headers.insert(name, value));
                    }
                }
                for header in cache_headers {
                    nested_headers.append("Set-Cookie", header);
                }
                response.headers = nested_headers;
                let mut hook_request = req.clone();
                let base_path = &self.config.base_path;
                if !base_path.is_empty() && base_path != "/" {
                    hook_request.path = req
                        .path()
                        .strip_prefix(base_path)
                        .unwrap_or_else(|| req.path())
                        .to_owned();
                }
                for plugin in self.plugins.iter().filter(|_| run_after_hooks) {
                    let accumulated_headers = response.headers.clone();
                    response = match plugin
                        .after_request(&hook_request, &context, response)
                        .await
                    {
                        Ok(response) => response,
                        Err(error @ AuthError::CallbackFailure(_)) => {
                            // An ordinary application exception aborts completed hooks.
                            // Source drops accumulated headers, including already-issued
                            // cookies, while preserving the committed authentication writes.
                            response = error.to_auth_response();
                            break;
                        }
                        Err(error) => {
                            let mut response_2 = error.to_auth_response();
                            for (name, value) in accumulated_headers {
                                if name.eq_ignore_ascii_case("set-cookie") {
                                    response_2.headers.append(name, value);
                                } else if !response_2.headers.contains_key(&name) {
                                    drop(response_2.headers.insert(name, value));
                                }
                            }
                            response_2
                        }
                    };
                    for (name, value) in req.take_response_headers() {
                        if name.eq_ignore_ascii_case("set-cookie") {
                            response.headers.append(name, value);
                        } else {
                            drop(response.headers.insert(name, value));
                        }
                    }
                }
                let response = middleware::run_after(&self.middlewares, &req, response).await?;
                middleware::run_after(&self.transport_middlewares, &req, response).await
            },
        ))
        .await
    }

    /// Inner request handler that may return errors.
    async fn handle_request_inner(
        &self,
        req: &mut AuthRequest,
        run_after_hooks: &mut bool,
        context: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let base_path = self.config.base_path.trim_end_matches('/');
        let requested_path = req
            .path()
            .strip_prefix(base_path)
            .filter(|suffix| suffix.starts_with('/'))
            .unwrap_or_else(|| req.path());
        let disabled_path = requested_path.trim_end_matches('/');
        if self.config.is_path_disabled(disabled_path) {
            let mut response =
                AuthResponse::new(404).with_header("content-type", "text/plain;charset=utf-8");
            response.body = b"Not Found".to_vec();
            return Ok(response);
        }

        // Run before-request middleware chain
        if let Some(response) = middleware::run_before(&self.transport_middlewares, req).await? {
            return Ok(response);
        }

        for plugin in &self.plugins {
            if let Some(response) = plugin.on_http_request(req, context).await? {
                return Ok(response);
            }
        }

        if let Some(response) = middleware::run_before(&self.middlewares, req).await? {
            return Ok(response);
        }

        // Strip base_path prefix from the request path for internal routing.
        // This happens BEFORE plugin hooks so that `before_request` sees the
        // same normalised path that `on_request` / core handlers use.
        // External callers send e.g. "/api/auth/sign-in/email"; internally
        // handlers match against "/sign-in/email".
        let base_path = &self.config.base_path;
        let stripped_path = if !base_path.is_empty() && base_path != "/" {
            req.path()
                .strip_prefix(base_path)
                .filter(|suffix| suffix.starts_with('/'))
                .unwrap_or_else(|| req.path())
        } else {
            req.path()
        };

        // Build a request with the stripped path for all subsequent dispatch
        let mut internal_req = if stripped_path == req.path() {
            req.clone()
        } else {
            let mut r = req.clone();
            stripped_path.clone_into(&mut r.path);
            r
        };

        if self.config.advanced.skip_trailing_slashes {
            internal_req.path = internal_req.path.trim_end_matches('/').to_owned();
        }

        // The pinned router resolves the endpoint before dispatching hooks.
        // An unknown path or method cannot trigger authentication side effects.
        let core_route = matches!(
            (internal_req.method(), internal_req.path()),
            (
                HttpMethod::Get,
                core_paths::OK | core_paths::ERROR | core_paths::OPENAPI_SPEC
            ) | (HttpMethod::Post, core_paths::UPDATE_USER)
        );
        let plugin_route = self.plugins.iter().find_map(|plugin| {
            plugin
                .routes()
                .into_iter()
                .find(|route| {
                    route.method == internal_req.method
                        && !self.openapi.is_server_only(plugin.name(), route)
                        && route_path_matches(&route.path, internal_req.path())
                })
                .map(|route| (plugin, route))
        });
        if (!core_route && plugin_route.is_none()) || internal_req.path().contains("//") {
            return Ok(AuthResponse::new(404));
        }
        let allowed_media_types = plugin_route.as_ref().map_or_else(
            || vec!["application/json"],
            |(plugin, route)| plugin.allowed_media_types(route),
        );
        parse_dispatch_body(&internal_req, &allowed_media_types).await?;
        self.request_protection
            .with_auth_config(Arc::clone(&context.config))
            .check_request_origin(&internal_req)?;

        let context_path = plugin_route
            .as_ref()
            .map(|(_, route)| route.context_path.as_deref().unwrap_or(&route.path))
            .unwrap_or_else(|| internal_req.path())
            .to_owned();
        let params = context_path
            .split('/')
            .zip(internal_req.path().split('/'))
            .filter_map(|(part, value)| {
                let name = part.strip_prefix(':').or_else(|| {
                    part.strip_prefix('{')
                        .and_then(|name| name.strip_suffix('}'))
                })?;
                Some((name.to_owned(), value.to_owned()))
            })
            .collect();
        internal_req
            .extensions()
            .insert(better_auth_core::plugin::ResolvedEndpoint {
                path: context_path,
                params,
            });

        // Run plugin before_request hooks (e.g. API-key → session emulation)
        // Plugins now see the normalised (base_path-stripped) path.
        for plugin in &self.plugins {
            if let Some(action) = plugin.before_request(&internal_req, context).await? {
                match action {
                    BeforeRequestAction::Respond(response) => {
                        return Ok(response);
                    }
                    BeforeRequestAction::InjectSession { session } => {
                        // Completed-response hooks must retain the authenticated
                        // context established by before hooks.
                        req.set_virtual_session(session.clone());
                        internal_req.set_virtual_session(session);
                    }
                    BeforeRequestAction::ReplaceHeaders { headers } => {
                        req.headers.clone_from(&headers);
                        internal_req.headers = headers;
                    }
                }
            }
        }

        // A before-hook response or rejection returns immediately upstream.
        // Only endpoint dispatch reaches the completed-response hook pipeline.
        *run_after_hooks = true;

        // Handle core endpoints first
        if let Some(response) = self.handle_core_request(&internal_req, context).await? {
            return Ok(response);
        }

        // Dispatch only the resolved HTTP endpoint. A server-only handler from
        // another plugin may share this path and must never receive the call.
        if let Some((plugin, _route)) = plugin_route
            && let Some(response) = plugin.on_request(&internal_req, context).await?
        {
            return Ok(response);
        }

        // No handler found
        Err(AuthError::not_found("No handler found for this request"))
    }

    /// Get the configuration.
    #[must_use]
    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    /// Return the initialized context for server-only plugin APIs.
    ///
    /// The context includes metadata registered by every installed plugin.
    #[must_use]
    pub const fn context(&self) -> &AuthContext<S> {
        &self.context
    }

    /// Get the shared auth store used by Better Auth.
    #[must_use]
    pub fn store(&self) -> &Arc<dyn AuthStore<S>> {
        &self.store
    }

    /// Get the effective request body size limit.
    ///
    /// Transports read the body before any middleware runs, so they need this
    /// to bound the read itself rather than rejecting after buffering.
    #[must_use]
    pub const fn body_limit(&self) -> &BodyLimitConfig {
        &self.body_limit
    }

    /// Get the session manager.
    #[must_use]
    pub const fn session_manager(&self) -> &SessionManager<S> {
        &self.session_manager
    }

    /// Get all routes from plugins.
    #[must_use]
    pub fn routes(&self) -> Vec<(String, &dyn AuthPlugin<S>)> {
        let mut routes = Vec::new();
        for plugin in &self.plugins {
            for route in plugin.routes() {
                routes.push((route.path, plugin.as_ref()));
            }
        }
        routes
    }

    /// Snapshot of actual registered routes, independent of documentation filters.
    /// The native embedding endpoint `/__test/openapi.json` is a Rust extension.
    #[must_use]
    pub fn registered_routes(&self) -> Vec<AuthRoute> {
        self.openapi.registered_routes()
    }

    /// Get all plugins.
    #[must_use]
    pub fn plugins(&self) -> &[Box<dyn AuthPlugin<S>>] {
        &self.plugins
    }

    /// Get plugin by name.
    #[must_use]
    pub fn get_plugin(&self, name: &str) -> Option<&dyn AuthPlugin<S>> {
        self.plugins
            .iter()
            .find(|p| p.name() == name)
            .map(AsRef::as_ref)
    }

    /// List all plugin names.
    #[must_use]
    pub fn plugin_names(&self) -> Vec<&'static str> {
        self.plugins.iter().map(|p| p.name()).collect()
    }

    /// Generate the `OpenAPI` spec for all registered routes.
    #[must_use]
    pub fn openapi_spec(&self) -> OpenApiSpec {
        OpenApiBuilder::registered(&self.config, &self.openapi).build()
    }

    /// Generate documentation including registered Rust extension endpoints.
    #[must_use]
    pub fn openapi_spec_with_native_extensions(&self) -> OpenApiSpec {
        OpenApiBuilder::registered_with_native_extensions(&self.config, &self.openapi, true).build()
    }

    /// Handle core authentication requests.
    async fn handle_core_request(
        &self,
        req: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Get, core_paths::OK) => {
                Ok(Some(AuthResponse::json(200, &OkResponse { ok: true })?))
            }
            (HttpMethod::Get, core_paths::ERROR) => {
                let error_code = req
                    .query
                    .get("error")
                    .cloned()
                    .unwrap_or_else(|| "UNKNOWN".to_owned());
                let error_description = req
                    .query
                    .get("error_description")
                    .map(String::as_str)
                    .filter(|description| !description.is_empty());
                if !self.config.render_error_page {
                    return Ok(Some(AuthResponse::new(302).with_header(
                        "location",
                        core_paths::error_page_redirect_location(&error_code, error_description),
                    )));
                }
                let html =
                    core_paths::error_page_html_with_description(&error_code, error_description);
                Ok(Some(
                    AuthResponse::html(200, html).with_header("content-type", "text/html"),
                ))
            }
            (HttpMethod::Get, core_paths::OPENAPI_SPEC) => {
                let spec = self.openapi_spec();
                Ok(Some(AuthResponse::json(200, &spec)?))
            }
            (HttpMethod::Post, core_paths::UPDATE_USER) => {
                Ok(Some(self.handle_update_user(req, context).await?))
            }
            _ => Ok(None),
        }
    }

    /// Handle user profile update.
    #[expect(
        clippy::too_many_lines,
        reason = "Keep field validation and user-update callbacks adjacent to the persistence operation"
    )]
    async fn handle_update_user(
        &self,
        req: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let (current_user, current_session) =
            context.require_cached_session(req).await.map_err(|error| {
                if matches!(
                    error,
                    AuthError::Unauthenticated
                        | AuthError::SessionNotFound
                        | AuthError::UserNotFound
                ) {
                    AuthError::Upstream {
                        status: 401,
                        code: "UNAUTHORIZED",
                        message: "Unauthorized",
                    }
                } else {
                    error
                }
            })?;
        let body: serde_json::Value = req
            .body_as_json()
            .map_err(|e| AuthError::bad_request(format!("Invalid JSON: {e}")))?;
        let Some(body) = body.as_object() else {
            let actual = match &body {
                serde_json::Value::Null => "null",
                serde_json::Value::Bool(_) => "boolean",
                serde_json::Value::Number(_) => "number",
                serde_json::Value::String(_) => "string",
                serde_json::Value::Array(_) => "array",
                serde_json::Value::Object(_) => "record",
            };
            return Ok(AuthResponse::json(
                400,
                &ErrorCodeMessageResponse {
                    code: Some("VALIDATION_ERROR".to_owned()),
                    message: format!("[body] Invalid input: expected record, received {actual}"),
                },
            )?);
        };

        if body.contains_key("email") {
            return Err(AuthError::bad_request("Email can not be updated"));
        }

        let raw_body: better_auth_core::utils::json::JsValue = req.body_as_json()?;
        better_auth_api::plugins::last_login_method::reject_last_login_method_input(
            context,
            raw_body.get("lastLoginMethod"),
        )?;

        let update_req: UpdateUserRequest =
            serde_json::from_value(serde_json::Value::Object(body.clone()))
                .map_err(|e| AuthError::bad_request(format!("Invalid JSON: {e}")))?;
        let policy = context.extensions.get::<UsernameConfig>();
        if let Some(policy) = &policy {
            if let Some(value) = &update_req.username {
                policy.validate_hook_value(value).await?;
                let normalized = policy.normalize(value)?;
                let current_username = current_user.username();
                if policy.immutable_username
                    && current_username
                        .as_ref()
                        .is_some_and(|value| !value.is_empty() && *value != normalized)
                {
                    return Err(AuthError::Upstream {
                        status: 400,
                        code: "USERNAME_IS_IMMUTABLE",
                        message: "Username cannot be updated",
                    });
                }
                if let Some(existing_user) = self.store.get_user_by_username(&normalized).await?
                    && existing_user.id() != current_user.id()
                {
                    return Err(AuthError::Upstream {
                        status: 400,
                        code: "USERNAME_IS_ALREADY_TAKEN",
                        message: "Username is already taken. Please try another.",
                    });
                }
            }
            if let Some(value) = &update_req.display_username {
                policy.validate_display(value).await?;
            }
        }
        let mut input_fields = raw_body
            .as_object()
            .ok_or_else(|| AuthError::bad_request("Invalid JSON object"))?
            .clone();
        if policy.is_none() {
            drop(input_fields.shift_remove("username"));
        }
        if policy
            .as_ref()
            .is_none_or(|policy| !policy.include_display_username)
        {
            drop(input_fields.shift_remove("displayUsername"));
        }
        let additional_fields =
            context
                .parse_user_fields(&input_fields, false)
                .map_err(|error| match error {
                    better_auth_core::field_policy::FieldInputError::Validation {
                        code,
                        message,
                    } => AuthError::Api {
                        status: 400,
                        code: Some(code.into()),
                        message,
                    },
                    better_auth_core::field_policy::FieldInputError::Transform(error) => error,
                })?;
        let username = additional_fields
            .get("username")
            .and_then(better_auth_core::utils::json::JsValue::as_str)
            .map(str::to_owned);
        let display_username = additional_fields
            .get("displayUsername")
            .and_then(better_auth_core::utils::json::JsValue::as_str)
            .map(str::to_owned);

        let clear_phone = context
            .get_metadata("phone-number.enabled")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
            && body.get("phoneNumber") == Some(&serde_json::Value::Null);
        let has_changes = additional_fields.has_input_fields()
            || clear_phone
            || update_req.name.is_some()
            || update_req.image.is_some()
            || username.is_some()
            || display_username.is_some()
            || update_req.role.is_some()
            || update_req.metadata.is_some();
        if !has_changes {
            return Err(AuthError::bad_request("No fields to update"));
        }

        let update_user = UpdateUser {
            provider_email_verified: None,
            provider_name: None,
            provider_image: None,
            additional_fields,
            is_anonymous: None,
            phone_number: clear_phone.then_some(None),
            phone_number_verified: None,
            last_login_method: None,
            email: None,
            name: update_req.name,
            image: update_req.image,
            email_verified: None,
            username,
            display_username,
            role: update_req.role,
            banned: None,
            ban_reason: None,
            ban_expires: None,
            two_factor_enabled: None,
            metadata: update_req.metadata,
        };

        let publication = match self
            .store
            .update_user_record(&current_user.id(), update_user.clone())
            .await
        {
            Ok(updated_user) => better_auth_core::CacheVersionContext::created(
                updated_user.clone(),
                current_session.clone(),
                context.user_view(&updated_user),
                current_session.clone(),
            ),
            Err(AuthError::UserNotFound) => {
                // Source retains the authenticated output snapshot when the
                // adapter no longer has this user. This does not recreate a row.
                let mut user = context.user_view(&current_user);
                if let Some(name) = update_user.name {
                    user.name = Some(name);
                }
                if let Some(image) = update_user.image {
                    user.image = Some(image);
                }
                if let Some(username) = update_user.username {
                    user.username = Some(username);
                }
                if let Some(display_username) = update_user.display_username {
                    user.display_username = Some(display_username);
                }
                if let Some(role) = update_user.role {
                    user.role = Some(role);
                }
                if let Some(metadata) = update_user.metadata {
                    user.metadata = metadata;
                }
                for (name, value) in update_user.additional_fields {
                    drop(user.extension_fields.insert(name, value.to_json_value()?));
                }
                if let Some(phone_number) = update_user.phone_number {
                    user.phone_number = phone_number;
                    drop(
                        user.extension_fields
                            .insert("phoneNumber".into(), serde_json::Value::Null),
                    );
                }
                better_auth_core::CacheVersionContext::created(
                    user.clone(),
                    current_session.clone(),
                    user,
                    current_session.clone(),
                )
            }
            Err(error) => return Err(error),
        };
        better_auth_core::cache::runtime::emit_issuance_snapshot(context, publication).await?;

        let mut response =
            AuthResponse::json(200, &better_auth_core::StatusResponse { status: true })?;

        if let Some(token) = context.session_manager().extract_session_token(req) {
            let cookie_header = better_auth_core::utils::cookie_utils::create_session_cookie(
                &token,
                &context.config,
            );
            response = response.with_header("Set-Cookie", cookie_header);
        }

        Ok(response)
    }
}

async fn parse_dispatch_body(req: &AuthRequest, allowed: &[&str]) -> AuthResult<()> {
    let Some(body) = &req.body else {
        return Ok(());
    };
    let content_type = req
        .headers
        .iter()
        .find_map(|(key, value)| {
            key.eq_ignore_ascii_case("content-type")
                .then_some(value.as_str())
        })
        .unwrap_or("");
    let lower = content_type.to_ascii_lowercase();
    let base = lower.split(';').next().unwrap_or("").trim();
    if !allowed.is_empty()
        && !allowed
            .iter()
            .any(|allowed| base.contains(allowed.to_ascii_lowercase().trim()))
    {
        let message = if content_type.is_empty() {
            format!(
                "Content-Type is required. Allowed types: {}",
                allowed.join(", ")
            )
        } else {
            format!(
                "Content-Type \"{content_type}\" is not allowed. Allowed types: {}",
                allowed.join(", ")
            )
        };
        return Err(AuthError::Api {
            status: 415,
            code: Some("UNSUPPORTED_MEDIA_TYPE".into()),
            message,
        });
    }
    let json_media = lower.strip_prefix("application/").is_some_and(|suffix| {
        suffix.starts_with("json")
            || suffix.match_indices("+json").any(|(index, _)| {
                suffix[..index].bytes().all(|character| {
                    character.is_ascii_lowercase()
                        || character.is_ascii_digit()
                        || matches!(character, b'.' | b'+' | b'-')
                })
            })
    });
    let parsed = if json_media {
        Some(
            better_auth_core::utils::json::from_slice::<better_auth_core::utils::json::JsValue>(
                body,
            )
            .map_err(|_| AuthError::Upstream {
                status: 400,
                code: "BAD_REQUEST",
                message: "Invalid JSON in request body",
            })?,
        )
    } else if lower.contains("application/x-www-form-urlencoded") {
        Some(better_auth_core::utils::json::JsValue::Object(
            url::form_urlencoded::parse(body)
                .map(|(key, value)| {
                    (
                        key.into_owned(),
                        better_auth_core::utils::json::JsValue::String(value.into_owned()),
                    )
                })
                .collect(),
        ))
    } else if lower.contains("multipart/form-data") {
        // Fetch parses form-data even when additional media text follows its subtype.
        // Keep the original header; normalize only the parser's MIME prefix.
        let parameters = content_type.split_once(';').map_or("", |(_, value)| value);
        let boundary = multer::parse_boundary(format!("multipart/form-data;{parameters}"))
            .map_err(|error| {
                AuthError::CallbackFailure(Box::new(AuthError::internal(error.to_string())))
            })?;
        let mut multipart = multer::Multipart::with_reader(body.as_slice(), boundary);
        let mut fields = better_auth_core::utils::json::JsValue::Object(Default::default());
        let mut files = better_auth_core::types::MultipartFiles::default();
        while let Some(field) = multipart.next_field().await.map_err(|error| {
            AuthError::CallbackFailure(Box::new(AuthError::internal(error.to_string())))
        })? {
            let Some(name) = field.name().map(str::to_owned) else {
                continue;
            };
            let filename = field.file_name().map(str::to_owned);
            let content_type = field.content_type().map(ToString::to_string);
            let bytes = field.bytes().await.map_err(|error| {
                AuthError::CallbackFailure(Box::new(AuthError::internal(error.to_string())))
            })?;
            let value = if let Some(filename) = filename {
                drop(files.0.insert(
                    name.clone(),
                    better_auth_core::types::MultipartFile {
                        filename,
                        content_type,
                        bytes: bytes.to_vec(),
                    },
                ));
                better_auth_core::utils::json::JsValue::Object(Default::default())
            } else {
                drop(files.0.remove(&name));
                better_auth_core::utils::json::JsValue::String(
                    String::from_utf8_lossy(&bytes).into_owned(),
                )
            };
            if let better_auth_core::utils::json::JsValue::Object(object) = &mut fields {
                drop(object.insert(name, value));
            }
        }
        req.extensions().insert(files);
        Some(fields)
    } else {
        None
    };
    let decoded = if let Some(parsed) = parsed {
        better_auth_core::types::ParsedRequestBody::Value(parsed)
    } else if lower.contains("text/plain") {
        let text = String::from_utf8_lossy(body);
        better_auth_core::types::ParsedRequestBody::Value(
            better_auth_core::utils::json::JsValue::String(
                text.strip_prefix('\u{feff}').unwrap_or(&text).to_owned(),
            ),
        )
    } else {
        let kind = if lower.contains("application/octet-stream") {
            "ArrayBuffer"
        } else if lower.contains("application/pdf")
            || lower.contains("image/")
            || lower.contains("video/")
        {
            "Blob"
        } else {
            "ReadableStream"
        };
        better_auth_core::types::ParsedRequestBody::Opaque(kind)
    };
    req.extensions().insert(decoded);
    Ok(())
}

fn route_path_matches(pattern: &str, path: &str) -> bool {
    let pattern_parts = pattern.split('/');
    let mut path_parts = path.split('/');
    for part in pattern_parts {
        if part == "*" {
            return true;
        }
        let Some(actual) = path_parts.next() else {
            return false;
        };
        let parameter = part.starts_with(':') || (part.starts_with('{') && part.ends_with('}'));
        if (parameter && actual.is_empty()) || (!parameter && part != actual) {
            return false;
        }
    }
    path_parts.next().is_none()
}

impl AuthBuilder<crate::store::StatelessSchema> {
    /// Build with ephemeral user/account provisioning and cookie-only sessions.
    /// User credentials are local to this instance and lost on restart. Session
    /// cookies remain independently valid until expiry/version/key invalidation.
    #[must_use]
    pub fn without_database(mut config: AuthConfig) -> Self {
        config.session = config.session.stateless();
        config.account.store_account_cookie = true;
        Self::new(config).store(crate::store::StatelessStore::default())
    }
}
