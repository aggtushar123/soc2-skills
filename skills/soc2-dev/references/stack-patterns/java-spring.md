# Java (Spring Boot 3 with Spring Security 6) — SOC 2 patterns

Spring Boot is the one stack here where most registry controls exist as framework features that only need to be configured correctly rather than written: Spring Security's filter chain is deny-by-default once you call `anyRequest().authenticated()`, Bean Validation runs on `@Valid` parameters, Spring Data JPA parameterizes everything, and Actuator ships health probes. The audit risk is therefore misconfiguration: `permitAll()` on a broad matcher, `csrf().disable()` copied from a tutorial, `spring.jpa.show-sql=true` in a prod profile, or a `@Query` built with string concatenation. Patterns assume Spring Boot 3.3+, Spring Security 6.3+, Jakarta Bean Validation 3 (`hibernate-validator` 8), Bucket4j 8 with `bucket4j-spring-boot-starter` (or a hand-written filter), Logback with `logstash-logback-encoder` 7, Spring Data JPA with PostgreSQL, `Argon2PasswordEncoder` / `BCryptPasswordEncoder`, Spring Boot Actuator, and AWS KMS SDK v2 for envelope keys.

## Detection

- `pom.xml` with `spring-boot-starter-web` (or `-webflux`) and `spring-boot-starter-security`; `build.gradle(.kts)` with the same coordinates. `spring-boot-starter-oauth2-resource-server` indicates JWT bearer auth. `spring-boot-starter-data-jpa` (or `-jdbc`, `-r2dbc`) for persistence.
- Lockfile: Maven has none by default (versions are pinned by the BOM plus explicit `<version>` overrides); Gradle `gradle.lockfile` after `dependencyLocking { lockAllConfigurations() }`. For SEC-03 in Maven, `dependencyManagement` with pinned versions plus the `versions-maven-plugin` rules and Dependabot suffice; for Gradle, require the lockfile.
- Layout: `src/main/java/<pkg>/` with `Application.java`; `controller/` or `web/`; `service/`; `repository/`; `domain/` or `model/` (JPA entities); `config/` (`SecurityConfig.java`, `WebConfig.java`); `security/` (filters, `UserDetailsService`); `src/main/resources/application.yml` with profile sections (`application-prod.yml`), `logback-spring.xml`, `db/migration/` (Flyway) or `db/changelog/` (Liquibase).
- Greppable markers: `@RestController`, `@RequestMapping`, `SecurityFilterChain`, `@PreAuthorize`, `@Entity`, `@Query`.

## Project scaffold for compliance

```
src/main/java/com/example/app/
  config/
    SecurityConfig.java             # AUTH-01, AUTH-05, API-06 — filter chain, public matchers, headers, CORS, CSRF
    AppProperties.java              # SEC-01, SEC-02, SEC-06 — @ConfigurationProperties, validated, no secret defaults
    JacksonConfig.java              # API-01 — FAIL_ON_UNKNOWN_PROPERTIES
  security/
    JwtAuthConverter.java           # AUTH-01, AUTH-05 — claims → authorities + tenant
    RevocationCheck.java            # AUTH-05, AUTH-07 — jti denylist validator
    TenantContext.java              # DATA-08 — per-request tenant from principal
    OwnershipEvaluator.java         # AUTH-02, AUTH-09 — PermissionEvaluator for object checks
    RateLimitFilter.java            # API-04, AUTH-06 — Bucket4j
    RequestIdFilter.java            # API-05, LOG-02 — correlation ID + MDC
  web/
    GlobalExceptionHandler.java     # API-05, SEC-06 — @RestControllerAdvice
    SecurityMeta.java               # API-07 — annotation
    RoutesManifest.java             # API-07, EVD-01 — manifest generator
    HealthIndicators.java           # LOG-06
  audit/
    AuditEvent.java, AuditService.java   # LOG-01, LOG-02 — append-only structured events
  logging/
    RedactingJsonProvider.java      # LOG-03 — logstash encoder value masker
  crypto/
    PasswordService.java            # AUTH-04, SEC-07
    FieldCipher.java                # DATA-02, SEC-07 — AES-256-GCM envelope
    EncryptedStringConverter.java   # DATA-02 — JPA AttributeConverter
  jobs/RetentionJob.java            # DATA-04, DATA-05
src/main/resources/
  application.yml, application-prod.yml   # SEC-06, LOG-04, DATA-03
  logback-spring.xml                # LOG-03, LOG-04, LOG-07
  db/migration/V*__audit_log.sql    # LOG-02 — REVOKE UPDATE/DELETE
.soc2/CONTROL_MAP.md                # EVD-01
```

## Patterns

### 1. Authentication filter chain, deny by default (AUTH-01, AUTH-05)

```java
// config/SecurityConfig.java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity                       // enables @PreAuthorize (pattern 2)
public class SecurityConfig {

    // SOC2:AUTH-01 — the complete public allow-list; everything else requires a verified token
    private static final String[] PUBLIC = {
        "/actuator/health/liveness", "/actuator/health/readiness",
        "/v1/auth/login", "/v1/auth/refresh"
    };

    @Bean
    SecurityFilterChain api(HttpSecurity http, JwtAuthConverter converter, RateLimitFilter rateLimit, RequestIdFilter requestId) throws Exception {
        http
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Bearer API: no HttpSession
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.GET, PUBLIC[0], PUBLIC[1]).permitAll()
                .requestMatchers(HttpMethod.POST, PUBLIC[2], PUBLIC[3]).permitAll()
                .requestMatchers("/actuator/**").hasRole("PLATFORM_ADMIN")
                .anyRequest().authenticated())                                              // SOC2:AUTH-01 — deny by default
            .oauth2ResourceServer(o -> o.jwt(j -> j.jwtAuthenticationConverter(converter)))
            .exceptionHandling(e -> e
                .authenticationEntryPoint(new JsonAuthEntryPoint())                          // 401 as JSON with correlation ID
                .accessDeniedHandler(new JsonAccessDeniedHandler()))                         // 403 as JSON
            .addFilterBefore(requestId, SecurityContextHolderFilter.class)
            .addFilterAfter(rateLimit, RequestIdFilter.class);
        return http.build();
    }

    // SOC2:AUTH-05 — issuer/audience pinned, 1h age ceiling, jti revocation check, 30s skew
    @Bean
    JwtDecoder jwtDecoder(AppProperties props, RevocationCheck revocation) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(props.auth().jwksUri())
            .jwsAlgorithms(a -> { a.add(SignatureAlgorithm.RS256); a.add(SignatureAlgorithm.ES256); })
            .build();
        OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(
            JwtValidators.createDefaultWithIssuer(props.auth().issuer()),
            new JwtClaimValidator<List<String>>("aud", aud -> aud != null && aud.contains(props.auth().audience())),
            new JwtTimestampValidator(Duration.ofSeconds(30)),
            jwt -> Duration.between(jwt.getIssuedAt(), jwt.getExpiresAt()).compareTo(Duration.ofHours(1)) <= 0
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "token lifetime exceeds 1h", null)),
            revocation);                                                                     // AUTH-07: deactivation revokes jti
        decoder.setJwtValidator(validator);
        return decoder;
    }
}
```

- `requestMatchers("/**").permitAll()` or `.anyRequest().permitAll()` anywhere in a chain is the finding; also watch for a second `SecurityFilterChain` bean with a higher `@Order` and a broad `securityMatcher` that shadows this one.
- Spring Security 6 requires explicit `HttpMethod` on public matchers to avoid making `DELETE /v1/auth/login` public along with `POST`.
- Default `JwtDecoder` accepts any algorithm advertised in the JWKS; restrict with `jwsAlgorithms` so an HMAC key cannot be introduced.
- For session-cookie apps (Thymeleaf/MVC), keep `SessionCreationPolicy.IF_REQUIRED`, set `server.servlet.session.timeout=30m`, `server.servlet.session.cookie.{secure,http-only,same-site}=true/true/lax`, and enable `sessionManagement().maximumSessions(1)` with a `SessionRegistry` so deactivation can expire sessions.

### 2. Authorization: role + object ownership (AUTH-02, AUTH-09, DATA-08)

```java
// security/JwtAuthConverter.java — roles become ROLE_* authorities; tenant is stored on the principal
@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    @Override public AbstractAuthenticationToken convert(Jwt jwt) {
        // SOC2:AUTH-09 — roles are discrete claims; there is no isAdmin flag on the user entity
        List<GrantedAuthority> authorities = jwt.getClaimAsStringList("roles").stream()
            .map(r -> new SimpleGrantedAuthority("ROLE_" + r.toUpperCase())).map(GrantedAuthority.class::cast).toList();
        var principal = new AppPrincipal(jwt.getSubject(), jwt.getClaimAsString("tenant_id"), jwt.getId());
        return new AppAuthenticationToken(principal, jwt, authorities);
    }
}

// security/OwnershipEvaluator.java — object-level check used by @PreAuthorize hasPermission
@Component("owns")
public class OwnershipEvaluator {
    private final InvoiceRepository invoices;
    public OwnershipEvaluator(InvoiceRepository invoices) { this.invoices = invoices; }

    // SOC2:AUTH-02 — record is loaded scoped by the principal's tenant; ownership or tenant_admin required
    // SOC2:DATA-08 — tenant_id comes from the token, never from a path/body/query parameter
    public boolean invoice(Authentication auth, UUID invoiceId) {
        AppPrincipal p = (AppPrincipal) auth.getPrincipal();
        return invoices.findByIdAndTenantId(invoiceId, p.tenantId())
            .map(inv -> inv.getOwnerId().equals(p.userId()) || auth.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_TENANT_ADMIN")))
            .orElse(false);   // false => 403; controller maps to 404 to avoid cross-tenant enumeration
    }
}

// web/InvoiceController.java
@RestController @RequestMapping("/v1/invoices")
public class InvoiceController {
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyRole('MEMBER','TENANT_ADMIN') and @owns.invoice(authentication, #id)")   // SOC2:AUTH-02
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable UUID id, @AuthenticationPrincipal AppPrincipal p) { service.delete(id, p.tenantId()); }
}

// repository/InvoiceRepository.java — every finder takes tenantId; no findById exposed
public interface InvoiceRepository extends Repository<Invoice, UUID> {
    Optional<Invoice> findByIdAndTenantId(UUID id, String tenantId);            // SOC2:DATA-08
    List<Invoice> findAllByTenantIdAndStatus(String tenantId, InvoiceStatus status, Pageable page);
}

// Hibernate @Filter as the backstop (enabled per request from TenantContext)
@Entity @FilterDef(name = "tenant", parameters = @ParamDef(name = "tenantId", type = String.class))
@Filter(name = "tenant", condition = "tenant_id = :tenantId")
public class Invoice { /* ... */ }
```

- Extend `Repository<T, ID>` (not `JpaRepository`) so `findById`, `findAll`, and `deleteById` without a tenant parameter do not exist to be misused; the scanner flags `extends JpaRepository` on tenant-scoped entities.
- Hibernate `@Filter` must be enabled on the session per request (`session.enableFilter("tenant").setParameter(...)` in a `HandlerInterceptor`); it does not apply to `em.find()` by ID or native queries. Postgres RLS with `SET LOCAL app.tenant_id` in a `DataSource` connection customizer is the stronger backstop.
- Never bind `tenantId`, `ownerId`, or `roles` from request DTOs to entities. Separate `InvoiceCreateRequest` record from the `Invoice` entity; the scanner flags `@RequestBody` on an `@Entity` type.
- `@PreAuthorize` requires `@EnableMethodSecurity`; without it the annotation is silently ignored and every method is open. Test it with `@WithMockUser` and an expected 403.

### 3. Input validation with Bean Validation, rejecting unknown fields (API-01)

```java
// config/JacksonConfig.java
@Configuration
public class JacksonConfig {
    @Bean
    Jackson2ObjectMapperBuilderCustomizer strictJson() {
        // SOC2:API-01 — unknown JSON properties are a 400, not silently ignored
        return b -> b.featuresToEnable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                     .featuresToDisable(MapperFeature.ALLOW_COERCION_OF_SCALARS)
                     .featuresToEnable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES);
    }
}

// web/dto/InvoiceCreateRequest.java — record with constraints; no tenantId/ownerId fields
public record InvoiceCreateRequest(
    @NotNull UUID customerId,
    @NotNull @Positive @Max(10_000_000) Long amountCents,
    @NotNull @Pattern(regexp = "USD|EUR|GBP") String currency,
    @Size(max = 500) String memo
) {}

// web/dto/InvoiceListQuery.java — query params bound to a validated record
public record InvoiceListQuery(
    @Pattern(regexp = "draft|sent|paid") String status,
    @Min(1) @Max(100) Integer limit,
    @Size(max = 200) String cursor
) { public InvoiceListQuery { if (limit == null) limit = 25; } }

// web/InvoiceController.java
@RestController @RequestMapping("/v1/invoices")
@Validated                                   // enables validation of path/query params on this bean
public class InvoiceController {

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public InvoiceResponse create(@Valid @RequestBody InvoiceCreateRequest body, @AuthenticationPrincipal AppPrincipal p) {
        // SOC2:API-01 — @Valid ran before this line; tenant/owner set from principal, never from body
        return service.create(body, p.tenantId(), p.userId());
    }

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public List<InvoiceResponse> list(@Valid @ModelAttribute InvoiceListQuery q, @AuthenticationPrincipal AppPrincipal p) {
        return service.list(p.tenantId(), q);
    }

    @GetMapping("/{id}")
    public InvoiceResponse get(@PathVariable @org.hibernate.validator.constraints.UUID String id, @AuthenticationPrincipal AppPrincipal p) { ... }
}
```

- `@Valid` on a nested object requires `@Valid` on the field too; collection elements need `List<@Valid Item>`. A missing inner `@Valid` is the most common way a validated DTO carries unvalidated data.
- `FAIL_ON_UNKNOWN_PROPERTIES` is Boot's default-off (`spring.jackson.deserialization.fail-on-unknown-properties=false`). Setting it as a property works too, but the customizer bean is harder to override by accident in a profile.
- `@RequestParam` validation needs `@Validated` on the controller class; `@Valid @RequestBody` works without it. `MethodArgumentNotValidException` and `ConstraintViolationException` must both be handled (pattern 6) or the default 500 with field names leaks.
- `@Pattern` on a `String` is often better than `@Enumerated` binding failures, whose default error message echoes the offending value.

### 4. Parameterized data access and the anti-pattern (API-03)

```java
// repository/InvoiceRepository.java
public interface InvoiceRepository extends Repository<Invoice, UUID> {

    // SOC2:API-03 — derived query: parameters are always bound
    Optional<Invoice> findByIdAndTenantId(UUID id, String tenantId);

    // SOC2:API-03 — JPQL with named parameters; the ILIKE wildcard is added in the parameter, not the query text
    @Query("select i from Invoice i where i.tenantId = :tenant and lower(i.number) like lower(concat('%', :term, '%')) order by i.createdAt desc")
    List<Invoice> search(@Param("tenant") String tenantId, @Param("term") String term, Pageable page);

    // SOC2:API-03 — native SQL still uses :named binds
    @Query(value = "select count(*) from invoices where tenant_id = :tenant and customer_id = :customer", nativeQuery = true)
    long countByCustomer(@Param("tenant") String tenantId, @Param("customer") UUID customerId);
}

// service/InvoiceQueryService.java — dynamic sorting through an allow-list, never a user string in the ORDER BY
@Service
public class InvoiceQueryService {
    private static final Map<String, String> SORTABLE = Map.of("created", "createdAt", "amount", "amountCents");
    private final InvoiceRepository repo;

    public List<Invoice> list(String tenantId, InvoiceListQuery q, String sortKey) {
        String property = SORTABLE.get(sortKey);
        if (property == null) throw new BadRequestException("invalid_sort");
        return repo.findAllByTenantIdAndStatus(tenantId, InvoiceStatus.valueOf(q.status()), PageRequest.of(0, q.limit(), Sort.by(property).descending()));
    }
}

// JdbcTemplate: same rule — jdbc.query("select id from invoices where tenant_id = ? and status = ?", rowMapper, tenantId, status);

// ANTI-PATTERN — flag on sight
// em.createQuery("select i from Invoice i where i.number = '" + term + "'")
// jdbc.queryForList("select * from users where email = '" + email + "'")
// new ProcessBuilder("sh", "-c", "convert " + filename)          -> new ProcessBuilder("convert", filename, "out.png")
// Runtime.getRuntime().exec("ping " + host)
```

- Grep targets: `createQuery(` / `createNativeQuery(` / `queryForList(` / `queryForObject(` / `execute(` with `+` or `String.format` / `formatted(` in the argument; `Runtime.getRuntime().exec(`; `ProcessBuilder("sh"`; `ScriptEngine`; `ognl`/`SpEL` `parseExpression` on request data.
- `Sort.by(userString)` is JPQL injection in older Spring Data; always map through an allow-list as above, or use `JpaSort.unsafe` only with a validated property name.
- Criteria API (`CriteriaBuilder`) and Querydsl are safe by construction; Specifications are the idiomatic answer to dynamic filters.
- DATA-03 on the JDBC URL: `jdbc:postgresql://host/db?ssl=true&sslmode=verify-full`. `sslmode=require` skips certificate verification; validate the URL in `AppProperties` (pattern 10).

### 5. Rate limiting and body size limits (API-04, AUTH-06)

```java
// security/RateLimitFilter.java — Bucket4j; use the Redis/JCache ProxyManager when running >1 instance
@Component
public class RateLimitFilter extends OncePerRequestFilter {
    private final ProxyManager<String> buckets;          // e.g. LettuceBasedProxyManager for Redis
    private final Set<IpAddressMatcher> trustedProxies;

    // SOC2:API-04 — global per-client limit on every endpoint
    private static final BucketConfiguration GLOBAL = BucketConfiguration.builder()
        .addLimit(Bandwidth.builder().capacity(300).refillGreedy(300, Duration.ofMinutes(1)).build()).build();
    // SOC2:AUTH-06 — credential endpoints: 10 per 15 minutes keyed by ip + identifier
    private static final BucketConfiguration LOGIN = BucketConfiguration.builder()
        .addLimit(Bandwidth.builder().capacity(10).refillIntervally(10, Duration.ofMinutes(15)).build()).build();
    private static final Set<String> CREDENTIAL_PATHS = Set.of("/v1/auth/login", "/v1/auth/reset", "/v1/auth/mfa/verify", "/v1/auth/refresh");

    @Override protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {
        String ip = clientIp(req);
        boolean credential = "POST".equals(req.getMethod()) && CREDENTIAL_PATHS.contains(req.getRequestURI());
        String key = credential ? "login:" + ip + ":" + identifierHint(req) : "global:" + ip;
        Bucket bucket = buckets.builder().build(key, () -> credential ? LOGIN : GLOBAL);
        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);
        if (!probe.isConsumed()) {
            res.setHeader("Retry-After", String.valueOf(probe.getNanosToWaitForRefill() / 1_000_000_000L));
            JsonErrors.write(res, req, HttpStatus.TOO_MANY_REQUESTS, credential ? "too_many_attempts" : "rate_limited");
            return;
        }
        res.setHeader("X-RateLimit-Remaining", String.valueOf(probe.getRemainingTokens()));
        chain.doFilter(req, res);
    }

    private String clientIp(HttpServletRequest req) {
        String peer = req.getRemoteAddr();
        if (trustedProxies.stream().anyMatch(m -> m.matches(peer))) {
            String xff = req.getHeader("X-Forwarded-For");
            if (xff != null && !xff.isBlank()) { String[] hops = xff.split(","); return hops[hops.length - 1].trim(); }
        }
        return peer;
    }
}
```

```yaml
# application.yml — SOC2:API-04 body and header limits at the container; multipart separately
server:
  max-http-request-header-size: 16KB
  tomcat:
    max-swallow-size: 1MB
    max-http-form-post-size: 100KB
    connection-timeout: 5s
spring:
  servlet:
    multipart: { max-file-size: 10MB, max-request-size: 12MB }
  codec: { max-in-memory-size: 100KB }   # WebFlux
```

- Tomcat has no direct JSON body cap; `max-http-form-post-size` covers form bodies only. Add a `ContentCachingRequestWrapper` filter that rejects `Content-Length > limit` (413) and wraps the stream with a counting `ServletInputStream` for chunked bodies.
- Bucket4j's in-memory `Bucket` is per JVM; with replicas the effective limit multiplies. Use `ProxyManager` backed by Redis/Hazelcast.
- `server.forward-headers-strategy=native` or `framework` makes `getRemoteAddr()` trust `X-Forwarded-For` from anyone. Prefer explicit trusted-proxy matching as above, or set `server.tomcat.remoteip.internal-proxies` to the LB CIDR.
- Account lockout (AUTH-06 "lockout or backoff") is separate: a `failed_login_count` + `locked_until` on the user row, checked in the `AuthenticationProvider`, reset on success, audited on lock.

### 6. Error handler: generic response + correlation ID (API-05, SEC-06)

```java
// security/RequestIdFilter.java
@Component
public class RequestIdFilter extends OncePerRequestFilter {
    private static final Pattern ID = Pattern.compile("^[A-Za-z0-9_-]{8,64}$");
    @Override protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {
        // SOC2:LOG-02 — accept a well-formed upstream ID, else mint one; MDC carries it into every log line
        String incoming = req.getHeader("X-Request-Id");
        String id = incoming != null && ID.matcher(incoming).matches() ? incoming : UUID.randomUUID().toString();
        req.setAttribute("correlationId", id);
        res.setHeader("X-Request-Id", id);
        try (MDC.MDCCloseable ignored = MDC.putCloseable("correlation_id", id)) { chain.doFilter(req, res); }
    }
}

// web/GlobalExceptionHandler.java
@RestControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    public record ErrorBody(String error, String correlationId, List<Map<String, String>> issues) {}

    private static ErrorBody body(HttpServletRequest req, String code, List<Map<String, String>> issues) {
        return new ErrorBody(code, (String) req.getAttribute("correlationId"), issues);
    }

    // SOC2:API-05 — field path + constraint only; never the rejected value
    @ExceptionHandler(MethodArgumentNotValidException.class) @ResponseStatus(HttpStatus.BAD_REQUEST)
    ErrorBody invalid(MethodArgumentNotValidException ex, HttpServletRequest req) {
        var issues = ex.getBindingResult().getFieldErrors().stream().map(f -> Map.of("field", f.getField(), "code", f.getCode())).toList();
        return body(req, "validation_failed", issues);
    }
    @ExceptionHandler(ConstraintViolationException.class) @ResponseStatus(HttpStatus.BAD_REQUEST)
    ErrorBody violation(ConstraintViolationException ex, HttpServletRequest req) {
        var issues = ex.getConstraintViolations().stream().map(v -> Map.of("field", v.getPropertyPath().toString(), "code", v.getConstraintDescriptor().getAnnotation().annotationType().getSimpleName())).toList();
        return body(req, "validation_failed", issues);
    }
    @ExceptionHandler(HttpMessageNotReadableException.class) @ResponseStatus(HttpStatus.BAD_REQUEST)
    ErrorBody unreadable(HttpServletRequest req) { return body(req, "malformed_json", List.of()); }  // Jackson message names the unknown property; do not echo it

    @ExceptionHandler(DataIntegrityViolationException.class) @ResponseStatus(HttpStatus.CONFLICT)
    ErrorBody conflict(DataIntegrityViolationException ex, HttpServletRequest req) {
        log.warn("integrity violation", ex);                     // constraint name goes to the log only
        return body(req, "conflict", List.of());
    }
    @ExceptionHandler(AccessDeniedException.class) @ResponseStatus(HttpStatus.FORBIDDEN)
    ErrorBody denied(HttpServletRequest req) { return body(req, "forbidden", List.of()); }

    // SOC2:SEC-06 — no stack trace, exception class, or message reaches the client in any profile
    @ExceptionHandler(Exception.class) @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    ErrorBody unhandled(Exception ex, HttpServletRequest req) {
        log.error("unhandled exception", ex);
        return body(req, "internal_error", List.of());
    }
}
```

```yaml
# application.yml — SOC2:SEC-06 — Boot's default error attributes must not leak
server.error: { include-message: never, include-stacktrace: never, include-binding-errors: never, include-exception: false, whitelabel.enabled: false }
```

- Spring Security exceptions (`AuthenticationException`, `AccessDeniedException` thrown inside the filter chain) do not reach `@RestControllerAdvice`; they go to the `AuthenticationEntryPoint` / `AccessDeniedHandler` configured in pattern 1, which must produce the same JSON shape with the correlation ID.
- `server.error.include-message=always` and `include-stacktrace=on-param` are the two settings tutorials turn on and nobody turns off; the scanner should flag both in any profile that is not `local`.
- `HttpMessageNotReadableException.getMessage()` includes the unrecognized field name and sometimes the offending value; never pass it through.
- WebFlux: `@ControllerAdvice` works the same; the correlation ID lives in the reactor `Context` rather than MDC, and `ServerWebExchange.getAttributes()`.

### 7. Security headers, CORS allow-list, CSRF (API-06, DATA-03)

```java
// config/SecurityConfig.java (continued inside the SecurityFilterChain bean)
http
    // SOC2:API-06 — Spring Security adds HSTS, nosniff, and frame options by default; CSP and referrer must be explicit
    .headers(h -> h
        .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).preload(true).maxAgeInSeconds(31_536_000))   // SOC2:DATA-03
        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'none'; frame-ancestors 'none'; base-uri 'none'"))
        .frameOptions(f -> f.deny())
        .referrerPolicy(r -> r.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
        .permissionsPolicyHeader(p -> p.policy("camera=(), microphone=(), geolocation=()"))
        .cacheControl(Customizer.withDefaults()))
    // SOC2:API-06 — explicit origin allow-list from properties; never "*" with credentials, never allowedOriginPatterns("*")
    .cors(c -> c.configurationSource(corsSource(props)))
    // SOC2:API-06 — CSRF stays ON for cookie sessions; for a STATELESS Bearer-only API it is disabled with a documented exception
    .csrf(csrf -> props.session().mode() == SessionMode.COOKIE
        ? csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
              .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler())        // BREACH-safe handler from Spring docs
        : csrf.disable());   // SOC2:EVD-03 — record in .soc2/EXCEPTIONS.md: Bearer tokens are not auto-sent by browsers

static CorsConfigurationSource corsSource(AppProperties props) {
    CorsConfiguration cfg = new CorsConfiguration();
    cfg.setAllowedOrigins(props.cors().origins());                                 // ["https://app.example.com"]
    cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE"));
    cfg.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Request-Id", "X-XSRF-TOKEN"));
    cfg.setAllowCredentials(true);
    cfg.setMaxAge(600L);
    UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
    src.registerCorsConfiguration("/**", cfg);
    return src;
}
```

```yaml
# application-prod.yml — SOC2:DATA-03 — TLS on the connector when not behind a terminating LB
server:
  ssl: { enabled: true, bundle: "server", protocol: TLS, enabled-protocols: "TLSv1.2,TLSv1.3" }
  forward-headers-strategy: none        # trust X-Forwarded-* only via tomcat.remoteip.internal-proxies
  tomcat.remoteip: { internal-proxies: "10\\.0\\.\\d{1,3}\\.\\d{1,3}", protocol-header: X-Forwarded-Proto, remote-ip-header: X-Forwarded-For }
```

- `csrf().disable()` on a chain that also uses `formLogin()` or `HttpSession` is the single most common Spring finding. Only stateless Bearer chains may disable it, and that needs an `.soc2/EXCEPTIONS.md` entry.
- `@CrossOrigin` on controllers with no `origins` defaults to `*`; grep `@CrossOrigin` and require it to be replaced by the central `CorsConfigurationSource`.
- The `SpaCsrfTokenRequestHandler` pattern (Spring Security reference, "Single-Page Applications") is required for SPAs on Spring Security 6; the older `withHttpOnlyFalse()` alone breaks because of BREACH protection.
- HSTS is only emitted on HTTPS requests; behind a terminating LB configure `remoteip` so Spring sees `https`, otherwise the header (and `Secure` cookies) silently disappear.

### 8. Audit logger: append-only structured events (LOG-01, LOG-02)

```java
// audit/AuditEvent.java
public record AuditEvent(
    String actorId, ActorType actorType, AuditAction action, String targetType, String targetId,
    Outcome outcome, String ip, String correlationId, String tenantId, Map<String, String> metadata) {
    public enum ActorType { USER, SERVICE, SYSTEM }
    public enum Outcome { SUCCESS, FAILURE, DENIED }
    public enum AuditAction {
        AUTH_LOGIN_SUCCESS, AUTH_LOGIN_FAILURE, AUTH_MFA_VERIFY, AUTH_LOGOUT,
        USER_PASSWORD_CHANGE, USER_ROLE_GRANT, USER_ROLE_REVOKE, USER_DEACTIVATE,
        DATA_RESTRICTED_READ, DATA_EXPORT, DATA_DELETE, ADMIN_CONFIG_CHANGE
    }
}

// audit/AuditService.java
@Service
public class AuditService {
    private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT");   // SOC2:LOG-02 — separate logger/appender from app logs
    private final JdbcTemplate auditJdbc;                                   // SOC2:LOG-02 — DataSource bound to a role with INSERT only

    public AuditService(@Qualifier("auditJdbc") JdbcTemplate auditJdbc) { this.auditJdbc = auditJdbc; }

    // SOC2:LOG-01 — the single entry point for security-relevant events; runs after the business transaction commits
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(AuditEvent e) {
        Instant ts = Instant.now();                                          // SOC2:LOG-07 — UTC
        AUDIT.info("audit", kv("actor", e.actorId()), kv("actor_type", e.actorType()), kv("action", e.action()),
            kv("target_type", e.targetType()), kv("target_id", e.targetId()), kv("outcome", e.outcome()), kv("ip", e.ip()),
            kv("correlation_id", e.correlationId()), kv("tenant_id", e.tenantId()), kv("timestamp", ts), kv("metadata", e.metadata()));
        auditJdbc.update("""
            insert into audit_log (actor_id, actor_type, action, target_type, target_id, outcome, ip, correlation_id, tenant_id, ts, metadata)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb)""",
            e.actorId(), e.actorType().name(), e.action().name(), e.targetType(), e.targetId(), e.outcome().name(),
            e.ip(), e.correlationId(), e.tenantId(), Timestamp.from(ts), toJson(e.metadata()));
    }
}

// Spring Security events feed the same table without touching the login code
@Component
public class AuthEventListener {
    @EventListener void onSuccess(AuthenticationSuccessEvent ev) { audit.record(from(ev, AuditAction.AUTH_LOGIN_SUCCESS, Outcome.SUCCESS)); }
    @EventListener void onFailure(AbstractAuthenticationFailureEvent ev) { audit.record(from(ev, AuditAction.AUTH_LOGIN_FAILURE, Outcome.FAILURE)); }
    @EventListener void onDenied(AuthorizationDeniedEvent<?> ev) { audit.record(deniedFrom(ev)); }   // requires AuthorizationEventPublisher bean
}
```

```sql
-- db/migration/V007__audit_log_append_only.sql   SOC2:LOG-02
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM app_rw, audit_writer;
CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'audit_log is append-only'; END $$ LANGUAGE plpgsql;
CREATE TRIGGER audit_log_no_change BEFORE UPDATE OR DELETE ON audit_log FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
```

- `REQUIRES_NEW` keeps the audit insert out of the business transaction so a rollback cannot erase a "success" entry and a failed audit does not break the request (decide and document which way you want that to fail).
- Register `SpringAuthorizationEventPublisher` so `AuthorizationDeniedEvent` fires for `@PreAuthorize` denials; denied events are the most valuable and most often missing.
- `metadata` is `Map<String, String>`; never `Map<String, Object>`. Passing the DTO is how card numbers end up in the audit table.
- Route the `AUDIT` logger to its own appender in `logback-spring.xml` with `additivity="false"` so it is shippable to a separate, write-restricted index.

### 9. Log redaction of secrets and PII (LOG-03, LOG-04)

```xml
<!-- src/main/resources/logback-spring.xml -->
<configuration>
  <springProfile name="!local">
    <appender name="JSON" class="ch.qos.logback.core.ConsoleAppender">
      <!-- SOC2:LOG-04 — JSON lines to stdout, shipped by the platform -->
      <encoder class="net.logstash.logback.encoder.LogstashEncoder">
        <timeZone>UTC</timeZone>                                  <!-- SOC2:LOG-07 -->
        <includeMdcKeyName>correlation_id</includeMdcKeyName>
        <includeMdcKeyName>tenant_id</includeMdcKeyName>
        <includeMdcKeyName>user_id</includeMdcKeyName>
        <customFields>{"service":"${SERVICE_NAME}","env":"${APP_ENV}"}</customFields>
        <!-- SOC2:LOG-03 — masks by key name and by value pattern before serialization -->
        <jsonGeneratorDecorator class="net.logstash.logback.mask.MaskingJsonGeneratorDecorator">
          <defaultMask>[REDACTED]</defaultMask>
          <path>*/password</path><path>*/newPassword</path><path>*/currentPassword</path>
          <path>*/token</path><path>*/refreshToken</path><path>*/accessToken</path>
          <path>*/secret</path><path>*/clientSecret</path><path>*/apiKey</path>
          <path>*/authorization</path><path>*/cookie</path><path>*/ssn</path><path>*/cardNumber</path><path>*/cvv</path>
          <value>Bearer\s+[A-Za-z0-9._~+/=-]{20,}</value>          <!-- bearer tokens in free text -->
          <value>\b(?:\d[ -]?){13,19}\b</value>                    <!-- card-like digit runs -->
          <valueMasker class="com.example.app.logging.PiiPartialMasker"/>   <!-- email/phone -> ab***@example.com -->
        </jsonGeneratorDecorator>
        <throwableConverter class="net.logstash.logback.stacktrace.ShortenedThrowableConverter"><maxDepthPerThrowable>30</maxDepthPerThrowable></throwableConverter>
      </encoder>
    </appender>
    <appender name="AUDIT" class="ch.qos.logback.core.ConsoleAppender">
      <encoder class="net.logstash.logback.encoder.LogstashEncoder"><timeZone>UTC</timeZone><customFields>{"stream":"audit"}</customFields></encoder>
    </appender>
    <logger name="AUDIT" level="INFO" additivity="false"><appender-ref ref="AUDIT"/></logger>   <!-- SOC2:LOG-02 — separate stream -->
    <logger name="org.hibernate.SQL" level="WARN"/>                                                <!-- SOC2:LOG-03 — never DEBUG in prod -->
    <logger name="org.hibernate.orm.jdbc.bind" level="WARN"/>                                      <!-- bound parameter values -->
    <logger name="org.springframework.web" level="INFO"/>
    <root level="${LOG_LEVEL:-INFO}"><appender-ref ref="JSON"/></root>
  </springProfile>
</configuration>
```

- `spring.jpa.show-sql=true` bypasses Logback entirely (it prints to stdout via `System.out`) and `org.hibernate.orm.jdbc.bind=TRACE` prints parameter values. Both belong only in `application-local.yml`; the scanner flags them in any other profile.
- `CommonsRequestLoggingFilter` with `setIncludePayload(true)` or `setIncludeQueryString(true)` logs bodies and query strings (LOG-03, DATA-06). Write an access-log filter that logs path, status, duration, and the MDC only.
- Masking is key-path based; `log.info("user: {}", user)` with a `toString()` that includes email bypasses it. Override `toString()` on entities to omit PII, or use a `@ToString.Exclude` (Lombok) on classified fields.
- `System.out.println` and `e.printStackTrace()` bypass everything. Enforce with Checkstyle `Regexp` or ErrorProne `SystemOut` as build errors.

### 10. Secrets loading with startup validation (SEC-01, SEC-02, SEC-06)

```java
// config/AppProperties.java
@ConfigurationProperties(prefix = "app")
@Validated
public record AppProperties(
    @NotNull Env env,
    @NotBlank String serviceName,
    @Valid @NotNull Auth auth,
    @Valid @NotNull Cors cors,
    @Valid @NotNull Session session,
    @Valid @NotNull Crypto crypto,
    boolean debug
) {
    public enum Env { LOCAL, TEST, PRODUCTION }
    // SOC2:SEC-01 — no default values on secrets; a missing property fails ApplicationContext startup with the NAME only
    public record Auth(@NotBlank String jwksUri, @NotBlank String issuer, @NotBlank String audience) {}
    public record Cors(@NotEmpty List<@Pattern(regexp = "https://[^*]+") String> origins) {}
    public record Session(@NotNull SessionMode mode, @Size(min = 32) String csrfSecret) {}
    public record Crypto(@NotBlank String fieldKeyId) {}    // KMS key id/alias, never key bytes

    @AssertTrue(message = "production cannot run with debug enabled")           // SOC2:SEC-06
    boolean isDebugAllowed() { return env != Env.PRODUCTION || !debug; }
}

// config/StartupGuards.java — checks that need other beans
@Component
public class StartupGuards implements SmartInitializingSingleton {
    private final AppProperties props; private final Environment env; private final DataSourceProperties ds;

    @Override public void afterSingletonsInstantiated() {
        List<String> errors = new ArrayList<>();
        // SOC2:DATA-03 — JDBC URL must verify the server certificate outside localhost
        if (!ds.getUrl().contains("localhost") && !ds.getUrl().contains("sslmode=verify-full")) errors.add("spring.datasource.url must use sslmode=verify-full");
        if (props.env() == AppProperties.Env.PRODUCTION) {
            // SOC2:SEC-06 — secure defaults enforced, not assumed
            if (!"never".equals(env.getProperty("server.error.include-stacktrace"))) errors.add("server.error.include-stacktrace must be never");
            if (Boolean.parseBoolean(env.getProperty("spring.jpa.show-sql", "false"))) errors.add("spring.jpa.show-sql must be false");
            if (!"none".equals(env.getProperty("spring.jpa.hibernate.ddl-auto", "none"))) errors.add("ddl-auto must be none in production");
            if (env.getProperty("management.endpoints.web.exposure.include", "").contains("*")) errors.add("actuator exposure must be explicit");
            if (env.getProperty("spring.security.user.password") != null) errors.add("default Spring Security user must not be configured");
        }
        if (!errors.isEmpty()) throw new IllegalStateException("invalid configuration: " + String.join("; ", errors));
    }
}
```

```yaml
# application.yml — SOC2:SEC-01 — secrets are ${ENV} references with no ":default"; local dev uses a git-ignored application-local.yml
spring:
  datasource: { url: "${DATABASE_URL}", username: "${DATABASE_USER}", password: "${DATABASE_PASSWORD}" }
  config.import: "optional:aws-secretsmanager:/prod/app/"    # spring-cloud-aws: secret manager values become properties
app:
  auth: { jwks-uri: "${AUTH_JWKS_URL}", issuer: "${AUTH_ISSUER}", audience: "${AUTH_AUDIENCE}" }
  session: { mode: "${SESSION_MODE:BEARER}", csrf-secret: "${CSRF_SECRET}" }
  crypto: { field-key-id: "${FIELD_ENCRYPTION_KEY_ID}" }
```

- `${DATABASE_PASSWORD:postgres}` is the Spring spelling of a default credential. Grep `\$\{[A-Z_]*(PASSWORD|SECRET|KEY|TOKEN)[A-Z_]*:` in every `application*.yml` and `.properties`.
- `spring.security.user.password` (the auto-generated login) must not be set anywhere; leaving it unset in a prod profile with `spring-boot-starter-security` is fine because a custom `SecurityFilterChain` disables the default user.
- `@Value("${secret}")` scattered across services defeats validation; only `AppProperties` binds secrets, and `@RefreshScope` (Spring Cloud) or a `Supplier<String>` that re-reads from the secret manager on a TTL gives SEC-02 rotation without redeploy.
- `management.endpoint.env` and `configprops` expose property values; keep them off the web exposure list or behind `PLATFORM_ADMIN` and confirm `management.endpoint.env.show-values=never`.

### 11. Password hashing and approved crypto helpers (AUTH-04, SEC-07)

```java
// crypto/PasswordService.java
@Service
public class PasswordService {
    // SOC2:AUTH-04 — argon2id (OWASP: 19 MiB, t=2, p=1); DelegatingPasswordEncoder keeps legacy bcrypt verifiable and upgrades on login
    private static final Argon2PasswordEncoder ARGON2 = new Argon2PasswordEncoder(16, 32, 1, 19 * 1024, 2);
    private static final PasswordEncoder ENCODER;
    static {
        Map<String, PasswordEncoder> encoders = Map.of("argon2", ARGON2, "bcrypt", new BCryptPasswordEncoder(12));
        DelegatingPasswordEncoder d = new DelegatingPasswordEncoder("argon2", encoders);
        d.setDefaultPasswordEncoderForMatches(new BCryptPasswordEncoder(12));
        ENCODER = d;
    }
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();

    public String hash(String plain) {
        if (plain.length() < 12 || plain.length() > 256) throw new PasswordPolicyException("password_policy");
        if (isBreached(plain)) throw new PasswordPolicyException("password_breached");
        return ENCODER.encode(plain);
    }
    public boolean matches(String plain, String stored) { return ENCODER.matches(plain, stored); }
    public boolean needsUpgrade(String stored) { return ENCODER.upgradeEncoding(stored); }

    // SOC2:AUTH-04 — HIBP k-anonymity; SHA-1 is the HIBP protocol, not storage; only 5 hex chars leave the JVM
    boolean isBreached(String plain) {
        try {
            String sha1 = HexFormat.of().withUpperCase().formatHex(MessageDigest.getInstance("SHA-1").digest(plain.getBytes(StandardCharsets.UTF_8)));
            var req = HttpRequest.newBuilder(URI.create("https://api.pwnedpasswords.com/range/" + sha1.substring(0, 5))).header("Add-Padding", "true").GET().build();
            var res = http.send(req, HttpResponse.BodyHandlers.ofString());
            return res.statusCode() == 200 && res.body().lines().anyMatch(l -> l.startsWith(sha1.substring(5)));
        } catch (Exception e) { return false; }                     // fail open on outage; log it
    }
}

// crypto/CryptoUtil.java — SOC2:SEC-07 — approved primitives only
public final class CryptoUtil {
    private static final SecureRandom RNG = new SecureRandom();
    public static String sha256Hex(byte[] data) throws NoSuchAlgorithmException { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data)); }
    public static String newToken(int bytes) { byte[] b = new byte[bytes]; RNG.nextBytes(b); return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }
    public static boolean safeEqual(String a, String b) { return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8)); }
}
```

- `new BCryptPasswordEncoder()` defaults to strength 10; the registry requires 12+. `NoOpPasswordEncoder` and `StandardPasswordEncoder` (SHA-256, deprecated) are findings on sight.
- `Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()` uses 16 MiB/t=2/p=1, which is acceptable; the explicit constructor above matches OWASP's 19 MiB recommendation.
- SEC-07 grep targets: `MessageDigest.getInstance("MD5")`, `"SHA-1"` outside HIBP, `Cipher.getInstance("AES")` (defaults to ECB), `"AES/CBC/PKCS5Padding"` without HMAC, `"DES"`, `"RC4"`, `new Random()` for tokens, `TrustManager` that returns without checking, `setHostnameVerifier((h, s) -> true)`.
- Reset and verification tokens are stored as `sha256Hex(token)` and compared with `safeEqual`; a plaintext token column is a DATA-02 finding.

### 12. Field-level encryption for a restricted column (DATA-02)

```java
// crypto/FieldCipher.java — envelope: KMS wraps a per-value data key; AES-256-GCM seals with AAD = table.column
@Component
public class FieldCipher {
    private final KmsClient kms; private final String keyId;
    public FieldCipher(KmsClient kms, AppProperties props) { this.kms = kms; this.keyId = props.crypto().fieldKeyId(); }

    // Stored: "v1.<b64 wrapped>.<b64 iv>.<b64 ct||tag>"
    // SOC2:DATA-02 SOC2:SEC-07 — AES-256-GCM under a KMS-managed key with authenticated AAD
    public String encrypt(String plain, String aad) {
        GenerateDataKeyResponse dk = kms.generateDataKey(b -> b.keyId(keyId).keySpec(DataKeySpec.AES_256));
        byte[] key = dk.plaintext().asByteArray();
        try {
            byte[] iv = new byte[12]; new SecureRandom().nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            c.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
            byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            var e = Base64.getEncoder();
            return "v1." + e.encodeToString(dk.ciphertextBlob().asByteArray()) + "." + e.encodeToString(iv) + "." + e.encodeToString(ct);
        } catch (GeneralSecurityException ex) { throw new IllegalStateException("encrypt failed", ex); }
        finally { Arrays.fill(key, (byte) 0); }
    }

    public String decrypt(String stored, String aad) {
        String[] p = stored.split("\\.");
        if (p.length != 4 || !"v1".equals(p[0])) throw new IllegalArgumentException("unknown ciphertext version");
        var d = Base64.getDecoder();
        byte[] key = kms.decrypt(b -> b.keyId(keyId).ciphertextBlob(SdkBytes.fromByteArray(d.decode(p[1])))).plaintext().asByteArray();
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, d.decode(p[2])));
            c.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
            return new String(c.doFinal(d.decode(p[3])), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException ex) { throw new IllegalStateException("decrypt failed", ex); }
        finally { Arrays.fill(key, (byte) 0); }
    }
}

// crypto/EncryptedStringConverter.java — JPA converter; AAD is table.column (row-binding needs an entity listener)
@Converter
public class EncryptedStringConverter implements AttributeConverter<String, String> {
    private static FieldCipher cipher;                       // injected via a @Component holder at startup
    @Override public String convertToDatabaseColumn(String v) { return v == null ? null : cipher.encrypt(v, "users.tax_id"); }
    @Override public String convertToEntityAttribute(String v) { return v == null ? null : cipher.decrypt(v, "users.tax_id"); }
}

// domain/User.java — SOC2:DATA-01 — tax_id: classification=restricted pii=true purpose="tax reporting" retention=7y
@Entity @Table(name = "users")
public class User {
    @Convert(converter = EncryptedStringConverter.class) @Column(name = "tax_id") @Basic(fetch = FetchType.LAZY) private String taxId;
    @Column(name = "tax_id_bidx", length = 64) private String taxIdBlindIndex;   // HMAC-SHA256 for equality lookups
}
```

- A converter decrypts transparently on every load, which makes "access to restricted data is audited" (LOG-01) hard to prove. Mark the field `@Basic(fetch = LAZY)` (needs bytecode enhancement) or keep the ciphertext in a separate entity loaded only by a repository method that also calls `audit.record(DATA_RESTRICTED_READ)`.
- `AttributeConverter` instances are not Spring beans by default; Hibernate 6 supports `@Converter` injection via `hibernate.cdi` or use a static holder set from a `@PostConstruct`, as above. Test that the converter is non-null before the first query.
- Rotation (SEC-02): repoint the KMS alias, then a job re-wraps `p[1]` for each row; ciphertext and data keys do not change.
- Do not use `Cipher.getInstance("AES")` (ECB) or `"AES/CBC/PKCS5Padding"` without an HMAC; both are SEC-07 findings. Jasypt's default `PBEWithMD5AndDES` is a finding on sight.

### 13. Retention/purge job skeleton (DATA-04, DATA-05)

```java
// jobs/RetentionJob.java — runs in a separate "jobs" deployment with its own DB role (DELETE grants); the API role has none
@Component
@Profile("jobs")
public class RetentionJob {
    private static final Logger log = LoggerFactory.getLogger(RetentionJob.class);
    private final JdbcTemplate jdbc; private final StringRedisTemplate redis; private final SearchClient search; private final AuditService audit;
    private final RetentionProperties cfg;

    // SOC2:DATA-04 — periods in configuration (app.retention.*), audit >= 365 days (LOG-04)
    @ConfigurationProperties(prefix = "app.retention") @Validated
    public record RetentionProperties(@Min(365) int auditLogDays, @Min(1) int sessionsDays, @Min(1) int resetTokenDays,
                                      @Min(1) int deletedUserGraceDays, @Min(1) int archivedInvoiceDays) {}

    @Scheduled(cron = "0 15 3 * * *", zone = "UTC")
    @SchedulerLock(name = "retention", lockAtMostFor = "PT2H")          // ShedLock: one instance runs
    public void run() {
        String correlationId = UUID.randomUUID().toString();
        MDC.put("correlation_id", correlationId);
        try {
            int sessions = jdbc.update("delete from sessions where last_seen_at < ?", cutoff(cfg.sessionsDays()));
            int resets = jdbc.update("delete from password_reset_tokens where created_at < ?", cutoff(cfg.resetTokenDays()));

            // SOC2:DATA-05 — subject erasure past grace: cascade to derived rows, cache, search index; audit per subject
            List<Map<String, Object>> users = jdbc.queryForList("select id, tenant_id from users where deleted_at < ? limit 500", cutoff(cfg.deletedUserGraceDays()));
            for (var u : users) {
                String id = u.get("id").toString(), tenant = (String) u.get("tenant_id");
                transactionTemplate.executeWithoutResult(tx -> {
                    jdbc.update("delete from user_preferences where user_id = ?", id);
                    jdbc.update("delete from api_keys where user_id = ?", id);
                    jdbc.update("delete from users where id = ?", id);              // FKs ON DELETE CASCADE cover the rest
                });
                redis.delete("user:" + id);
                search.delete("users", id);
                audit.record(new AuditEvent("retention-job", ActorType.SYSTEM, AuditAction.DATA_DELETE, "user", id, Outcome.SUCCESS, null, correlationId, tenant, Map.of()));
            }
            log.info("retention complete", kv("sessions", sessions), kv("resets", resets), kv("users", users.size()));
        } finally { MDC.clear(); }
    }

    private static Timestamp cutoff(int days) { return Timestamp.from(Instant.now().minus(days, ChronoUnit.DAYS)); }
}
```

- `@Scheduled` in the API deployment means every replica runs the job and the API's DataSource needs DELETE. Use a `jobs` profile deployed separately (or a Kubernetes CronJob invoking a `CommandLineRunner`) with ShedLock for single execution.
- Bound each pass (`limit 500`) and log counts, never row contents; run more often rather than in sweeps that hold locks.
- Backups are outside the job; DATA-05 needs the snapshot retention window documented so erased subjects are known to age out.
- Every erasure produces an audit event; a purge with no trail is indistinguishable from an attacker's `DELETE`.

### 14. Health/readiness endpoints (LOG-06)

```yaml
# application.yml — SOC2:LOG-06 — Actuator probes, minimal exposure, details only for admins
management:
  endpoints.web.exposure.include: health, info, prometheus
  endpoint.health:
    probes.enabled: true                # /actuator/health/liveness and /readiness
    show-details: when-authorized       # ok/fail only for the LB; component detail for PLATFORM_ADMIN
    show-components: when-authorized
    group:
      readiness.include: db, redis, diskSpace
      liveness.include: livenessState
  health:
    db.enabled: true
    redis.enabled: true
  server.port: 8081                     # separate management port, not exposed by the public ingress
```

```java
// web/HealthIndicators.java — custom dependency check with a hard timeout
@Component("search")
public class SearchHealthIndicator implements HealthIndicator {
    private final SearchClient client;
    @Override public Health health() {
        try {
            // SOC2:LOG-06 — bounded probe; a hung dependency must not hang the readiness endpoint
            boolean ok = CompletableFuture.supplyAsync(client::ping).get(1500, TimeUnit.MILLISECONDS);
            return ok ? Health.up().build() : Health.down().build();
        } catch (Exception e) {
            return Health.down().build();          // no e.getMessage(): hostnames and stack text stay in the log
        }
    }
}
```

- `show-details: always` publishes database product names, versions, disk paths, and exception messages to anyone who can reach the probe; `when-authorized` with the actuator matcher from pattern 1 is required.
- `DataSourceHealthIndicator` uses the pool's validation query; if the pool is exhausted it waits for `connection-timeout` (HikariCP default 30 s), which is longer than most LB probe timeouts. Set `spring.datasource.hikari.connection-timeout` to 5 s or wrap in a timeout as above.
- Keep both probes on the public allow-list (pattern 1) but everything else under `/actuator/**` behind `PLATFORM_ADMIN`; `exposure.include: "*"` is a finding.
- The other half of LOG-06 is monitoring: scrape `/actuator/prometheus` on the management port and alert on p95 and error rate against the documented SLO.

### 15. Route metadata annotation and routes manifest (API-07, EVD-01)

```java
// web/SecurityMeta.java
@Target({ElementType.METHOD, ElementType.TYPE}) @Retention(RetentionPolicy.RUNTIME) @Documented
public @interface SecurityMeta {
    enum Auth { PUBLIC, USER, TENANT_ADMIN, PLATFORM_ADMIN, SERVICE }
    enum Classification { PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED }
    Auth auth();
    Classification classification();
    String owner();            // "@payments-team"
    boolean pii() default false;
}

// usage
@DeleteMapping("/{id}")
@SecurityMeta(auth = SecurityMeta.Auth.USER, classification = SecurityMeta.Classification.CONFIDENTIAL, owner = "@payments-team", pii = true)   // SOC2:API-07
@PreAuthorize("hasAnyRole('MEMBER','TENANT_ADMIN') and @owns.invoice(authentication, #id)")
public void delete(@PathVariable UUID id, @AuthenticationPrincipal AppPrincipal p) { ... }

// web/RoutesManifest.java — ArchUnit-style test plus a generator: every handler must carry @SecurityMeta, and the
// declared auth must be consistent with @PreAuthorize / the public matcher list
@SpringBootTest @ActiveProfiles("test")
class RoutesManifestTest {
    @Autowired RequestMappingHandlerMapping mapping;

    // SOC2:EVD-01 — regenerates .soc2/routes.json; CI fails on `git diff --exit-code .soc2/`
    @Test void everyRouteDeclaresMetadataAndManifestIsCurrent() throws IOException {
        List<Map<String, Object>> routes = new ArrayList<>(); List<String> missing = new ArrayList<>();
        mapping.getHandlerMethods().forEach((info, handler) -> {
            String path = String.join(",", info.getPathPatternsCondition().getPatternValues());
            String methods = info.getMethodsCondition().getMethods().stream().map(Enum::name).sorted().collect(Collectors.joining(","));
            SecurityMeta m = Optional.ofNullable(handler.getMethodAnnotation(SecurityMeta.class)).orElse(handler.getBeanType().getAnnotation(SecurityMeta.class));
            if (m == null) { missing.add(methods + " " + path); return; }
            boolean hasPre = handler.hasMethodAnnotation(PreAuthorize.class) || handler.getBeanType().isAnnotationPresent(PreAuthorize.class);
            if (m.auth() != SecurityMeta.Auth.PUBLIC && m.auth() != SecurityMeta.Auth.USER && !hasPre) missing.add(methods + " " + path + " (auth=" + m.auth() + " but no @PreAuthorize)");
            routes.add(Map.of("methods", methods, "path", path, "auth", m.auth().name().toLowerCase(), "classification", m.classification().name().toLowerCase(), "owner", m.owner(), "pii", m.pii()));
        });
        assertThat(missing).as("routes without @SecurityMeta or with inconsistent auth").isEmpty();
        routes.sort(Comparator.comparing(r -> r.get("path") + " " + r.get("methods")));
        new ObjectMapper().writerWithDefaultPrettyPrinter().writeValue(new File(".soc2/routes.json"), Map.of("generated_at", Instant.now().toString(), "routes", routes));
    }
}
```

- Keeping the generator as a test means it runs on every CI build with no extra plumbing; the `git diff --exit-code` step after `mvn verify` is the enforcement.
- Cross-check the manifest's `auth: public` entries against the `PUBLIC` array in `SecurityConfig` (expose it as a package-visible constant) so a route cannot claim public without being on the allow-list.
- `RequestMappingHandlerMapping` excludes Actuator endpoints; list those separately from `WebEndpointsSupplier` if the auditor wants them in the manifest.
- `.soc2/CONTROL_MAP.md` should cite `RoutesManifestTest` as the generator and `.soc2/routes.json` as the evidence artifact for API-07.

## CI additions for this stack

| Job | Tool | Requirement |
|-----|------|-------------|
| `test` | `mvn -B verify` (Surefire + Failsafe, JaCoCo) or `gradle check` | CHG-02 |
| `sast` | Semgrep (`p/java`, `p/spring`, `p/owasp-top-ten`, `p/jwt`) plus SpotBugs with `find-sec-bugs`; CodeQL `java-kotlin` for deeper dataflow | SEC-04 |
| `sca` | OWASP `dependency-check` (fail on CVSS ≥ 7) or `mvn org.sonatype.ossindex.maven:ossindex-maven-plugin:audit`; Gradle `dependencyLocking` verified | SEC-03 |
| `secrets` | gitleaks (full history on `main`, diff on PRs) | SEC-01 |
| `routes-manifest` | `RoutesManifestTest` then `git diff --exit-code .soc2/` | API-07, EVD-01 |
| `container` | Trivy on the built image (Jib/Buildpacks, non-root, distroless JRE) | SEC-05 |

```yaml
# .github/workflows/ci.yml (excerpt)
name: ci
on: { pull_request: {}, push: { branches: [main] } }
permissions: { contents: read, security-events: write }
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with: { distribution: temurin, java-version: "21", cache: maven }
      - run: mvn -B -ntp verify                          # tests + JaCoCo + RoutesManifestTest
      - run: git diff --exit-code .soc2/routes.json      # SOC2:EVD-01
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with: { distribution: temurin, java-version: "21", cache: maven }
      - run: mvn -B -ntp compile com.github.spotbugs:spotbugs-maven-plugin:check -Dspotbugs.plugins=com.h3xstream.findsecbugs:findsecbugs-plugin:1.13.0   # SOC2:SEC-04
      - uses: returntocorp/semgrep-action@v1
        with: { config: "p/java p/spring p/owasp-top-ten p/jwt" }
  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with: { distribution: temurin, java-version: "21", cache: maven }
      - run: mvn -B -ntp org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=7 -DnvdApiKey=${{ secrets.NVD_API_KEY }}   # SOC2:SEC-03
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: gitleaks/gitleaks-action@v2        # SOC2:SEC-01
        env: { GITHUB_TOKEN: "${{ secrets.GITHUB_TOKEN }}" }
```

Branch protection must list `test`, `sast`, `sca`, and `secrets` as required status checks (CHG-01, CHG-02).

## Known pitfalls in this stack

- **`csrf().disable()` on a chain that uses sessions or form login.** Copied from every "REST API" tutorial; correct only for a `STATELESS` Bearer chain, and even then it needs an `.soc2/EXCEPTIONS.md` entry.
- **`permitAll()` on a broad matcher, or a second `SecurityFilterChain` that shadows the first.** `requestMatchers("/api/**").permitAll()` "for the frontend" makes the whole API public; multiple chains resolve by `@Order` and `securityMatcher`, and the first match wins.
- **`@PreAuthorize` without `@EnableMethodSecurity`.** The annotation is silently ignored and every method is open. One test with `@WithMockUser(roles = "MEMBER")` expecting 403 on an admin method catches it.
- **`server.error.include-message=always` / `include-stacktrace=on-param` and `spring.jpa.show-sql=true` in a shared profile.** The first pair leaks exception text to clients (API-05); the second prints SQL with values to stdout, bypassing Logback masking (LOG-03).
- **`extends JpaRepository` on tenant-scoped entities.** `findById`, `findAll`, and `deleteById` exist with no tenant parameter and will be called. Use `Repository<T, ID>` and declare only tenant-scoped finders (DATA-08).
- **`${SECRET:default}` placeholders and `spring.security.user.password` in YAML.** A working default credential in the repo is a SEC-01 and SEC-06 finding in one line.
- **`management.endpoints.web.exposure.include: "*"` with `show-details: always`.** `env`, `configprops`, `heapdump`, and `threaddump` become readable, and `heapdump` contains every secret in memory.
- **`new BCryptPasswordEncoder()`, `Cipher.getInstance("AES")`, Jasypt defaults.** Strength 10, ECB mode, and `PBEWithMD5AndDES` respectively; each is a one-line SEC-07 finding that nothing at runtime will complain about.
