package com.postprod.TrafficMirror.interceptor;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.postprod.TrafficMirror.config.MirrorProperties;
import com.postprod.TrafficMirror.security.AuditService;
import com.postprod.TrafficMirror.security.DataProtectionService;
import com.postprod.TrafficMirror.security.JwtAuthenticationService;
import com.postprod.TrafficMirror.security.SecurityValidationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.util.ContentCachingRequestWrapper;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Slf4j
@Component
@RequiredArgsConstructor
public class MirrorInterceptor implements HandlerInterceptor {
    
    private final MirrorProperties props;
    private final JwtAuthenticationService jwtService;
    private final SecurityValidationService securityValidationService;
    private final DataProtectionService dataProtectionService;
    private final AuditService auditService;
    
    private static final String JWT_HEADER = "X-Mirror-Token";
    private static final String FORWARD_URL_HEADER = "X-Forward-Url";
    private static final String JWT_HEADER_LOWER = "x-mirror-token";
    private static final String FORWARD_URL_HEADER_LOWER = "x-forward-url";
    private static final ExecutorService executor = Executors.newFixedThreadPool(10);
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    // Headers that are restricted by Java HttpClient and should not be forwarded
    private static final Set<String> RESTRICTED_HEADERS = Set.of(
             "upgrade", "via", "warning",
        "accept-encoding", "transfer-encoding", "te",
        "proxy-authenticate", "proxy-authorization", "proxy-connection",
        "expect", "upgrade-insecure-requests"
    );

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!props.isEnabled()) {
            return true; // Continue normal processing
        }
        
        String jwtToken = request.getHeader(JWT_HEADER);
        String forwardUrl = request.getHeader(FORWARD_URL_HEADER);
        
        // Check if this is a mirror request
        if (jwtToken == null || forwardUrl == null) {
            return true; // Not a mirror request, continue normal processing
        }
        
        String developerId = null;
        try {
            // Step 1: Validate JWT token
            if (!jwtService.validateToken(jwtToken)) {
                auditService.logSecurityViolation(request, "INVALID_JWT", 
                    "JWT token validation failed", null);
                sendErrorResponse(response, HttpStatus.UNAUTHORIZED, "Invalid authentication token");
                return false;
            }
            
            developerId = jwtService.extractDeveloperId(jwtToken);
            
            // Step 2: Validate security constraints
            if (!securityValidationService.validateRequest(request, forwardUrl, developerId)) {
                auditService.logSecurityViolation(request, "SECURITY_VALIDATION_FAILED", 
                    "Request failed security validation", developerId);
                sendErrorResponse(response, HttpStatus.FORBIDDEN, "Security validation failed");
                return false;
            }
            
            // Step 3: Read and sanitize request body
            ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper(request);
            String requestBody = "";
            try {
                requestBody = new String(StreamUtils.copyToByteArray(requestWrapper.getInputStream()));
            } catch (IOException e) {
                log.warn("Failed to read request body: {}", e.getMessage());
            }
            
            // Sanitize request body for PII and sensitive data
            String sanitizedBody = dataProtectionService.sanitizeRequestBody(requestBody);
            
            // Step 4: Mirror the request asynchronously
            CompletableFuture<ResponseEntity<String>> mirrorFuture = mirrorRequest(
                request, forwardUrl, sanitizedBody, developerId
            );
            
            try {
                // Wait for the mirrored response
                ResponseEntity<String> mirroredResponse = mirrorFuture.get();
                
                if (mirroredResponse != null) {
                    // Step 5: Send the mirrored response back to client
                    sendMirroredResponse(response, mirroredResponse);
                    
                    // Step 6: Log successful mirror operation
                    auditService.logMirrorRequest(request, developerId, forwardUrl, 
                        sanitizedBody, true, null);
                    
                    return false; // Stop further processing
                } else {
                    auditService.logMirrorRequest(request, developerId, forwardUrl, 
                        sanitizedBody, false, "No response received from mirror");
                    sendErrorResponse(response, HttpStatus.INTERNAL_SERVER_ERROR, 
                        "Failed to get response from mirror");
                    return false;
                }
                
            } catch (Exception e) {
                log.error("Failed to process mirror request: {}", e.getMessage(), e);
                auditService.logMirrorRequest(request, developerId, forwardUrl, 
                    sanitizedBody, false, e.getMessage());
                sendErrorResponse(response, HttpStatus.INTERNAL_SERVER_ERROR, 
                    "Mirror request processing failed");
                return false;
            }
            
        } catch (Exception e) {
            log.error("Unexpected error in mirror interceptor: {}", e.getMessage(), e);
            auditService.logMirrorRequest(request, developerId, forwardUrl, 
                null, false, e.getMessage());
            sendErrorResponse(response, HttpStatus.INTERNAL_SERVER_ERROR, 
                "Internal server error");
            return false;
        }
    }
    
    private CompletableFuture<ResponseEntity<String>> mirrorRequest(
            HttpServletRequest originalRequest, String forwardUrl, 
            String requestBody, String developerId) {
        
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Build the target URL
                String targetUrl = forwardUrl + originalRequest.getRequestURI();
                if (originalRequest.getQueryString() != null) {
                    targetUrl += "?" + originalRequest.getQueryString();
                }

                log.info(targetUrl);
                
                // Create HTTP client with security configurations
                HttpClient client = createSecureHttpClient();
                
                // Prepare headers (sanitized)
                Map<String, String> originalHeaders = extractHeaders(originalRequest);
                Map<String, String> sanitizedHeaders = dataProtectionService.sanitizeHeaders(originalHeaders);
                
                // Build the HTTP request
                HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(targetUrl))
                    .timeout(Duration.ofSeconds(30));
                
                // Add sanitized headers
                sanitizedHeaders.forEach(requestBuilder::header);
                
                // Set request method and body
                String method = originalRequest.getMethod().toUpperCase();
                switch (method) {
                    case "GET":
                        requestBuilder.GET();
                        break;
                    case "POST":
                        requestBuilder.POST(HttpRequest.BodyPublishers.ofString(requestBody));
                        break;
                    case "PUT":
                        requestBuilder.PUT(HttpRequest.BodyPublishers.ofString(requestBody));
                        break;
                    case "DELETE":
                        requestBuilder.DELETE();
                        break;
                    case "PATCH":
                        requestBuilder.method("PATCH", HttpRequest.BodyPublishers.ofString(requestBody));
                        break;
                    default:
                        requestBuilder.method(method, HttpRequest.BodyPublishers.ofString(requestBody));
                }
                
                HttpRequest httpRequest = requestBuilder.build();
                
                // Send the request
                HttpResponse<String> httpResponse = client.send(httpRequest, 
                    HttpResponse.BodyHandlers.ofString());

                
                // Create response entity
                return ResponseEntity
                    .status(httpResponse.statusCode())
                    .body(httpResponse.body());
                    
            } catch (Exception e) {
                log.error("Failed to mirror request to {}: {} ", forwardUrl, e.toString(), e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("{\"error\": \"Failed to forward request: " + e.getMessage() + "\"}");
            }
        }, executor);
    }
    
    private HttpClient createSecureHttpClient() {
        HttpClient.Builder clientBuilder = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NORMAL);
        
        // Configure SSL/TLS if required
        if (!props.getSecurity().isValidateCertificates()) {
            try {
                // Create a trust manager that accepts all certificates (for development only)
                TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() { return null; }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                        public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                    }
                };
                
                SSLContext sslContext = SSLContext.getInstance("SSL");
                sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
                clientBuilder.sslContext(sslContext);
                
            } catch (Exception e) {
                log.warn("Failed to configure SSL context: {}", e.getMessage());
            }
        }
        
        return clientBuilder.build();
    }
    
    private Map<String, String> extractHeaders(HttpServletRequest request) {
        Map<String, String> headers = new HashMap<>();
        request.getHeaderNames().asIterator().forEachRemaining(headerName -> {
            String lowerCaseHeaderName = headerName.toLowerCase();
            
            // Skip internal mirror headers and restricted headers
            if ((!JWT_HEADER_LOWER.equals(headerName)) &&
                    (!FORWARD_URL_HEADER_LOWER.equals(headerName)) &&
                    (RESTRICTED_HEADERS.contains(lowerCaseHeaderName))) {
                headers.put(headerName, request.getHeader(headerName));
            }
        });
        return headers;
    }
    
    private void sendMirroredResponse(HttpServletResponse response, 
                                    ResponseEntity<String> mirroredResponse) throws IOException {
        // Set status code
        response.setStatus(mirroredResponse.getStatusCode().value());
        
        // Set headers (excluding sensitive ones)
        mirroredResponse.getHeaders().forEach((name, values) -> 
            values.forEach(value -> response.addHeader(name, value))
        );
        
        // Set content type
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        
        // Pretty print JSON response if possible
        try {
            String responseBody = mirroredResponse.getBody();
            if (responseBody != null && !responseBody.isEmpty()) {
                Object jsonResponse = objectMapper.readValue(responseBody, Object.class);
                String prettyJson = objectMapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(jsonResponse);
                response.getWriter().write(prettyJson);
            }
        } catch (Exception e) {
            // If JSON parsing fails, send as-is
            String responseBody = mirroredResponse.getBody();
            if (responseBody != null) {
                response.getWriter().write(responseBody);
            }
        }
    }
    
    private void sendErrorResponse(HttpServletResponse response, HttpStatus status, 
                                 String message) {
        try {
            response.setStatus(status.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", message);
            errorResponse.put("status", status.value());
            errorResponse.put("timestamp", java.time.Instant.now().toString());
            
            String errorJson = objectMapper.writeValueAsString(errorResponse);
            response.getWriter().write(errorJson);
            
        } catch (IOException e) {
            log.error("Failed to send error response: {}", e.getMessage());
        }
    }
}