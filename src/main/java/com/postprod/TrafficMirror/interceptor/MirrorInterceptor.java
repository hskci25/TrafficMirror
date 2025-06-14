package com.postprod.TrafficMirror.interceptor;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.postprod.TrafficMirror.config.MirrorProperties;
import com.postprod.TrafficMirror.model.MirroredRequest;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.util.StreamUtils;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.io.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Component
@RequiredArgsConstructor
public class MirrorInterceptor implements HandlerInterceptor {
    private final MirrorProperties props;
    private static final Logger logger = LoggerFactory.getLogger(MirrorInterceptor.class);
    private static final String FORWARD_URL_HEADER = "X-Forward-Url";
    private static final ExecutorService executor = Executors.newFixedThreadPool(10);
    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        String sessionId = request.getHeader("X-Debug-Session");
        Map<String, String> allHeaders = props.getHeaders();

        if (props.isEnabled() && sessionId != null && sessionId.equals(props.getHeaders().get("X-Debug-Session"))) {
            logger.info("1");
            ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper(request);
            String body = "";
            try {
                body = new String(StreamUtils.copyToByteArray(requestWrapper.getInputStream()));
            } catch (IOException e) {
                logger.warn("Failed to read request body: {}", e.getMessage());
            }
            logger.info("body ---> " + body);

            if (!body.isEmpty()) {
                logger.info("2");
                // Start async forwarding
                CompletableFuture<ResponseEntity<String>> forwardedResponseFuture = mirrorRequest(request.getRequestURI(), request.getMethod(), body, request);
                
                // Wait for the response
                try {
                    ResponseEntity<String> forwardedResponse = forwardedResponseFuture.get();
                    if (forwardedResponse != null) {
                        try {
                            // Copy the status code
                            response.setStatus(forwardedResponse.getStatusCode().value());
                            
                            // Copy all headers
                            forwardedResponse.getHeaders().forEach((name, values) -> 
                                values.forEach(value -> response.addHeader(name, value))
                            );
                            
                            // Set content type to application/json
                            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                            
                            // Parse and pretty print the JSON response
                            Object jsonResponse = objectMapper.readValue(forwardedResponse.getBody(), Object.class);
                            String prettyJson = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonResponse);
                            
                            // Write the pretty printed JSON response
                            response.getWriter().write(prettyJson);
                            
                            // Return false to stop further processing
                            return false;
                        } catch (IOException e) {
                            logger.error("Failed to write response: {}", e.getMessage(), e);
                        }
                    }
                } catch (Exception e) {
                    logger.error("Failed to get forwarded response: {}", e.getMessage(), e);
                    return false;
                }
            }
        }
        return true;
    }

    private CompletableFuture<ResponseEntity<String>> mirrorRequest(String path, String method, String body, HttpServletRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                logger.info("3");
                String forwardUrl = request.getHeader(FORWARD_URL_HEADER);
                if (forwardUrl == null || forwardUrl.isEmpty()) {
                    logger.error("Forward URL header {} is missing", FORWARD_URL_HEADER);
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body("{\"error\": \"Forward URL header is required\"}");
                }

                HttpClient client = HttpClient.newHttpClient();
                HttpRequest httpRequest = HttpRequest.newBuilder()
                        .uri(URI.create(forwardUrl + path))
                        .method(method, HttpRequest.BodyPublishers.ofString(body))
                        .header("Content-Type", "application/json")
                        .build();
                logger.info("4");
                
                HttpResponse<String> httpResponse = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
                
                // Convert the HttpResponse to ResponseEntity
                return ResponseEntity
                        .status(httpResponse.statusCode())
                        .body(httpResponse.body());
                        
            } catch (Exception e) {
                logger.error("Failed to mirror request: {}", e.getMessage(), e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("{\"error\": \"Failed to forward request: " + e.getMessage() + "\"}");
            }
        }, executor);
    }
}