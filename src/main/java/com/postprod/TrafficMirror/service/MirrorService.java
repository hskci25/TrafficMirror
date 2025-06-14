//package com.postprod.TrafficMirror.service;
//
//import com.fasterxml.jackson.databind.ObjectMapper;
//import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
//import com.postprod.TrafficMirror.config.MirrorProperties;
//import com.postprod.TrafficMirror.interceptor.MirrorInterceptor;
//import com.postprod.TrafficMirror.model.MirroredRequest;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.http.*;
//import org.springframework.stereotype.Service;
//import org.springframework.web.client.RestTemplate;
//
//import java.util.concurrent.CompletableFuture;
//import java.util.concurrent.ExecutorService;
//import java.util.concurrent.Executors;
//
//@Slf4j
//@Service
//@RequiredArgsConstructor
//public class MirrorService {
//    private final MirrorProperties props;
//    private final RestTemplate restTemplate;
//    private static final ExecutorService executor = Executors.newSingleThreadExecutor();
//    private static final ObjectMapper objectMapper = new ObjectMapper()
//            .registerModule(new JavaTimeModule());
//
//    public void forward(MirroredRequest request) {
//        if (!props.isEnabled()) {
//            log.debug("Traffic mirroring is disabled");
//            return;
//        }
//
//        CompletableFuture.runAsync(() -> {
//            try {
//                String url = props.getForwardUrl() + request.getPath();
//                log.info("Forwarding request to {}: {} {}", url, request.getMethod(), request.getPath());
//
//                HttpHeaders headers = new HttpHeaders();
//                headers.setContentType(MediaType.APPLICATION_JSON);
//                request.getHeaders().forEach(headers::add);
//
//                String body = objectMapper.writeValueAsString(request);
//                HttpEntity<String> entity = new HttpEntity<>(body, headers);
//
//                restTemplate.exchange(
//                        url,
//                        HttpMethod.valueOf(request.getMethod()),
//                        entity,
//                        String.class
//                );
//            } catch (Exception e) {
//                log.error("Failed to forward request: {}", e.getMessage(), e);
//            }
//        }, executor);
//    }
//}