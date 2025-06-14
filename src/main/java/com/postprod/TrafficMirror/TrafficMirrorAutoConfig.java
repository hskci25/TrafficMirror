package com.postprod.TrafficMirror;


import com.postprod.TrafficMirror.config.MirrorProperties;
import com.postprod.TrafficMirror.interceptor.MirrorInterceptor;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@RequiredArgsConstructor
@EnableConfigurationProperties(MirrorProperties.class)
@ConditionalOnProperty(prefix = "traffic-mirror", name = "enabled", havingValue = "true")
public class TrafficMirrorAutoConfig implements WebMvcConfigurer {
    private final MirrorInterceptor interceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(interceptor);
    }
}