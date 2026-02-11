package com.wpanther.eidasremotesigning.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.security.SecureRandom;
import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * Configuration for asynchronous task execution
 * Enables CSC API v2.0 asynchronous signing operations
 */
@Configuration
@EnableAsync
public class AsyncConfig {

    @Value("${app.async.core-pool-size:5}")
    private int corePoolSize;

    @Value("${app.async.max-pool-size:10}")
    private int maxPoolSize;

    @Value("${app.async.queue-capacity:100}")
    private int queueCapacity;

    @Value("${app.async.thread-name-prefix:async-signing-}")
    private String threadNamePrefix;

    /**
     * Creates a thread pool executor for asynchronous signing operations
     *
     * @return configured Executor for async tasks
     */
    @Bean(name = "asyncSigningExecutor")
    @Primary
    public Executor asyncSigningExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(corePoolSize);
        executor.setMaxPoolSize(maxPoolSize);
        executor.setQueueCapacity(queueCapacity);
        executor.setThreadNamePrefix(threadNamePrefix);

        // Use CallerRunsPolicy to prevent task rejection under high load
        // The calling thread will execute the task if the pool is saturated
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());

        executor.initialize();
        return executor;
    }

    /**
     * Provides a SecureRandom bean for generating secure tokens
     *
     * @return a new SecureRandom instance
     */
    @Bean
    public SecureRandom secureRandom() {
        return new SecureRandom();
    }
}
