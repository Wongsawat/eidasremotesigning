package com.wpanther.eidasremotesigning.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wpanther.eidasremotesigning.entity.AsyncOperation;
import com.wpanther.eidasremotesigning.repository.AsyncOperationRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service for managing asynchronous operations
 * Implements dual storage strategy: in-memory cache + database persistence
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AsyncOperationService {

    private final AsyncOperationRepository asyncOperationRepository;
    private final ObjectMapper objectMapper;

    // In-memory cache for fast lookups
    private final Map<String, AsyncOperation> operationCache = new ConcurrentHashMap<>();

    @Value("${app.async.operation-expiry-minutes:30}")
    private int operationExpiryMinutes;

    // Operation status constants
    public static final String STATUS_CREATED = "CREATED";
    public static final String STATUS_PROCESSING = "PROCESSING";
    public static final String STATUS_COMPLETED = "COMPLETED";
    public static final String STATUS_FAILED = "FAILED";
    public static final String STATUS_EXPIRED = "EXPIRED";

    // Operation type constants
    public static final String TYPE_SIGN_HASH = "SIGN_HASH";
    public static final String TYPE_SIGN_DOCUMENT = "SIGN_DOCUMENT";
    public static final String TYPE_TIMESTAMP = "TIMESTAMP";

    /**
     * Create a new async operation
     *
     * @param clientId        OAuth2 client ID
     * @param operationType   Type of operation (SIGN_HASH, SIGN_DOCUMENT, TIMESTAMP)
     * @param expiryMinutes   Minutes until operation expires
     * @return created AsyncOperation entity
     */
    @Transactional
    public AsyncOperation createOperation(String clientId, String operationType, int expiryMinutes) {
        String operationId = UUID.randomUUID().toString();
        Instant now = Instant.now();
        Instant expiresAt = now.plus(expiryMinutes, ChronoUnit.MINUTES);

        AsyncOperation operation = AsyncOperation.builder()
                .id(operationId)
                .clientId(clientId)
                .operationType(operationType)
                .status(STATUS_PROCESSING)
                .createdAt(now)
                .updatedAt(now)
                .expiresAt(expiresAt)
                .build();

        // Save to database
        asyncOperationRepository.save(operation);

        // Add to cache
        operationCache.put(operationId, operation);

        log.info("Created async operation: id={}, clientId={}, type={}, expiresAt={}",
                operationId, clientId, operationType, expiresAt);

        return operation;
    }

    /**
     * Update operation with successful result
     *
     * @param operationId   Operation ID
     * @param resultData    Result object to serialize and store
     */
    @Transactional
    public void updateOperationSuccess(String operationId, Object resultData) {
        try {
            AsyncOperation operation = asyncOperationRepository.findById(operationId)
                    .orElseThrow(() -> new IllegalArgumentException("Operation not found: " + operationId));

            // Serialize result to JSON
            byte[] serializedResult = objectMapper.writeValueAsBytes(resultData);

            operation.setStatus(STATUS_COMPLETED);
            operation.setResultData(serializedResult);
            operation.setUpdatedAt(Instant.now());

            asyncOperationRepository.save(operation);

            // Update cache
            operationCache.put(operationId, operation);

            log.info("Operation completed successfully: id={}", operationId);

        } catch (Exception e) {
            log.error("Error updating operation success: id={}", operationId, e);
            updateOperationFailure(operationId, "Failed to serialize result: " + e.getMessage());
        }
    }

    /**
     * Update operation with failure
     *
     * @param operationId     Operation ID
     * @param errorMessage    Error message
     */
    @Transactional
    public void updateOperationFailure(String operationId, String errorMessage) {
        try {
            AsyncOperation operation = asyncOperationRepository.findById(operationId)
                    .orElseThrow(() -> new IllegalArgumentException("Operation not found: " + operationId));

            operation.setStatus(STATUS_FAILED);
            operation.setErrorMessage(errorMessage);
            operation.setUpdatedAt(Instant.now());

            asyncOperationRepository.save(operation);

            // Update cache
            operationCache.put(operationId, operation);

            log.error("Operation failed: id={}, error={}", operationId, errorMessage);

        } catch (Exception e) {
            log.error("Error updating operation failure: id={}", operationId, e);
        }
    }

    /**
     * Get operation by ID with client validation
     * Uses cache-aside pattern: check cache first, fall back to database
     *
     * @param operationId   Operation ID
     * @param clientId      Client ID for validation
     * @return Optional containing operation if found and belongs to client
     */
    @Transactional(readOnly = true)
    public Optional<AsyncOperation> getOperation(String operationId, String clientId) {
        // Check cache first (fast path)
        AsyncOperation cachedOp = operationCache.get(operationId);
        if (cachedOp != null) {
            if (cachedOp.getClientId().equals(clientId)) {
                log.debug("Cache hit for operation: id={}", operationId);
                return Optional.of(cachedOp);
            } else {
                log.warn("Operation found in cache but client mismatch: id={}, expected={}, actual={}",
                        operationId, clientId, cachedOp.getClientId());
                return Optional.empty();
            }
        }

        // Cache miss - check database
        log.debug("Cache miss for operation: id={}, checking database", operationId);
        Optional<AsyncOperation> dbOp = asyncOperationRepository.findByIdAndClientId(operationId, clientId);

        // Populate cache if found
        dbOp.ifPresent(op -> {
            operationCache.put(operationId, op);
            log.debug("Loaded operation from database and cached: id={}", operationId);
        });

        return dbOp;
    }

    /**
     * Deserialize result data from byte array
     *
     * @param resultData    Serialized result data
     * @param resultClass   Class to deserialize into
     * @param <T>           Result type
     * @return Deserialized object
     */
    public <T> T deserializeResult(byte[] resultData, Class<T> resultClass) {
        try {
            return objectMapper.readValue(resultData, resultClass);
        } catch (Exception e) {
            log.error("Error deserializing result data to class: {}", resultClass.getName(), e);
            throw new RuntimeException("Failed to deserialize result: " + e.getMessage(), e);
        }
    }

    /**
     * Remove operation from cache
     *
     * @param operationId   Operation ID to remove
     */
    public void removeFromCache(String operationId) {
        AsyncOperation removed = operationCache.remove(operationId);
        if (removed != null) {
            log.debug("Removed operation from cache: id={}", operationId);
        }
    }

    /**
     * Get cache for direct access (used by CSCSignatureService for backward compatibility)
     *
     * @return operation cache map
     */
    public Map<String, AsyncOperation> getOperationCache() {
        return operationCache;
    }
}
