package com.wpanther.eidasremotesigning.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wpanther.eidasremotesigning.dto.csc.CSCSignatureResponse;
import com.wpanther.eidasremotesigning.entity.AsyncOperation;
import com.wpanther.eidasremotesigning.repository.AsyncOperationRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for AsyncOperationService
 */
@ExtendWith(MockitoExtension.class)
class AsyncOperationServiceTest {

    @Mock
    private AsyncOperationRepository asyncOperationRepository;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private AsyncOperationService asyncOperationService;

    private static final String TEST_CLIENT_ID = "test-client-123";
    private static final String TEST_OPERATION_ID = "op-456";

    @BeforeEach
    void setUp() {
        // Reset cache before each test
        asyncOperationService.getOperationCache().clear();
    }

    @Test
    void testCreateOperation() {
        // Arrange
        String operationType = AsyncOperationService.TYPE_SIGN_HASH;
        int expiryMinutes = 30;

        when(asyncOperationRepository.save(any(AsyncOperation.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // Act
        AsyncOperation result = asyncOperationService.createOperation(
                TEST_CLIENT_ID, operationType, expiryMinutes);

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.getId()).isNotNull();
        assertThat(result.getClientId()).isEqualTo(TEST_CLIENT_ID);
        assertThat(result.getOperationType()).isEqualTo(operationType);
        assertThat(result.getStatus()).isEqualTo(AsyncOperationService.STATUS_PROCESSING);
        assertThat(result.getCreatedAt()).isNotNull();
        assertThat(result.getUpdatedAt()).isNotNull();
        assertThat(result.getExpiresAt()).isNotNull();
        assertThat(result.getExpiresAt()).isAfter(result.getCreatedAt());

        // Verify database save
        verify(asyncOperationRepository).save(any(AsyncOperation.class));

        // Verify cache population
        assertThat(asyncOperationService.getOperationCache()).containsKey(result.getId());
    }

    @Test
    void testUpdateOperationSuccess() throws Exception {
        // Arrange
        AsyncOperation operation = createTestOperation();
        CSCSignatureResponse resultData = CSCSignatureResponse.builder()
                .signatures(new String[]{"signature1", "signature2"})
                .signatureAlgorithm("SHA256withRSA")
                .build();

        byte[] serializedData = "{\"signatures\":[\"signature1\",\"signature2\"]}".getBytes();

        when(asyncOperationRepository.findById(TEST_OPERATION_ID))
                .thenReturn(Optional.of(operation));
        when(objectMapper.writeValueAsBytes(resultData))
                .thenReturn(serializedData);
        when(asyncOperationRepository.save(any(AsyncOperation.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // Act
        asyncOperationService.updateOperationSuccess(TEST_OPERATION_ID, resultData);

        // Assert
        ArgumentCaptor<AsyncOperation> captor = ArgumentCaptor.forClass(AsyncOperation.class);
        verify(asyncOperationRepository).save(captor.capture());

        AsyncOperation saved = captor.getValue();
        assertThat(saved.getStatus()).isEqualTo(AsyncOperationService.STATUS_COMPLETED);
        assertThat(saved.getResultData()).isEqualTo(serializedData);
        assertThat(saved.getUpdatedAt()).isNotNull();

        // Verify cache update
        assertThat(asyncOperationService.getOperationCache().get(TEST_OPERATION_ID))
                .isNotNull()
                .extracting(AsyncOperation::getStatus)
                .isEqualTo(AsyncOperationService.STATUS_COMPLETED);
    }

    @Test
    void testUpdateOperationFailure() {
        // Arrange
        AsyncOperation operation = createTestOperation();
        String errorMessage = "Signing failed: Invalid PIN";

        when(asyncOperationRepository.findById(TEST_OPERATION_ID))
                .thenReturn(Optional.of(operation));
        when(asyncOperationRepository.save(any(AsyncOperation.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // Act
        asyncOperationService.updateOperationFailure(TEST_OPERATION_ID, errorMessage);

        // Assert
        ArgumentCaptor<AsyncOperation> captor = ArgumentCaptor.forClass(AsyncOperation.class);
        verify(asyncOperationRepository).save(captor.capture());

        AsyncOperation saved = captor.getValue();
        assertThat(saved.getStatus()).isEqualTo(AsyncOperationService.STATUS_FAILED);
        assertThat(saved.getErrorMessage()).isEqualTo(errorMessage);
        assertThat(saved.getUpdatedAt()).isNotNull();

        // Verify cache update
        assertThat(asyncOperationService.getOperationCache().get(TEST_OPERATION_ID))
                .isNotNull()
                .extracting(AsyncOperation::getStatus)
                .isEqualTo(AsyncOperationService.STATUS_FAILED);
    }

    @Test
    void testGetOperationFromCache() {
        // Arrange
        AsyncOperation cachedOperation = createTestOperation();
        asyncOperationService.getOperationCache().put(TEST_OPERATION_ID, cachedOperation);

        // Act
        Optional<AsyncOperation> result = asyncOperationService.getOperation(
                TEST_OPERATION_ID, TEST_CLIENT_ID);

        // Assert
        assertThat(result).isPresent();
        assertThat(result.get()).isEqualTo(cachedOperation);

        // Verify database was NOT accessed (cache hit)
        verify(asyncOperationRepository, never()).findByIdAndClientId(any(), any());
    }

    @Test
    void testGetOperationFromDatabase() {
        // Arrange
        AsyncOperation dbOperation = createTestOperation();

        when(asyncOperationRepository.findByIdAndClientId(TEST_OPERATION_ID, TEST_CLIENT_ID))
                .thenReturn(Optional.of(dbOperation));

        // Act
        Optional<AsyncOperation> result = asyncOperationService.getOperation(
                TEST_OPERATION_ID, TEST_CLIENT_ID);

        // Assert
        assertThat(result).isPresent();
        assertThat(result.get()).isEqualTo(dbOperation);

        // Verify database was accessed (cache miss)
        verify(asyncOperationRepository).findByIdAndClientId(TEST_OPERATION_ID, TEST_CLIENT_ID);

        // Verify cache was populated
        assertThat(asyncOperationService.getOperationCache()).containsKey(TEST_OPERATION_ID);
    }

    @Test
    void testGetOperationNotFound() {
        // Arrange
        when(asyncOperationRepository.findByIdAndClientId(TEST_OPERATION_ID, TEST_CLIENT_ID))
                .thenReturn(Optional.empty());

        // Act
        Optional<AsyncOperation> result = asyncOperationService.getOperation(
                TEST_OPERATION_ID, TEST_CLIENT_ID);

        // Assert
        assertThat(result).isEmpty();
        verify(asyncOperationRepository).findByIdAndClientId(TEST_OPERATION_ID, TEST_CLIENT_ID);
    }

    @Test
    void testGetOperationClientMismatch() {
        // Arrange
        AsyncOperation cachedOperation = createTestOperation();
        asyncOperationService.getOperationCache().put(TEST_OPERATION_ID, cachedOperation);

        // Act - request with different client ID
        Optional<AsyncOperation> result = asyncOperationService.getOperation(
                TEST_OPERATION_ID, "different-client");

        // Assert
        assertThat(result).isEmpty();

        // Verify database was NOT accessed (security check failed on cache)
        verify(asyncOperationRepository, never()).findByIdAndClientId(any(), any());
    }

    @Test
    void testRemoveFromCache() {
        // Arrange
        AsyncOperation cachedOperation = createTestOperation();
        asyncOperationService.getOperationCache().put(TEST_OPERATION_ID, cachedOperation);

        // Act
        asyncOperationService.removeFromCache(TEST_OPERATION_ID);

        // Assert
        assertThat(asyncOperationService.getOperationCache()).doesNotContainKey(TEST_OPERATION_ID);
    }

    @Test
    void testDeserializeResult() throws Exception {
        // Arrange
        byte[] serializedData = "{\"signatures\":[\"sig1\"],\"signatureAlgorithm\":\"SHA256withRSA\"}".getBytes();
        CSCSignatureResponse expectedResult = CSCSignatureResponse.builder()
                .signatures(new String[]{"sig1"})
                .signatureAlgorithm("SHA256withRSA")
                .build();

        when(objectMapper.readValue(serializedData, CSCSignatureResponse.class))
                .thenReturn(expectedResult);

        // Act
        CSCSignatureResponse result = asyncOperationService.deserializeResult(
                serializedData, CSCSignatureResponse.class);

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.getSignatureAlgorithm()).isEqualTo("SHA256withRSA");
        verify(objectMapper).readValue(serializedData, CSCSignatureResponse.class);
    }

    @Test
    void testDeserializeResultFailure() throws Exception {
        // Arrange
        byte[] invalidData = "invalid json".getBytes();

        when(objectMapper.readValue(invalidData, CSCSignatureResponse.class))
                .thenThrow(new RuntimeException("JSON parse error"));

        // Act & Assert
        assertThatThrownBy(() ->
                asyncOperationService.deserializeResult(invalidData, CSCSignatureResponse.class))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Failed to deserialize result");
    }

    // Helper method
    private AsyncOperation createTestOperation() {
        return AsyncOperation.builder()
                .id(TEST_OPERATION_ID)
                .clientId(TEST_CLIENT_ID)
                .operationType(AsyncOperationService.TYPE_SIGN_HASH)
                .status(AsyncOperationService.STATUS_PROCESSING)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(1800))
                .build();
    }
}
