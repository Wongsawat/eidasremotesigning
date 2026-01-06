package com.wpanther.eidasremotesigning.scheduler;

import com.wpanther.eidasremotesigning.entity.AsyncOperation;
import com.wpanther.eidasremotesigning.repository.AsyncOperationRepository;
import com.wpanther.eidasremotesigning.service.AsyncOperationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for AsyncOperationCleanupScheduler
 */
@ExtendWith(MockitoExtension.class)
class AsyncOperationCleanupSchedulerTest {

    @Mock
    private AsyncOperationRepository asyncOperationRepository;

    @Mock
    private AsyncOperationService asyncOperationService;

    @InjectMocks
    private AsyncOperationCleanupScheduler scheduler;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(scheduler, "retentionDays", 7);
    }

    @Test
    void testCleanupExpiredOperations_WithExpiredProcessingOperations() {
        // Arrange
        Instant now = Instant.now();
        Instant expiredTime = now.minus(1, ChronoUnit.HOURS);

        AsyncOperation expiredOp1 = createOperation("op1", "client1",
                AsyncOperationService.STATUS_PROCESSING, expiredTime);
        AsyncOperation expiredOp2 = createOperation("op2", "client2",
                AsyncOperationService.STATUS_CREATED, expiredTime);

        when(asyncOperationRepository.findByExpiresAtLessThan(any(Instant.class)))
                .thenReturn(Arrays.asList(expiredOp1, expiredOp2));

        // Act
        scheduler.cleanupExpiredOperations();

        // Assert
        verify(asyncOperationRepository, times(2)).save(any(AsyncOperation.class));
        verify(asyncOperationService, times(2)).removeFromCache(any(String.class));
        verify(asyncOperationService).removeFromCache("op1");
        verify(asyncOperationService).removeFromCache("op2");
    }

    @Test
    void testCleanupExpiredOperations_SkipsCompletedOperations() {
        // Arrange
        Instant expiredTime = Instant.now().minus(1, ChronoUnit.HOURS);

        AsyncOperation completedOp = createOperation("op1", "client1",
                AsyncOperationService.STATUS_COMPLETED, expiredTime);

        when(asyncOperationRepository.findByExpiresAtLessThan(any(Instant.class)))
                .thenReturn(Collections.singletonList(completedOp));

        // Act
        scheduler.cleanupExpiredOperations();

        // Assert
        verify(asyncOperationRepository, never()).save(any(AsyncOperation.class));
        verify(asyncOperationService, never()).removeFromCache(any(String.class));
    }

    @Test
    void testCleanupExpiredOperations_SkipsAlreadyExpiredOperations() {
        // Arrange
        Instant expiredTime = Instant.now().minus(1, ChronoUnit.HOURS);

        AsyncOperation alreadyExpiredOp = createOperation("op1", "client1",
                AsyncOperationService.STATUS_EXPIRED, expiredTime);

        when(asyncOperationRepository.findByExpiresAtLessThan(any(Instant.class)))
                .thenReturn(Collections.singletonList(alreadyExpiredOp));

        // Act
        scheduler.cleanupExpiredOperations();

        // Assert
        verify(asyncOperationRepository, never()).save(any(AsyncOperation.class));
        verify(asyncOperationService, never()).removeFromCache(any(String.class));
    }

    @Test
    void testCleanupExpiredOperations_NoExpiredOperations() {
        // Arrange
        when(asyncOperationRepository.findByExpiresAtLessThan(any(Instant.class)))
                .thenReturn(Collections.emptyList());

        // Act
        scheduler.cleanupExpiredOperations();

        // Assert
        verify(asyncOperationRepository, never()).save(any(AsyncOperation.class));
        verify(asyncOperationService, never()).removeFromCache(any(String.class));
    }

    @Test
    void testCleanupExpiredOperations_HandlesException() {
        // Arrange
        when(asyncOperationRepository.findByExpiresAtLessThan(any(Instant.class)))
                .thenThrow(new RuntimeException("Database error"));

        // Act - should not throw exception
        scheduler.cleanupExpiredOperations();

        // Assert
        verify(asyncOperationService, never()).removeFromCache(any(String.class));
    }

    @Test
    void testDeleteOldOperations_DeletesOldCompletedOperations() {
        // Arrange
        Instant oldTime = Instant.now().minus(10, ChronoUnit.DAYS);

        AsyncOperation oldCompletedOp = createOperation("op1", "client1",
                AsyncOperationService.STATUS_COMPLETED, oldTime);
        oldCompletedOp.setUpdatedAt(oldTime);

        when(asyncOperationRepository.findAll())
                .thenReturn(Collections.singletonList(oldCompletedOp));

        // Act
        scheduler.deleteOldOperations();

        // Assert
        verify(asyncOperationRepository).delete(oldCompletedOp);
        verify(asyncOperationService).removeFromCache("op1");
    }

    @Test
    void testDeleteOldOperations_DeletesOldFailedAndExpiredOperations() {
        // Arrange
        Instant oldTime = Instant.now().minus(10, ChronoUnit.DAYS);

        AsyncOperation oldFailedOp = createOperation("op1", "client1",
                AsyncOperationService.STATUS_FAILED, oldTime);
        oldFailedOp.setUpdatedAt(oldTime);

        AsyncOperation oldExpiredOp = createOperation("op2", "client2",
                AsyncOperationService.STATUS_EXPIRED, oldTime);
        oldExpiredOp.setUpdatedAt(oldTime);

        when(asyncOperationRepository.findAll())
                .thenReturn(Arrays.asList(oldFailedOp, oldExpiredOp));

        // Act
        scheduler.deleteOldOperations();

        // Assert
        verify(asyncOperationRepository).delete(oldFailedOp);
        verify(asyncOperationRepository).delete(oldExpiredOp);
        verify(asyncOperationService, times(2)).removeFromCache(any(String.class));
    }

    @Test
    void testDeleteOldOperations_KeepsRecentOperations() {
        // Arrange
        Instant recentTime = Instant.now().minus(3, ChronoUnit.DAYS);

        AsyncOperation recentOp = createOperation("op1", "client1",
                AsyncOperationService.STATUS_COMPLETED, recentTime);
        recentOp.setUpdatedAt(recentTime);

        when(asyncOperationRepository.findAll())
                .thenReturn(Collections.singletonList(recentOp));

        // Act
        scheduler.deleteOldOperations();

        // Assert
        verify(asyncOperationRepository, never()).delete(any(AsyncOperation.class));
        verify(asyncOperationService, never()).removeFromCache(any(String.class));
    }

    @Test
    void testDeleteOldOperations_KeepsProcessingOperations() {
        // Arrange
        Instant oldTime = Instant.now().minus(10, ChronoUnit.DAYS);

        AsyncOperation oldProcessingOp = createOperation("op1", "client1",
                AsyncOperationService.STATUS_PROCESSING, oldTime);
        oldProcessingOp.setUpdatedAt(oldTime);

        when(asyncOperationRepository.findAll())
                .thenReturn(Collections.singletonList(oldProcessingOp));

        // Act
        scheduler.deleteOldOperations();

        // Assert
        verify(asyncOperationRepository, never()).delete(any(AsyncOperation.class));
        verify(asyncOperationService, never()).removeFromCache(any(String.class));
    }

    @Test
    void testDeleteOldOperations_NoOperations() {
        // Arrange
        when(asyncOperationRepository.findAll())
                .thenReturn(Collections.emptyList());

        // Act
        scheduler.deleteOldOperations();

        // Assert
        verify(asyncOperationRepository, never()).delete(any(AsyncOperation.class));
        verify(asyncOperationService, never()).removeFromCache(any(String.class));
    }

    @Test
    void testDeleteOldOperations_HandlesException() {
        // Arrange
        when(asyncOperationRepository.findAll())
                .thenThrow(new RuntimeException("Database error"));

        // Act - should not throw exception
        scheduler.deleteOldOperations();

        // Assert
        verify(asyncOperationRepository, never()).delete(any(AsyncOperation.class));
    }

    // Helper method
    private AsyncOperation createOperation(String id, String clientId, String status, Instant expiresAt) {
        return AsyncOperation.builder()
                .id(id)
                .clientId(clientId)
                .operationType(AsyncOperationService.TYPE_SIGN_HASH)
                .status(status)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .expiresAt(expiresAt)
                .build();
    }
}
