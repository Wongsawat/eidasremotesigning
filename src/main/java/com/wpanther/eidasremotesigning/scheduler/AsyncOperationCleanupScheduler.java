package com.wpanther.eidasremotesigning.scheduler;

import com.wpanther.eidasremotesigning.entity.AsyncOperation;
import com.wpanther.eidasremotesigning.repository.AsyncOperationRepository;
import com.wpanther.eidasremotesigning.service.AsyncOperationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * Scheduled task to cleanup expired and old async operations
 * Runs periodically to maintain database hygiene
 */
@Component
@EnableScheduling
@RequiredArgsConstructor
@Slf4j
public class AsyncOperationCleanupScheduler {

    private final AsyncOperationRepository asyncOperationRepository;
    private final AsyncOperationService asyncOperationService;

    @Value("${app.async.retention-days:7}")
    private int retentionDays;

    /**
     * Mark expired operations and remove them from cache
     * Runs every hour by default (configurable via app.async.cleanup-cron)
     */
    @Scheduled(cron = "${app.async.cleanup-cron:0 0 * * * *}")
    public void cleanupExpiredOperations() {
        log.info("Starting cleanup of expired async operations");

        try {
            Instant now = Instant.now();
            List<AsyncOperation> expired = asyncOperationRepository.findByExpiresAtLessThan(now);

            int updatedCount = 0;
            for (AsyncOperation operation : expired) {
                // Only mark as expired if still in PROCESSING state
                if (AsyncOperationService.STATUS_PROCESSING.equals(operation.getStatus()) ||
                    AsyncOperationService.STATUS_CREATED.equals(operation.getStatus())) {

                    operation.setStatus(AsyncOperationService.STATUS_EXPIRED);
                    operation.setUpdatedAt(now);
                    asyncOperationRepository.save(operation);

                    // Remove from cache
                    asyncOperationService.removeFromCache(operation.getId());
                    updatedCount++;

                    log.debug("Marked operation as expired: id={}, clientId={}, type={}",
                            operation.getId(), operation.getClientId(), operation.getOperationType());
                }
            }

            log.info("Cleanup completed: {} operations marked as expired", updatedCount);

        } catch (Exception e) {
            log.error("Error during expired operations cleanup", e);
        }
    }

    /**
     * Delete old completed/failed/expired operations from database
     * Runs daily at 2 AM by default (configurable via app.async.deletion-cron)
     */
    @Scheduled(cron = "${app.async.deletion-cron:0 0 2 * * *}")
    public void deleteOldOperations() {
        log.info("Starting deletion of old async operations (retention: {} days)", retentionDays);

        try {
            Instant cutoff = Instant.now().minus(retentionDays, ChronoUnit.DAYS);

            // Find all operations older than retention period
            List<AsyncOperation> allOperations = asyncOperationRepository.findAll();

            int deletedCount = 0;
            for (AsyncOperation operation : allOperations) {
                // Only delete if:
                // 1. Operation is in terminal state (COMPLETED, FAILED, EXPIRED)
                // 2. Last update was before cutoff date
                if (operation.getUpdatedAt() != null &&
                    operation.getUpdatedAt().isBefore(cutoff)) {

                    String status = operation.getStatus();
                    if (AsyncOperationService.STATUS_COMPLETED.equals(status) ||
                        AsyncOperationService.STATUS_FAILED.equals(status) ||
                        AsyncOperationService.STATUS_EXPIRED.equals(status)) {

                        asyncOperationRepository.delete(operation);

                        // Remove from cache if present
                        asyncOperationService.removeFromCache(operation.getId());
                        deletedCount++;

                        log.debug("Deleted old operation: id={}, status={}, updatedAt={}",
                                operation.getId(), status, operation.getUpdatedAt());
                    }
                }
            }

            log.info("Deletion completed: {} old operations removed", deletedCount);

        } catch (Exception e) {
            log.error("Error during old operations deletion", e);
        }
    }
}
