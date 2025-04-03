package com.wpanther.eidasremotesigning.repository;

import com.wpanther.eidasremotesigning.entity.OAuth2Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OAuth2ClientRepository extends JpaRepository<OAuth2Client, String> {
    Optional<OAuth2Client> findByClientId(String clientId);
    boolean existsByClientId(String clientId);
}