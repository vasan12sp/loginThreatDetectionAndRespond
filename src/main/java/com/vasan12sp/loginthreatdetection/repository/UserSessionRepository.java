package com.vasan12sp.loginthreatdetection.repository;

import com.vasan12sp.loginthreatdetection.entity.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;


@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, String> {

    List<UserSession> findByIpAddress(String ipAddress);

    List<UserSession> findByUsername(String username);

    void deleteByIpAddress(String ipAddress);

    void deleteByUsername(String username);
}
