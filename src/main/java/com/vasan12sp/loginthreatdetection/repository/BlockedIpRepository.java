package com.vasan12sp.loginthreatdetection.repository;

import com.vasan12sp.loginthreatdetection.entity.BlockedIp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;


@Repository
public interface BlockedIpRepository extends JpaRepository<BlockedIp, String> {


    @Query("SELECT CASE WHEN COUNT(b) > 0 THEN true ELSE false END FROM BlockedIp b " +
           "WHERE b.ipAddress = :ip AND b.blockedUntil > :currentTime")
    boolean isIpBlocked(@Param("ip") String ip, @Param("currentTime") LocalDateTime currentTime);


    default boolean isIpBlocked(String ip) {
        return isIpBlocked(ip, LocalDateTime.now());
    }
}
