package banksecurity.repository;

import banksecurity.model.SecurityLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SecurityLogRepository extends JpaRepository<SecurityLog, Long> {
    List<SecurityLog> findAllByUsernameOrderByCreatedAtDesc(String username);
}
