package banksecurity.service;

import banksecurity.model.RiskLevel;
import banksecurity.model.SecurityEventType;
import banksecurity.model.SecurityLog;
import banksecurity.repository.SecurityLogRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class SecurityLogService {

    private final SecurityLogRepository securityLogRepository;

    public SecurityLogService(SecurityLogRepository securityLogRepository) {
        this.securityLogRepository = securityLogRepository;
    }

    public SecurityLog log(SecurityEventType eventType, RiskLevel riskLevel, String username, String source, String details) {
        SecurityLog securityLog = new SecurityLog();
        securityLog.setEventType(eventType);
        securityLog.setRiskLevel(riskLevel);
        securityLog.setUsername(username);
        securityLog.setSource(source);
        securityLog.setDetails(details);
        securityLog.setCreatedAt(LocalDateTime.now());
        return securityLogRepository.save(securityLog);
    }

    public List<SecurityLog> getLogsForUser(String username) {
        return securityLogRepository.findAllByUsernameOrderByCreatedAtDesc(username);
    }
}
