package com.datasoft.bkash.ea.service;

import com.datasoft.bkash.ea.dto.*;
import com.datasoft.bkash.ea.utils.SmtpEmailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Types;
import java.time.LocalDateTime;

@Service
public class LoginService {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private SmtpEmailService emailService;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    /**
     * PHASE 1: Email/Password verification (no OTP sent yet)
     */
    public LoginResponse loginWithPassword(LoginRequest request) {
        try {
            // Step 1: Initialize login and get user data
            UserInitData userData = loginInit(request.getEmail(), request.getIp(), request.getUserAgent());

            if (userData == null) {
                return createFailedResponse("INVALID", "User not found");
            }

            // Check account status before password verification
            if ("DISABLED".equals(userData.getStatus())) {
                return createFailedResponse("DISABLED", "Account is disabled");
            }

            if ("PENDING".equals(userData.getStatus())) {
                return createFailedResponse("PENDING", "Account is pending verification");
            }

            if ("LOCKED".equals(userData.getStatus())
                    && userData.getLockedUntil() != null
                    && userData.getLockedUntil().isAfter(LocalDateTime.now())) {
                return createFailedResponse("LOCKED", "Account is locked until " + userData.getLockedUntil());
            }

            // Step 2: Verify password
            boolean isPasswordValid = verifyPassword(request.getPassword(), userData.getPasswordHash());

            // Step 3: Call sp_cri_login (just verifies password, no OTP yet)
            return processPasswordLogin(
                    request.getEmail(),
                    isPasswordValid,
                    request.getIp(),
                    request.getUserAgent()
            );

        } catch (Exception e) {
            e.printStackTrace();
            return createFailedResponse("ERROR", "Login failed: " + e.getMessage());
        }
    }

    /**
     * PHASE 2: Request OTP (user chooses email or phone)
     */
    /**
     * PHASE 2: Request OTP
     * Aligned with sp_cri_request_signup_otp(primary_email, email_2fa, ip, user_agent, ...)
     */
    public LoginResponse requestOtp(OtpRequestRequest request) {
        return jdbcTemplate.execute((Connection conn) -> {
            // Updated call string to match your 4 IN and 5 OUT parameters
            String sql = "{call sp_cri_request_signup_otp(?, ?, ?, ?, ?, ?, ?, ?, ?)}";

            try (CallableStatement cs = conn.prepareCall(sql)) {
                // IN Parameters
                cs.setString(1, request.getEmail());       // p_primary_email

                // FIX: Use the actual 2FA email address.
                // If the user is requesting it to their primary email, pass request.getEmail().
                // If they have a separate 2FA email, pass that specific address.
                cs.setString(2, request.getEmail()); // p_email_2fa

                cs.setString(3, request.getIp());          // p_ip_text
                cs.setString(4, request.getUserAgent());   // p_user_agent

                // OUT Parameters
                cs.registerOutParameter(5, Types.BIGINT);    // o_user_id
                cs.registerOutParameter(6, Types.VARCHAR);   // o_request_status
                cs.registerOutParameter(7, Types.VARCHAR);   // o_otp
                cs.registerOutParameter(8, Types.TIMESTAMP); // o_otp_expires_at
                cs.registerOutParameter(9, Types.VARCHAR);   // o_recipient

                cs.execute();

                String status = cs.getString(6);
                LoginResponse response = new LoginResponse();
                response.setUserId(cs.getLong(5));
                response.setStatus(status);

                if ("OTP_SENT".equals(status)) {
                    String otp = cs.getString(7);
                    String recipient = cs.getString(9); // This is o_recipient from DB

                    if (cs.getTimestamp(8) != null) {
                        response.setOtpExpiresAt(cs.getTimestamp(8).toLocalDateTime());
                    }

                    // Send the email using your existing SMTP service
                    sendOtpEmail(recipient, otp);

                    response.setMessage("OTP sent to: " + maskEmail(recipient));
                } else {
                    // Logic for NO_USER, ACCOUNT_NOT_ACTIVE, or INVALID_EMAIL_2FA
                    response.setMessage(getOtpRequestStatusMessage(status));
                }

                return response;
            } catch (Exception e) {
                e.printStackTrace();
                return createFailedResponse("ERROR", "Database error during OTP request");
            }
        });
    }

    /**
     * PHASE 3: Verify OTP - Returns session/token
     */
    public LoginResponse verifyOtp(OtpVerifyRequest request) {
        return jdbcTemplate.execute((Connection conn) -> {
            try (CallableStatement cs = conn.prepareCall("{call sp_cri_verify_otp(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)}")) {
                cs.setString(1, request.getEmail());
                cs.setString(2, request.getOtp());
                cs.setInt(3, request.isRememberMe() ? 1 : 0);
                cs.setString(4, request.getIp());
                cs.setString(5, request.getUserAgent());

                cs.registerOutParameter(6, Types.BIGINT);    // o_user_id
                cs.registerOutParameter(7, Types.VARCHAR);   // o_verify_status
                cs.registerOutParameter(8, Types.BIGINT);    // o_session_id
                cs.registerOutParameter(9, Types.VARCHAR);   // o_refresh_token
                cs.registerOutParameter(10, Types.TIMESTAMP); // o_expires_at

                cs.execute();

                String status = cs.getString(7);

                LoginResponse response = new LoginResponse();
                response.setUserId(cs.getLong(6));
                response.setStatus(status);

                if ("SUCCESS".equals(status)) {
                    response.setSessionId(cs.getLong(8));
                    response.setRefreshToken(cs.getString(9));

                    if (cs.getTimestamp(10) != null) {
                        response.setExpiresAt(cs.getTimestamp(10).toLocalDateTime());
                    }
                    response.setMessage("Login successful");
                } else {
                    response.setMessage(getOtpVerifyStatusMessage(status));
                }

                return response;
            }
        });
    }

    /**
     * Call sp_cri_login_init to get user data
     */
    private UserInitData loginInit(String email, String ip, String userAgent) {
        return jdbcTemplate.execute((Connection conn) -> {
            try (CallableStatement cs = conn.prepareCall("{call sp_cri_login_init(?, ?, ?)}")) {
                cs.setString(1, email);
                cs.setString(2, ip);
                cs.setString(3, userAgent);

                boolean hasResults = cs.execute();

                if (hasResults) {
                    try (ResultSet rs = cs.getResultSet()) {
                        if (rs.next()) {
                            UserInitData data = new UserInitData();
                            data.setUserId(rs.getLong("user_id"));
                            data.setStatus(rs.getString("status"));
                            data.setEmailVerified(rs.getBoolean("email_2fa_verified"));
                            data.setPhoneVerified(rs.getBoolean("phone_verified"));
                            data.setFailedLoginCount(rs.getInt("failed_login_count"));

                            if (rs.getTimestamp("locked_until") != null) {
                                data.setLockedUntil(rs.getTimestamp("locked_until").toLocalDateTime());
                            }

                            data.setPasswordHash(rs.getString("password_hash"));

                            if (rs.getTimestamp("password_updated_at") != null) {
                                data.setPasswordUpdatedAt(rs.getTimestamp("password_updated_at").toLocalDateTime());
                            }

                            return data;
                        }
                    }
                }

                return null;
            }
        });
    }

    /**
     * Verify password using BCrypt
     */
    private boolean verifyPassword(String plainPassword, String passwordHash) {
        if (passwordHash == null || passwordHash.isEmpty()) {
            return false;
        }

        try {
            return passwordEncoder.matches(plainPassword, passwordHash);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Call sp_cri_login (just password verification, no OTP)
     */
    private LoginResponse processPasswordLogin(String email, boolean isPasswordValid,
                                               String ip, String userAgent) {
        return jdbcTemplate.execute((Connection conn) -> {
            try (CallableStatement cs = conn.prepareCall("{call sp_cri_login(?, ?, ?, ?, ?, ?)}")) {
                cs.setString(1, email);
                cs.setInt(2, isPasswordValid ? 1 : 0);
                cs.setString(3, ip);
                cs.setString(4, userAgent);

                cs.registerOutParameter(5, Types.BIGINT);    // o_user_id
                cs.registerOutParameter(6, Types.VARCHAR);   // o_login_status

                cs.execute();

                String status = cs.getString(6);

                LoginResponse response = new LoginResponse();
                response.setUserId(cs.getLong(5));
                response.setStatus(status);
                response.setMessage(getPasswordStatusMessage(status));

                return response;
            }
        });
    }

    /**
     * Send OTP via email
     */
    private void sendOtpEmail(String email, String otp) {
        try {
            String subject = "Your Login OTP Code";
            String body = buildOtpEmailBody(otp);
            String[] recipients = new String[]{email};

            emailService.sendEmail(subject, body, recipients, null, null);
        } catch (Exception e) {
            System.err.println("Failed to send OTP email to " + email + ": " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Build HTML email body for OTP
     */
    private String buildOtpEmailBody(String otp) {
        return "<html>" +
                "<body style='font-family: Arial, sans-serif;'>" +
                "<div style='max-width: 600px; margin: 0 auto; padding: 20px;'>" +
                "<h2 style='color: #333;'>Your Login OTP</h2>" +
                "<p>Your one-time password (OTP) for login is:</p>" +
                "<div style='background-color: #f4f4f4; padding: 15px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;'>" +
                otp +
                "</div>" +
                "<p style='color: #666;'>This OTP is valid for 5 minutes.</p>" +
                "<p style='color: #666;'>If you did not request this OTP, please ignore this email.</p>" +
                "<hr style='border: none; border-top: 1px solid #eee; margin: 20px 0;'>" +
                "<p style='color: #999; font-size: 12px;'>This is an automated message, please do not reply.</p>" +
                "</div>" +
                "</body>" +
                "</html>";
    }

    /**
     * Mask email for display (e.g., "j***@gmail.com")
     */
    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) return email;
        String[] parts = email.split("@");
        String username = parts[0];
        if (username.length() <= 2) return email;
        return username.charAt(0) + "***@" + parts[1];
    }

    /**
     * Mask phone for display (e.g., "***1234")
     */
    private String maskPhone(String phone) {
        if (phone == null || phone.length() < 4) return phone;
        return "***" + phone.substring(phone.length() - 4);
    }

    private LoginResponse createFailedResponse(String status, String message) {
        LoginResponse response = new LoginResponse();
        response.setStatus(status);
        response.setMessage(message);
        return response;
    }

    private String getPasswordStatusMessage(String status) {
        switch (status) {
            case "PASSWORD_VERIFIED": return "Password verified. Please choose OTP delivery method.";
            case "INVALID": return "Invalid email or password";
            case "LOCKED": return "Account is locked due to too many failed attempts";
            case "DISABLED": return "Account has been disabled";
            case "PENDING": return "Account is pending verification";
            default: return "Login failed";
        }
    }

    private String getOtpRequestStatusMessage(String status) {
        switch (status) {
            case "OTP_SENT": return "OTP sent successfully";
            case "NO_USER": return "User not found";
            case "ACCOUNT_NOT_ACTIVE": return "Account is not active";
            case "NO_EMAIL": return "No email address on file";
            case "NO_PHONE": return "No phone number on file";
            case "INVALID_METHOD": return "Invalid OTP delivery method";
            default: return "Failed to send OTP";
        }
    }

    private String getOtpVerifyStatusMessage(String status) {
        switch (status) {
            case "SUCCESS": return "Login successful";
            case "INVALID_OTP": return "Invalid OTP";
            case "EXPIRED_OTP": return "OTP has expired. Please request a new one";
            case "NO_OTP": return "No OTP generated. Please request OTP first";
            case "NO_USER": return "User not found";
            case "ACCOUNT_NOT_ACTIVE": return "Account is not active";
            default: return "OTP verification failed";
        }
    }


    public Long getUserIdByEmail(String email) {
        return jdbcTemplate.execute((Connection conn) -> {
            try (CallableStatement cs =
                         conn.prepareCall("{call get_user_id_by_email(?, ?)}")) {

                cs.setString(1, email);
                cs.registerOutParameter(2, Types.BIGINT);

                cs.execute();

                long userId = cs.getLong(2);
                return cs.wasNull() ? null : userId;

            } catch (Exception e) {
                throw new RuntimeException("Failed to get user id by email", e);
            }
        });
    }

    public UserName getUserNameById(Long id) {
        String sql = "SELECT first_name, last_name, is_dashboard_show FROM app_user WHERE id = ? LIMIT 1";

        return jdbcTemplate.query(sql, new Object[]{id}, rs -> {
            if (rs.next()) {
                UserName dto = new UserName();
                dto.setFirstName(rs.getString("first_name"));
                dto.setLastName(rs.getString("last_name"));
                dto.setDashboardShow(rs.getBoolean("is_dashboard_show"));
                return dto;
            }
            return null; // user not found
        });
    }

//    getUserNameById

}