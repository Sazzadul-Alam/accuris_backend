package com.datasoft.bkash.ea.home;

import com.datasoft.bkash.ea.entity.User;
import com.datasoft.bkash.ea.response.ApiResponse;
import com.datasoft.bkash.ea.utils.SmtpEmailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/home")
public class HomeController {

    @Autowired
    private SmtpEmailService emailService;

    private final HomeService homeService;


    public HomeController(HomeService homeService) {
        this.homeService = homeService;
    }
    @GetMapping("/get/code")
    public String getCode(){
        return "Code-1";
    }
//    http://localhost:8181/web-backend/home/get/code

    @GetMapping(value = "/mail/send")
    public ResponseEntity<?> getAll(@RequestParam String emailId, @RequestParam String subject, @RequestParam String body) {
        try {
            String [] emailID= new String[]{emailId};
            emailService.sendEmail(subject,body, emailID,  null,  null);
            return ResponseEntity.ok().body("Email Send Successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR.value()).body(e);
        }
    }


    @PostMapping(value = "/dashboard")
    public ApiResponse movingToDashboard(@RequestParam String userId){
        try {
            return homeService.movingToDashboard(userId);
        }catch (Exception ex){
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage(), ex.getCause());
        }
    }
}
