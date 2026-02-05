package com.datasoft.bkash.ea.home;

import com.datasoft.bkash.ea.response.ApiResponse;
import jakarta.persistence.criteria.CriteriaBuilder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Slf4j
@Service
public class HomeServiceImpl implements HomeService{
    private final HomeDao homeDao;

    public HomeServiceImpl(HomeDao homeDao) {
        this.homeDao = homeDao;
    }

    @Override
    public ApiResponse movingToDashboard(String userId) {
        try{
             homeDao.movingToDashboard(userId);
            return new ApiResponse(HttpStatus.OK.value(), "Memo Deleted Successfully", null);
        }catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage(), ex.getCause());
        }
    }
}
