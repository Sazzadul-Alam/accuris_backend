package com.datasoft.bkash.ea.home;

import com.datasoft.bkash.ea.dao.JdbcFunctionDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class HomeDaoImpl implements HomeDao{
    @Autowired
    private JdbcTemplate jdbcTemplate;
    @Autowired
    private JdbcFunctionDao jdbcFunctionDao;
    @Autowired
    private NamedParameterJdbcTemplate template;
    @Autowired
    private NamedParameterJdbcTemplate namedParameterJdbcTemplate;


    @Override
    public int movingToDashboard(String userId) {
        String sql = "UPDATE app_user SET is_dashboard_show = TRUE WHERE id = ? ";
        return namedParameterJdbcTemplate.getJdbcTemplate().update(sql, userId);
    }
}
