package com.swig.manda.config.auth;

import com.swig.manda.model.Member;
import com.swig.manda.repository.MemberRepository;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@Data
public class PrincipalDetailsService implements UserDetailsService {

   @Autowired
   private MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String userid) throws UsernameNotFoundException {
        Member member = memberRepository.findByUserid(userid);

        if(member !=null){
            return new PrincipalDetails(member);
        }

        return null;
    }
}
