package com.swig.manda.service;

import com.swig.manda.dto.MemberDto;
import com.swig.manda.model.Member;
import com.swig.manda.repository.MemberRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;


@Service
@Transactional
public class MemberService {

    @Autowired
    private PasswordEncoder passwordEncoder;


    @Autowired
    private MemberRepository memberRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public void join(@Valid MemberDto memberDto){

        String encodedPassword=passwordEncoder.encode(memberDto.getPassword());

        Member member=new Member();
        member.setUserid(memberDto.getUserid());
        member.setPassword(encodedPassword);
        member.setRole(memberDto.getRole());
        member.setEmail(memberDto.getEmail());
        member.setUsername(memberDto.getUsername());
        memberRepository.save(member);

    }

    public Member registerNewOAuth2User(String provider, String providerId, String nickname,String email) {

        String encodedPassword = bCryptPasswordEncoder.encode("temporary-password");

        Member user = Member.builder()
                    .username(nickname)
                    .password(encodedPassword)
                    .role("USER")
                .email(email)
                    .provider(provider)
                    .providerId(providerId)
                    .build();

        return memberRepository.save(user);
    }



    public Boolean duplicateUserid(String userid){

        return memberRepository.existsByUserid(userid);

    }
    public boolean userEmailCheck(String email, String userid) {
       Member member=memberRepository.findByUserid(userid);
       return member!= null&&member.getUserid().equals(userid);
    }

    public void updatePassword(String userid, String newPassword) {
        Member member = memberRepository.findByUserid(userid);
        if (member != null) {

            String encodedNewPassword = bCryptPasswordEncoder.encode(newPassword);

            member.setPassword(encodedNewPassword);

            memberRepository.save(member);
        }
    }

    public String findUsernameByEmailAndName(String email, String username) {

        Optional<Member> member = memberRepository.findByEmailAndUsername(email,username);
        return member.map(Member::getUserid).orElse(null);
    }

    public boolean existsByUserid(String userid) {
        return memberRepository.existsByUserid(userid);
    }




}
