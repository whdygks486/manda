package com.swig.manda.controller;

import com.swig.manda.dto.MemberDto;
import com.swig.manda.service.MemberService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;



@CrossOrigin(origins ="*", allowedHeaders = "*")
@RestController
@RequestMapping("/member")
public class MemberController {


    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired
    MemberService memberService;




    //회원가입 해야함! post
    @PostMapping("/join")
    public ResponseEntity<?> joinSave(@Valid @RequestBody MemberDto memberDto, BindingResult bindingResult) {
        if (bindingResult.hasErrors()){

            return ResponseEntity.badRequest().body(bindingResult.getAllErrors());

        }
        if (!memberDto.getPassword().equals(memberDto.getRepassword())) {

            return ResponseEntity.badRequest().body("패스워드가 맞지 않습니다!");
        }

        boolean isDuplicateUserid = memberService.existsByUserid(memberDto.getUserid());
        if (isDuplicateUserid) {
            return ResponseEntity.badRequest().body("이미 사용 중인 사용자명입니다.");
        }

        memberService.join(memberDto);
        return ResponseEntity.ok().body("회원가입을 축하드립니다.");



    }

}