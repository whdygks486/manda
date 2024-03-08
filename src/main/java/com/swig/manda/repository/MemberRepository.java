package com.swig.manda.repository;

import com.swig.manda.model.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.data.jpa.repository.Modifying;

import java.util.Optional;


@Transactional
public interface MemberRepository extends JpaRepository<Member,Long> {


    Member findByUserid(String userid);
    Member findByEmail(String email);


    Boolean existsByUserid(String userid);


    @Query("SELECT m.password FROM Member m WHERE m.userid = :userid")
    String findPasswordByUsername(@Param("userid") String userid);

    Optional<Member> findByEmailAndUsername(String email, String username);


    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("UPDATE Member m SET m.password = :password WHERE m.userid= :userid")
    void updatePasswordByUserid(@Param("password") String password, @Param("userid") String userid);
}

