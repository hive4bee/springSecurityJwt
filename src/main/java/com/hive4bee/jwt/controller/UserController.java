package com.hive4bee.jwt.controller;

import com.hive4bee.jwt.repository.UserRepository;
import com.hive4bee.jwt.security.JwtTokenProvider;
import com.hive4bee.jwt.security.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Map;

@RequiredArgsConstructor
@Controller
public class UserController {

    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;

    @GetMapping("/example")
    @ResponseBody
    public Object example(){
        Object obj = new String("hi");
        return obj;
    }
    @PostMapping("/example22")
    @ResponseBody
    public ResponseEntity<String> example22(){
        return new ResponseEntity<>("success", HttpStatus.OK);
    }

    // 회원가입

    @RequestMapping(value = "/join", method = RequestMethod.POST)
    @ResponseBody
    public ResponseEntity<Long> join(@RequestBody Map<String, String> user) {
        Long lo=userRepository.save(User.builder()
                .email(user.get("email"))
                .password(passwordEncoder.encode(user.get("password")))
                .roles(Collections.singletonList("ROLE_USER")) // 최초 가입시 USER 로 설정
                .build()).getId();
        return new ResponseEntity<Long>(lo, HttpStatus.OK);
    }

    // 로그인
    @PostMapping("/login")
    @ResponseBody
    public String login(@RequestBody Map<String, String> user) {
        User member = userRepository.findByEmail(user.get("email"))
                .orElseThrow(() -> new IllegalArgumentException("가입되지 않은 E-MAIL 입니다."));
        if (!passwordEncoder.matches(user.get("password"), member.getPassword())) {
            throw new IllegalArgumentException("잘못된 비밀번호입니다.");
        }
        return jwtTokenProvider.createToken(member.getUsername(), member.getRoles());
    }
}
