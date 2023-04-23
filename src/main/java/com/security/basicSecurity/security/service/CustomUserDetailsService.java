package com.security.basicSecurity.security.service;

import com.security.basicSecurity.domain.Account;
import com.security.basicSecurity.domain.Role;
import com.security.basicSecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

import static com.security.basicSecurity.domain.Role.USER;

@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // username 으로 실제 유저가 존재하는지 확인
        Account account = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Username is not founded"));

        // 권한 정보 생성
        List<GrantedAuthority> roles = new ArrayList<>();
        roles.add(new SimpleGrantedAuthority(account.getRole()));
        roles.add(new SimpleGrantedAuthority(USER.name()));

        // UserDetails 를 상속받은 인증 객체를 반환
        // 이후 AccountContext 를 사용하여 인증 처리
        return new AccountContext(account, roles);
    }
}
