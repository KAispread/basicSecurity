package com.security.basicSecurity.security.provider;

import com.security.basicSecurity.security.common.FormWebAuthenticationDetails;
import com.security.basicSecurity.security.service.AccountContext;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    /* 인증 객체를 반환한다.
     *
     * 파라미터로 받는 Authentication 은 AuthenticationManager 로 부터 전달받는다.
     * 이 객체는 Username 과 password 가 저장되어있음
     * */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 사용자가 입력한 아이디, 패스워드
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        // CustomUserDetailService 가 DB 와의 커넥션을 통해 username 을 검증하고 입력 값을 저장한 객체를 반환
        AccountContext userDetails = (AccountContext) userDetailsService.loadUserByUsername(username);

        // 실제 DB 에 저장된 Entity 와 비교하여 입력한 패스워드가 일치하는지 판별
        if (!passwordEncoder.matches(password, userDetails.getAccount().getPassword())) {
            throw new BadCredentialsException("비밀번호가 일치하지 않습니다");
        }

//        FormWebAuthenticationDetails details = (FormWebAuthenticationDetails) authentication.getDetails();
//        String secretKey = details.getSecretKey();
//        if (secretKey == null || secretKey.equals("secret")) throw new InsufficientAuthenticationException("Secret_key 가 다릅니다");

        /* UsernamePasswordAuthenticationToken
        * 생성자 파라미터
        * 1. (Object) principal - 사용자의 정보를 담은 객체 [정책에 따라 형태가 다름]
        * 2. (Object) credential - 암호 [시큐리티 내부적으로 보안상 credential 속성에 값을 저장하지 않고 있기 때문에 꼭 필요한 필드는 아님]
        * 3. Collection<? extends GrantedAuthority> authorities - 권한 정보 [UserDetails 에 저장되어있음]
        * */
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(userDetails.getAccount(), null, userDetails.getAuthorities());

        return authenticationToken;
    }

    // 인증 처리를 지원하는 클래스 타입인지 검사
    // [authenticate 와 맞춰준다 - 이유? authenticate 에 의해 Session 에 해당 타입의 인증 정보가 저장되기 때문]
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
