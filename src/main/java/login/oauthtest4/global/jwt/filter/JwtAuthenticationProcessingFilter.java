package login.oauthtest4.global.jwt.filter;

import login.oauthtest4.domain.user.User;
import login.oauthtest4.domain.user.repository.UserRepository;
import login.oauthtest4.global.jwt.service.JwtService;
import login.oauthtest4.global.oauth2.util.PasswordUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;

/**
 * Jwt 인증 필터
 * 1. RefreshToken이 유효한 경우 -> AccessToken 재발급하고 인증은 진행하지 않음.
 * 2. RefreshToken이 유효하지 않은 경우 & AccessToken 유효한 경우-> 인증 성공, RefreshToken을 재발급 하지는 않음
 * 3.  RefreshToken이 유효하지 않은 경우 & AccessToken 유효하지 않은 경우-> 인증 실패, 403 ERROR
 *
 * "/login" 이외의 URI 요청이 왔을 때 처리하는 필터
 */
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationProcessingFilter extends OncePerRequestFilter {

    private static final String NO_CHECK_URL = "/login"; // "/login"으로 들어오는 요청은 Filter 작동 X

    private final JwtService jwtService;
    private final UserRepository userRepository;

    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    /**
     * 리프레시 토큰 유/무에 따라 다르게 인증 처리
     * 1. Refresh 토큰이 있는 경우 : 유효하면 AccessToken를 응답 헤더에 재발급 후, 필터 진행을 멈추고 튕기기
     * 2. Refresh 토큰은 없고 AccessToken만 있는 경우 : 유저 정보를 저장 후 필터 계속 진행
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getRequestURI().equals(NO_CHECK_URL)) {
            filterChain.doFilter(request, response); // "/login" 요청이 들어오면, 다음 필터 호출
            return; // return으로 이후 현재 필터 진행 막기 (안해주면 아래로 내려가서 계속 필터 진행시킴)
        }

        // 헤더에서 RefreshToken 추출 -> RefreshToken이 없거나 유효하지 않다면 null을 반환
        String refreshToken = jwtService.extractRefreshToken(request)
                .filter(jwtService::isTokenValid)
                .orElse(null);

        // RefreshToken이 유효하다면 해당 RefreshToken을 가진 유저 정보를 찾아오고,
        // 해당 유저 정보가 존재한다면 AccessToken을 재발급
        if (refreshToken != null) {
            checkRefreshTokenAndReIssueAccessToken(response, refreshToken);
            return; // RefreshToken을 보낸 경우에는 AccessToken을 재발급 하고 인증 처리는 하지 않게 하기위해 바로 return으로 필터 진행 막기
        }

        // RefreshToken이 없거나 유효하지 않다면, AccessToken을 검사하고 인증을 처리하는 로직 수행
        // AccessToken이 없거나 유효하지 않다면, 인증 객체가 담기지 않은 상태로 다음 필터로 넘어가기 때문에 403 에러 발생
        // AccessToken이 유효했다면, 인증 객체가 담긴 상태로 다음 필터로 넘어가기 때문에 인증 성공
        if (refreshToken == null) {
            checkAccessTokenAndAuthentication(request, response, filterChain);
        }
    }

    /**
     *  [리프레시 토큰으로 유저 정보 찾기 & 액세스 토큰 재발급 메소드]
     *  파라미터로 들어온 헤더에서 추출한 리프레시 토큰으로 DB에서 유저를 찾고, 해당 유저가 있다면
     *  JwtService.createAccessToken()으로 AccessToken 생성 후 JwtService.sendAccessToken()으로 응답 헤더에 보내기
     */
    public void checkRefreshTokenAndReIssueAccessToken(HttpServletResponse response, String refreshToken) {
        userRepository.findByRefreshToken(refreshToken)
                .ifPresent(user -> jwtService.sendAccessToken(response, jwtService.createAccessToken(user.getEmail())));
    }

    /**
     * [액세스 토큰 체크 & 인증 처리 메소드]
     * request에서 extractAccessToken()으로 액세스 토큰 추출 후, isTokenValid()로 유효한 토큰인지 검증
     * 유효한 토큰이면, 액세스 토큰에서 extractEmail로 Email을 추출한 후 findByEmail()로 해당 이메일을 사용하는 유저 객체 반환
     * 그 유저 객체를 saveAuthentication()으로 인증 처리하여
     * 인증 허가 처리된 객체를 SecurityContextHolder에 담기
     * 그 후 다음 인증 필터로 진행
     */
    public void checkAccessTokenAndAuthentication(HttpServletRequest request, HttpServletResponse response,
                                                  FilterChain filterChain) throws ServletException, IOException {
        log.info("checkAccessTokenAndAuthentication() 호출");
        jwtService.extractAccessToken(request)
                .filter(jwtService::isTokenValid)
                .ifPresent(accessToken -> jwtService.extractEmail(accessToken)
                        .ifPresent(email -> userRepository.findByEmail(email)
                                .ifPresent(this::saveAuthentication)));

        filterChain.doFilter(request, response);
    }

    /**
     * [인증 허가 메소드]
     * 파라미터의 유저 : 우리가 만든 회원 객체 / 빌더의 유저 : UserDetails의 User 객체
     *
     * new UsernamePasswordAuthenticationToken()로 인증 객체인 Authentication 객체 생성
     * UsernamePasswordAuthenticationToken의 파라미터
     * 1. 위에서 만든 UserDetailsUser 객체 (유저 정보)
     * 2. credential(보통 비밀번호로, 인증 시에는 보통 null로 제거)
     * 3. Collection < ? extends GrantedAuthority>로,
     * UserDetails의 User 객체 안에 Set<GrantedAuthority> authorities이 있어서 getter로 호출한 후에,
     * new NullAuthoritiesMapper()로 GrantedAuthoritiesMapper 객체를 생성하고 mapAuthorities()에 담기
     *
     * SecurityContextHolder.getContext()로 SecurityContext를 꺼낸 후,
     * setAuthentication()을 이용하여 위에서 만든 Authentication 객체에 대한 인증 허가 처리
     */
    public void saveAuthentication(User myUser) {
        String password = myUser.getPassword();
        if (password == null) { // 소셜 로그인 유저의 비밀번호 임의로 설정 하여 소셜 로그인 유저도 인증 되도록 설정
            password = PasswordUtil.generateRandomPassword();
        }

        UserDetails userDetailsUser = org.springframework.security.core.userdetails.User.builder()
                .username(myUser.getEmail())
                .password(password)
                .roles(myUser.getRole().name())
                .build();

        Authentication authentication =
                new UsernamePasswordAuthenticationToken(userDetailsUser, null,
                authoritiesMapper.mapAuthorities(userDetailsUser.getAuthorities()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
